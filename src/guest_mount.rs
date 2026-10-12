//! `guest_mount` domain — render network mounts INTO a guest instead of on the
//! Proxmox host.
//!
//! An unprivileged LXC cannot mount a cifs/nfs share itself, and binding a
//! host-side mount into it (`mpN:`) both requires the host to hold the mount and
//! breaks under the container's uid mapping. The kernel-native answer is a raw
//! `lxc.mount.entry:` line in the guest's config: at container start the host
//! kernel performs the mount directly into the guest's mount namespace, so the
//! LXC stays unprivileged and the mount re-establishes itself on every guest
//! start — independent of the host's own mount state
//! ([[proxmox per-guest mounts]]).
//!
//! Host-path binds (`fstype` `bind`/`none`, absolute source) are PVE `mpN`
//! mount points, set through PVE's own CLI (`pct set`) run locally as root —
//! the API refuses non-volume mount points to tokens
//! (`check_ct_modify_config_perm` allows them only for `root@pam`). `pct`
//! hotplugs a bind into a running CT; when it cannot, PVE parks the change in
//! `[pve:pending]`, and the outcome is read back from the config.
//!
//! cifs/nfs kernel mounts are raw `lxc.mount.entry` lines, which no PVE API or
//! CLI can set. Those edits of `/etc/pve/lxc/<vmid>.conf` go through
//! [`edit_raw_conf`], which holds PVE's own per-CT config flock (the one `pct
//! set` and the API take), re-reads the file under it, and replaces it
//! atomically. Only the live section (before the first `[...]` header) is
//! edited; `[snapshot]` sections and `[pve:pending]` are left untouched. A
//! changed line on a running CT takes effect on its next restart; that is
//! reported as pending, never forced.
//!
//! Core routes a guest-targeted storage placement here as a
//! [`GuestMountSpec`](plugin_toolkit::storage::GuestMountSpec): `guest` is the
//! LXC vmid, `target` the mountpoint inside it, `sources` the share's routes,
//! `options` its rendered `-o` string, and `credential` an opaque
//! [`SecretRef`](plugin_toolkit::storage::SecretRef) string. For cifs the
//! password is resolved through the secrets domain and written to a root-owned
//! `0600` creds file in a `0700` [`SECRET_FILE_DIR`], referenced by
//! `credentials=` in the entry — the password never sits inline in the config.
//!
//! VM guests (their own kernel mounts via cloud-init/fstab) are a later phase;
//! this domain handles LXC and returns a clear error for a VM vmid.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::serde_json::{self, Value};
use plugin_toolkit::storage::{GuestMountSpec, SECRET_FILE_DIR, parse_option_string};
use serde::Deserialize;

/// Invoke-name prefix for this domain's ops (`proxmox.__guest_mount.*`).
pub const GM_PREFIX: &str = "proxmox.__guest_mount";
const PROVIDER: &str = "proxmox";
const CREDS_FILE_MODE: u32 = 0o600;
const CREDS_DIR_MODE: u32 = 0o700;
/// PVE's `lock_config` waits 10s for the config flock.
const CONF_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Option keys that carry a credential and must never be rendered inline into
/// the config — resolved into the root-owned creds file instead.
const CREDENTIAL_KEYS: &[&str] = &[
    "username",
    "user",
    "password",
    "pass",
    "credentials",
    "cred",
];

/// Wire args for `guest_mount_apply` — the whole spec crosses the boundary.
#[derive(Deserialize)]
struct GuestApplyArgs {
    spec: GuestMountSpec,
}

/// Wire args for `guest_mount_remove`.
#[derive(Deserialize)]
struct GuestRemoveArgs {
    guest: String,
    target: String,
}

/// The `guest_mount` backend descriptor this plugin advertises.
pub fn guest_mount_backend_def() -> BackendDef {
    BackendDef {
        domain: "guest_mount".to_string(),
        name: PROVIDER.to_string(),
        invoke_prefix: GM_PREFIX.to_string(),
        ..Default::default()
    }
}

/// Route `proxmox.__guest_mount.*` invoke calls to the apply/remove verbs.
/// Returns `None` when the name isn't ours so [`crate::registration`] falls
/// through to the next sub-dispatcher.
pub fn dispatch(
    name: &str,
    args: serde_json::Value,
) -> Option<Result<serde_json::Value, serde_json::Value>> {
    let op = name.strip_prefix(GM_PREFIX)?.strip_prefix('.')?;
    Some(match op {
        "guest_mount_apply" => serde_json::from_value::<GuestApplyArgs>(args)
            .map_err(|e| err_val(format!("guest_mount_apply args: {e}")))
            .and_then(|a| apply(&a.spec).map(Value::String).map_err(err_val)),
        "guest_mount_remove" => serde_json::from_value::<GuestRemoveArgs>(args)
            .map_err(|e| err_val(format!("guest_mount_remove args: {e}")))
            .and_then(|a| {
                remove(&a.guest, &a.target)
                    .map(Value::String)
                    .map_err(err_val)
            }),
        other => Err(err_val(format!("unknown guest_mount op '{other}'"))),
    })
}

/// A message-only backend error is a plain JSON string.
fn err_val(msg: impl Into<String>) -> serde_json::Value {
    serde_json::Value::String(msg.into())
}

/// Reconcile the guest's mount for `spec` to present. Idempotent: rewrites the
/// mount (and, for cifs, its creds file) only when it diverges. A host-path bind
/// is an `mpN` set via `pct`; a cifs/nfs mount is a raw `lxc.mount.entry`, which
/// a stopped CT mounts on its next start and a running CT after a restart.
fn apply(spec: &GuestMountSpec) -> Result<String, String> {
    let vmid = parse_vmid(&spec.guest)?;
    let conf_path = lxc_conf_path(vmid)?;
    let fs_spec = spec
        .sources
        .first()
        .ok_or_else(|| format!("guest {vmid}: share has no enabled source route"))?;
    if is_bind(&spec.fstype, fs_spec) {
        return apply_bind(vmid, &conf_path, fs_spec, spec);
    }
    let mountpoint_rel = relative_mountpoint(&spec.target);

    // cifs with a credential → resolve the password and materialize a root-owned
    // creds file the host kernel reads at mount time; the entry references it by
    // path so no secret sits inline in the config.
    let cred_path = if is_cifs(&spec.fstype) && spec.credential.is_some() {
        let path = write_creds_file(
            vmid,
            &spec.target,
            &spec.options,
            spec.credential.as_deref(),
        )?;
        Some(path)
    } else {
        None
    };

    let options = render_entry_options(&spec.options, cred_path.as_deref());
    let entry = render_lxc_mount_entry(fs_spec, &mountpoint_rel, &spec.fstype, &options);

    let outcome = edit_raw_conf(vmid, |conf| {
        let (rewritten, changed) = upsert_entry(conf, &mountpoint_rel, &entry);
        changed.then_some(rewritten)
    })?;
    Ok(match outcome {
        RawEdit::Unchanged => format!(
            "Guest mount {} already present in {conf_path} (CT {vmid}).",
            spec.target
        ),
        RawEdit::Written => format!(
            "Set guest mount {} in {conf_path}; mounts on next start of CT {vmid}.",
            spec.target
        ),
        RawEdit::PendingRestart => format!(
            "Pending restart: set guest mount {} in {conf_path}; CT {vmid} is running and \
             mounts it after a restart (`pct reboot {vmid}`).",
            spec.target
        ),
        RawEdit::Unverified => format!(
            "Pending restart, verify: set guest mount {} in {conf_path}; CT {vmid}'s run state \
             is unknown, so if it is running it mounts it after a restart (`pct reboot {vmid}`).",
            spec.target
        ),
    })
}

/// Reconcile a host-path bind as one `mpN` via `pct set`. An existing bind for
/// the same target is reused; any duplicate for it is deleted in the same call,
/// as is a raw `lxc.mount.entry` an older release wrote for it.
fn apply_bind(
    vmid: u64,
    conf_path: &str,
    src: &str,
    spec: &GuestMountSpec,
) -> Result<String, String> {
    let ro = parse_option_string(&spec.options)
        .any(|o| o.key == "ro" && o.value.is_none_or(|v| v == "1"));
    let value = render_mp_value(src, &spec.target, ro);
    let mountpoint_rel = relative_mountpoint(&spec.target);
    edit_raw_conf(vmid, |conf| {
        let (rewritten, removed) = strip_entry(conf, &mountpoint_rel);
        removed.then_some(rewritten)
    })?;

    let conf = read_conf(conf_path)?;
    let entries = conf_mp_entries(&conf);
    let matches = bind_mps(&entries, &spec.target);
    let (key, extras) = match matches.split_first() {
        Some(((k, v), rest)) if *v == value && rest.is_empty() => {
            return Ok(format!(
                "Bind mount {} already present as {k} on CT {vmid}.",
                spec.target
            ));
        }
        Some(((k, _), rest)) => (k.to_string(), rest.iter().map(|(k, _)| *k).collect()),
        None => (
            first_free_mp(&entries)
                .ok_or_else(|| format!("CT {vmid}: all {MAX_MP} mount point slots are in use"))?,
            Vec::new(),
        ),
    };
    run_pct(&pct_set_argv(vmid, Some((&key, &value)), &extras))?;

    let after = read_conf(conf_path)?;
    let live = conf_mp_entries(&after);
    Ok(if live.iter().any(|(k, v)| *k == key && *v == value) {
        format!("Set {key} bind mount {} on CT {vmid}.", spec.target)
    } else {
        format!(
            "Pending restart: set {key} bind mount {} on CT {vmid}; PVE could not hotplug it \
             and holds it in [pve:pending] until a restart (`pct reboot {vmid}`).",
            spec.target
        )
    })
}

/// Remove the mount at `target` inside `guest` — the counterpart to a deleted or
/// disabled placement. Idempotent: absent mount ⇒ `Ok`. Deletes every host-path
/// `mpN` bind for `target` via `pct set -delete` and the raw `lxc.mount.entry`.
/// The creds file is removed once the entry is gone and no running CT still uses it.
fn remove(guest: &str, target: &str) -> Result<String, String> {
    let vmid = parse_vmid(guest)?;
    let conf_path = lxc_conf_path(vmid)?;
    let mountpoint_rel = relative_mountpoint(target);

    let conf = read_conf(&conf_path)?;
    let entries = conf_mp_entries(&conf);
    let keys: Vec<&str> = bind_mps(&entries, target).iter().map(|(k, _)| *k).collect();
    let mut msgs = Vec::new();
    if !keys.is_empty() {
        run_pct(&pct_set_argv(vmid, None, &keys))?;
        let after = conf_mp_entries(&read_conf(&conf_path)?);
        let joined = keys.join(",");
        msgs.push(if bind_mps(&after, target).is_empty() {
            format!("Removed {joined} bind mount {target} from CT {vmid}.")
        } else {
            format!(
                "Pending restart: removed {joined} bind mount {target} from CT {vmid}; PVE \
                 could not unplug it and holds the delete in [pve:pending] until a restart \
                 (`pct reboot {vmid}`)."
            )
        });
    }

    let outcome = edit_raw_conf(vmid, |conf| {
        let (rewritten, removed) = strip_entry(conf, &mountpoint_rel);
        removed.then_some(rewritten)
    })?;
    if !matches!(outcome, RawEdit::PendingRestart | RawEdit::Unverified) {
        std::fs::remove_file(guest_creds_path(vmid, target)).ok();
    }
    match outcome {
        RawEdit::Unchanged if msgs.is_empty() => {
            msgs.push(format!(
                "Guest mount {target} not present in {conf_path} (CT {vmid})."
            ));
        }
        RawEdit::Unchanged => {}
        RawEdit::Written => {
            msgs.push(format!(
                "Removed guest mount {target} from {conf_path} (CT {vmid})."
            ));
        }
        RawEdit::PendingRestart => msgs.push(format!(
            "Pending restart: removed guest mount {target} from {conf_path}; CT {vmid} is \
             running and keeps it until a restart (`pct reboot {vmid}`)."
        )),
        RawEdit::Unverified => msgs.push(format!(
            "Pending restart, verify: removed guest mount {target} from {conf_path}; CT \
             {vmid}'s run state is unknown, so if it is running it keeps the mount until a \
             restart (`pct reboot {vmid}`)."
        )),
    }
    Ok(msgs.join(" "))
}

fn read_conf(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))
}

// ── Node-local paths ────────────────────────────────────────────────────────

/// Parse the guest identifier as an LXC vmid.
fn parse_vmid(guest: &str) -> Result<u64, String> {
    guest
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("guest '{guest}' is not a numeric LXC vmid"))
}

/// The LXC config path for `vmid`, erroring if it is not an LXC (e.g. a VM,
/// whose config lives under `qemu-server/` and whose mounts are a later phase).
pub(crate) fn lxc_conf_path(vmid: u64) -> Result<String, String> {
    lxc_conf_path_in(Path::new("/"), vmid)
}

fn lxc_conf_path_in(root: &Path, vmid: u64) -> Result<String, String> {
    let lxc = root.join(format!("etc/pve/lxc/{vmid}.conf"));
    if lxc.exists() {
        return Ok(lxc.to_string_lossy().into_owned());
    }
    if root
        .join(format!("etc/pve/qemu-server/{vmid}.conf"))
        .exists()
    {
        return Err(format!(
            "guest {vmid} is a VM; VM guest mounts (cloud-init/fstab) are not yet supported"
        ));
    }
    Err(format!(
        "no LXC config found at {} (guest {vmid} not on this node?)",
        lxc.display()
    ))
}

/// Root-owned `0600` creds-file path for a guest's mount, under
/// [`SECRET_FILE_DIR`] (so the privileged allowlist scopes writes there) and
/// keyed by BOTH vmid and target — many guests can mount the same path, so the
/// generic `secret_file_path` (target-only) would collide across guests.
fn guest_creds_path(vmid: u64, target: &str) -> String {
    format!("{SECRET_FILE_DIR}/guest-{vmid}-{}.secret", slug(target))
}

/// Filesystem-safe slug of a mountpoint: non-alphanumerics collapse to `-`.
fn slug(target: &str) -> String {
    target
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

// ── Credential handling ─────────────────────────────────────────────────────

/// Resolve the credential ref to a password, extract username/domain from the
/// options, render the cifs creds-file grammar, and write it root-owned `0600`.
/// Returns the path to reference via `credentials=` in the mount entry.
fn write_creds_file(
    vmid: u64,
    target: &str,
    options: &str,
    credential: Option<&str>,
) -> Result<String, String> {
    let cred_ref = credential.ok_or("cifs mount declares a credential but none was provided")?;
    let password = plugin_toolkit::secrets::get_required(cred_ref)
        .map_err(|e| format!("resolve credential '{cred_ref}': {e}"))?;
    let (username, domain) = extract_identity(options);
    let username =
        username.ok_or("cifs mount has a credential but no `username=` in its options")?;
    let contents = render_creds_file(&username, &password, domain.as_deref());

    let path = guest_creds_path(vmid, target);
    if let Some(parent) = Path::new(&path).parent() {
        ensure_private_dir(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    if creds_file_current(Path::new(&path), contents.as_bytes()) {
        return Ok(path);
    }
    atomic_write(
        Path::new(&path),
        contents.as_bytes(),
        CREDS_FILE_MODE,
        Some((0, 0)),
    )
    .map_err(|e| format!("write creds file {path}: {e}"))?;
    Ok(path)
}

/// Create `dir` (and parents) and force it to `0700`.
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(CREDS_DIR_MODE)
        .create(dir)?;
    if std::fs::metadata(dir)?.mode() & 0o7777 != CREDS_DIR_MODE {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(CREDS_DIR_MODE))?;
    }
    Ok(())
}

/// True when the creds file already holds `contents` with the expected mode, so
/// an unchanged secret is not rewritten every converge tick.
fn creds_file_current(path: &Path, contents: &[u8]) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.mode() & 0o7777 == CREDS_FILE_MODE
        && std::fs::read(path).is_ok_and(|existing| existing == contents)
}

/// Extract `username=` and `domain=` from a rendered option string (the inline
/// identity a cifs creds-file needs). Password is never taken from options — it
/// is the resolved secret.
fn extract_identity(options: &str) -> (Option<String>, Option<String>) {
    let mut username = None;
    let mut domain = None;
    for opt in parse_option_string(options) {
        match (opt.key, opt.value) {
            ("username" | "user", Some(v)) => username = Some(v.to_string()),
            ("domain", Some(v)) => domain = Some(v.to_string()),
            _ => {}
        }
    }
    (username, domain)
}

/// The exact `mount.cifs` `credentials=` file grammar — `username=`, `password=`,
/// and (when set) `domain=`, one per line.
fn render_creds_file(username: &str, password: &str, domain: Option<&str>) -> String {
    let mut out = format!("username={username}\npassword={password}\n");
    if let Some(d) = domain {
        out.push_str(&format!("domain={d}\n"));
    }
    out
}

// ── Safe file writes ────────────────────────────────────────────────────────

/// Create a fresh temp file beside `path` with `mode` set at creation, so the
/// contents are never readable under a looser mode.
fn create_temp_beside(
    path: &Path,
    mode: u32,
) -> std::io::Result<(std::fs::File, std::path::PathBuf)> {
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("path has no file name"))?
        .to_string_lossy();
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_file_name(format!(".{name}.tmp.{}.{seq}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    Ok((file, tmp))
}

/// Write `contents` to `path` atomically: temp file in the same dir, `sync_all`,
/// then rename. Mode and owner are fixed up only when the temp file differs, so
/// pmxcfs (which rejects chmod/chown but already applies its fixed ones) works.
fn atomic_write(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    let (mut file, tmp) = create_temp_beside(path, mode)?;
    let result = (|| {
        file.write_all(contents)?;
        let meta = file.metadata()?;
        if meta.mode() & 0o7777 != mode {
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        if let Some((uid, gid)) = owner
            && (meta.uid() != uid || meta.gid() != gid)
        {
            std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
        }
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        std::fs::remove_file(&tmp).ok();
    }
    result
}

/// [`atomic_write`] over an existing file, keeping its mode and owner.
fn atomic_replace(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let meta = std::fs::metadata(path)?;
    atomic_write(
        path,
        contents,
        meta.mode() & 0o7777,
        Some((meta.uid(), meta.gid())),
    )
}

// ── Raw conf edits ──────────────────────────────────────────────────────────

/// Result of [`edit_raw_conf`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RawEdit {
    Unchanged,
    /// Written to a stopped CT; applies on its next start.
    Written,
    /// Written to a running CT; lxc reads `lxc.*` lines only at start.
    PendingRestart,
    /// Written, but no cgroup hierarchy was found to tell whether the CT runs.
    Unverified,
}

impl RawEdit {
    fn after_write(state: CtState) -> Self {
        match state {
            CtState::Running => Self::PendingRestart,
            CtState::Stopped => Self::Written,
            CtState::Unknown => Self::Unverified,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtState {
    Running,
    Stopped,
    Unknown,
}

/// A running CT has a cgroup named for its vmid: `lxc/<vmid>` at the cgroup
/// root on v2, under the `pids` controller on v1, under `unified` on hybrid. A
/// local fact, so no API token or subprocess is needed.
fn ct_running(root: &Path, vmid: u64) -> CtState {
    let cg = root.join("sys/fs/cgroup");
    let v2 = cg.join("cgroup.controllers").exists().then(|| cg.clone());
    let hierarchies = v2
        .into_iter()
        .chain([cg.join("pids"), cg.join("unified")])
        .filter(|h| h.is_dir())
        .collect::<Vec<_>>();
    if hierarchies.is_empty() {
        return CtState::Unknown;
    }
    if hierarchies
        .iter()
        .any(|h| h.join(format!("lxc/{vmid}")).exists())
    {
        CtState::Running
    } else {
        CtState::Stopped
    }
}

/// Take `path`'s exclusive flock, polling until `timeout`.
fn lock_exclusive(path: &Path, timeout: Duration) -> Result<std::fs::File, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(format!(
                    "timed out after {}s waiting for {}",
                    timeout.as_secs(),
                    path.display()
                ));
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("lock {}: {e}", path.display()));
            }
        }
    }
}

/// Split a CT conf into its live section and the rest, which starts at the first
/// `[snapshot]` header and is returned untouched.
fn split_live_section(conf: &str) -> (&str, &str) {
    let mut offset = 0;
    for line in conf.split_inclusive('\n') {
        if line.trim_start().starts_with('[') {
            return conf.split_at(offset);
        }
        offset += line.len();
    }
    (conf, "")
}

/// Apply `edit` to the live section of `conf`; `None` when it makes no change.
fn edit_live_section<F>(conf: &str, edit: F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    let (live, snapshots) = split_live_section(conf);
    let mut out = edit(live)?;
    if !snapshots.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(snapshots);
    Some(out)
}

/// Raw `lxc.*` lines have no PVE API or CLI, so the conf is edited locally as
/// root. The edit runs under PVE's own config flock, re-reads the file under it,
/// touches only the live section, and replaces the file atomically. `edit`
/// returns the new live section, or `None` for no change. Errors for a VM vmid.
pub(crate) fn edit_raw_conf<F>(vmid: u64, edit: F) -> Result<RawEdit, String>
where
    F: Fn(&str) -> Option<String>,
{
    edit_raw_conf_in(Path::new("/"), vmid, edit)
}

fn edit_raw_conf_in<F>(root: &Path, vmid: u64, edit: F) -> Result<RawEdit, String>
where
    F: Fn(&str) -> Option<String>,
{
    let path = lxc_conf_path_in(root, vmid)?;
    if edit_live_section(&read_conf(&path)?, &edit).is_none() {
        return Ok(RawEdit::Unchanged);
    }
    // PVE's per-CT config lock (`PVE::LXC::Config::config_file_lock`).
    let lock = root.join(format!("run/lock/lxc/pve-config-{vmid}.lock"));
    let _lock = lock_exclusive(&lock, CONF_LOCK_TIMEOUT)
        .map_err(|e| format!("CT {vmid} config lock: {e}"))?;
    let Some(rewritten) = edit_live_section(&read_conf(&path)?, &edit) else {
        return Ok(RawEdit::Unchanged);
    };
    atomic_replace(Path::new(&path), rewritten.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))?;
    Ok(RawEdit::after_write(ct_running(root, vmid)))
}

/// Delete temp files a crashed [`edit_raw_conf`] left in `/etc/pve/lxc`. Run once
/// at plugin start, before any edit of ours can be in flight.
pub fn sweep_stale_conf_temps() {
    sweep_stale_conf_temps_in(Path::new("/"));
}

fn sweep_stale_conf_temps_in(root: &Path) {
    let Ok(dir) = std::fs::read_dir(root.join("etc/pve/lxc")) else {
        return;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') && name.contains(".conf.tmp.") {
            std::fs::remove_file(entry.path()).ok();
        }
    }
}

// ── Mount points (mpN) via pct ──────────────────────────────────────────────

/// PVE allows `mp0`..`mp255`.
const MAX_MP: usize = 256;

/// True for a host-path bind, which PVE models as an `mpN` mount point.
fn is_bind(fstype: &str, src: &str) -> bool {
    matches!(fstype, "bind" | "none") && src.starts_with('/')
}

fn is_mp_key(key: &str) -> bool {
    key.strip_prefix("mp")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// `mpN` entries from the conf's live section.
fn conf_mp_entries(conf: &str) -> Vec<(String, String)> {
    split_live_section(conf)
        .0
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let k = k.trim();
            is_mp_key(k).then(|| (k.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Every host-path bind `mpN` whose `mp=` is `target`, in conf order. Storage
/// volumes (`local-lvm:…`) are never matched — orca only creates host-path binds.
fn bind_mps<'a>(entries: &'a [(String, String)], target: &str) -> Vec<(&'a str, &'a str)> {
    entries
        .iter()
        .filter(|(_, v)| {
            v.starts_with('/') && v.split(',').any(|p| p.strip_prefix("mp=") == Some(target))
        })
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

fn first_free_mp(entries: &[(String, String)]) -> Option<String> {
    (0..MAX_MP)
        .map(|i| format!("mp{i}"))
        .find(|k| !entries.iter().any(|(e, _)| e == k))
}

fn render_mp_value(src: &str, target: &str, ro: bool) -> String {
    let ro = if ro { ",ro=1" } else { "" };
    format!("{src},mp={target}{ro}")
}

/// `pct set <vmid> [-<key> <value>] [-delete <k1,k2>]` argv (without `pct`).
fn pct_set_argv(vmid: u64, set: Option<(&str, &str)>, delete: &[&str]) -> Vec<String> {
    let mut argv = vec!["set".to_string(), vmid.to_string()];
    if let Some((key, value)) = set {
        argv.push(format!("-{key}"));
        argv.push(value.to_string());
    }
    if !delete.is_empty() {
        argv.push("-delete".to_string());
        argv.push(delete.join(","));
    }
    argv
}

/// Run `pct` with `argv`. The plugin is its own exec'd process (not a forked
/// child of the daemon), so spawning here is fork-safe.
fn run_pct(argv: &[String]) -> Result<(), String> {
    let out = std::process::Command::new("pct")
        .args(argv)
        .output()
        .map_err(|e| format!("spawn `pct {}`: {e}", argv.join(" ")))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "`pct {}` failed ({}): {}",
        argv.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

// ── Pure entry rendering ────────────────────────────────────────────────────

/// Strip the leading `/` from an absolute guest mountpoint — an
/// `lxc.mount.entry` mountpoint is relative to the guest rootfs.
fn relative_mountpoint(target: &str) -> String {
    target.trim_start_matches('/').to_string()
}

/// True if the fstype is a cifs/smb kernel type.
fn is_cifs(fstype: &str) -> bool {
    fstype == "cifs" || fstype == "smb3" || fstype == "smb"
}

/// Build the option field of the entry: drop every inline credential key (moved
/// to the creds file), add `credentials=<path>` when one was written, and ensure
/// `create=dir` so lxc creates the mountpoint if it is missing.
fn render_entry_options(options: &str, cred_path: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut has_create = false;
    for opt in parse_option_string(options) {
        if CREDENTIAL_KEYS.contains(&opt.key) {
            continue;
        }
        if opt.key == "create" {
            has_create = true;
        }
        match opt.value {
            Some(v) => parts.push(format!("{}={}", opt.key, v)),
            None => parts.push(opt.key.to_string()),
        }
    }
    if let Some(p) = cred_path {
        parts.push(format!("credentials={p}"));
    }
    if !has_create {
        parts.push("create=dir".to_string());
    }
    parts.join(",")
}

/// Render a full `lxc.mount.entry:` line. `dump`/`pass` are always `0 0`.
fn render_lxc_mount_entry(
    fs_spec: &str,
    mountpoint_rel: &str,
    fstype: &str,
    options: &str,
) -> String {
    format!("lxc.mount.entry: {fs_spec} {mountpoint_rel} {fstype} {options} 0 0")
}

/// The mountpoint field (2nd token after the key) of an `lxc.mount.entry` line,
/// if this line is one.
fn entry_mountpoint(line: &str) -> Option<&str> {
    let rest = line.trim().strip_prefix("lxc.mount.entry:")?;
    rest.split_whitespace().nth(1)
}

/// Replace the existing `lxc.mount.entry` for `mountpoint_rel` with `new_line`,
/// or append it if none exists. Every other line is preserved byte-for-byte.
/// Returns the rewritten config and whether it changed.
fn upsert_entry(conf: &str, mountpoint_rel: &str, new_line: &str) -> (String, bool) {
    let mut out = String::with_capacity(conf.len() + new_line.len() + 1);
    let mut replaced = false;
    let mut changed = false;
    for line in conf.lines() {
        if entry_mountpoint(line) == Some(mountpoint_rel) {
            replaced = true;
            if line.trim() != new_line {
                changed = true;
            }
            out.push_str(new_line);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(new_line);
        out.push('\n');
        changed = true;
    }
    (out, changed)
}

/// Remove the `lxc.mount.entry` for `mountpoint_rel`. Returns the rewritten
/// config and whether a line was removed.
fn strip_entry(conf: &str, mountpoint_rel: &str) -> (String, bool) {
    let mut out = String::with_capacity(conf.len());
    let mut removed = false;
    for line in conf.lines() {
        if entry_mountpoint(line) == Some(mountpoint_rel) {
            removed = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_mountpoint_strips_leading_slash() {
        assert_eq!(relative_mountpoint("/mnt/backups"), "mnt/backups");
        assert_eq!(relative_mountpoint("mnt/backups"), "mnt/backups");
        assert_eq!(relative_mountpoint("/"), "");
    }

    #[test]
    fn entry_mountpoint_parses_second_field() {
        let line =
            "lxc.mount.entry: //willow/backups mnt/backups cifs credentials=/x,create=dir 0 0";
        assert_eq!(entry_mountpoint(line), Some("mnt/backups"));
        assert_eq!(entry_mountpoint("memory: 512"), None);
        assert_eq!(entry_mountpoint("arch: amd64"), None);
    }

    #[test]
    fn render_entry_drops_inline_creds_and_adds_credentials_and_create() {
        let opts = "vers=3.1.1,uid=1000,username=alice,password=secret,domain=WORK";
        let got = render_entry_options(
            opts,
            Some("/etc/orca/secret-files/guest-110-mnt-backups.secret"),
        );
        // credential keys removed
        assert!(!got.contains("username="));
        assert!(!got.contains("password="));
        // non-credential options preserved
        assert!(got.contains("vers=3.1.1"));
        assert!(got.contains("uid=1000"));
        // creds file referenced + create=dir added
        assert!(got.contains("credentials=/etc/orca/secret-files/guest-110-mnt-backups.secret"));
        assert!(got.contains("create=dir"));
    }

    #[test]
    fn render_entry_preserves_existing_create_and_omits_credentials_when_none() {
        let got = render_entry_options("vers=4.2,hard,create=dir", None);
        assert!(got.contains("vers=4.2"));
        assert!(got.contains("hard"));
        assert!(got.contains("create=dir"));
        assert!(!got.contains("credentials="));
        // create=dir not duplicated
        assert_eq!(got.matches("create=dir").count(), 1);
    }

    #[test]
    fn render_lxc_mount_entry_formats_all_six_fields() {
        let line = render_lxc_mount_entry("//willow/backups", "mnt/backups", "cifs", "create=dir");
        assert_eq!(
            line,
            "lxc.mount.entry: //willow/backups mnt/backups cifs create=dir 0 0"
        );
    }

    #[test]
    fn upsert_appends_when_absent() {
        let conf = "arch: amd64\nhostname: adguard\n";
        let line = "lxc.mount.entry: //willow/backups mnt/backups cifs create=dir 0 0";
        let (out, changed) = upsert_entry(conf, "mnt/backups", line);
        assert!(changed);
        assert!(out.contains("arch: amd64"));
        assert!(out.ends_with(&format!("{line}\n")));
    }

    #[test]
    fn upsert_replaces_existing_same_mountpoint() {
        let conf = "arch: amd64\nlxc.mount.entry: //old/src mnt/backups cifs create=dir 0 0\nmemory: 512\n";
        let line = "lxc.mount.entry: //willow/backups mnt/backups cifs vers=3.1.1,create=dir 0 0";
        let (out, changed) = upsert_entry(conf, "mnt/backups", line);
        assert!(changed);
        assert!(out.contains("//willow/backups"));
        assert!(!out.contains("//old/src"));
        // other lines untouched
        assert!(out.contains("arch: amd64"));
        assert!(out.contains("memory: 512"));
        // exactly one entry for this mountpoint
        assert_eq!(out.matches("mnt/backups cifs").count(), 1);
    }

    #[test]
    fn upsert_is_idempotent_when_identical() {
        let line = "lxc.mount.entry: //willow/backups mnt/backups cifs create=dir 0 0";
        let conf = format!("arch: amd64\n{line}\n");
        let (out, changed) = upsert_entry(&conf, "mnt/backups", line);
        assert!(!changed, "identical entry must report no change");
        assert_eq!(out, conf);
    }

    #[test]
    fn strip_removes_only_matching_entry() {
        let conf = "arch: amd64\nlxc.mount.entry: //willow/backups mnt/backups cifs create=dir 0 0\nlxc.mount.entry: //willow/data mnt/data cifs create=dir 0 0\n";
        let (out, removed) = strip_entry(conf, "mnt/backups");
        assert!(removed);
        assert!(!out.contains("mnt/backups"));
        assert!(out.contains("mnt/data"));
        assert!(out.contains("arch: amd64"));
    }

    #[test]
    fn strip_reports_false_when_absent() {
        let conf = "arch: amd64\nmemory: 512\n";
        let (out, removed) = strip_entry(conf, "mnt/backups");
        assert!(!removed);
        assert_eq!(out, conf);
    }

    #[test]
    fn extract_identity_reads_username_and_domain_not_password() {
        let (u, d) = extract_identity("vers=3.1.1,username=alice,domain=WORK,password=secret");
        assert_eq!(u, Some("alice".to_string()));
        assert_eq!(d, Some("WORK".to_string()));
    }

    #[test]
    fn render_creds_file_matches_cifs_grammar() {
        assert_eq!(
            render_creds_file("alice", "secret", Some("WORK")),
            "username=alice\npassword=secret\ndomain=WORK\n"
        );
        assert_eq!(
            render_creds_file("bob", "pw", None),
            "username=bob\npassword=pw\n"
        );
    }

    #[test]
    fn guest_creds_path_keys_by_vmid_and_target() {
        let p = guest_creds_path(110, "/mnt/backups");
        assert!(p.starts_with(SECRET_FILE_DIR));
        assert!(p.contains("guest-110-"));
        // different guests, same target → distinct paths (no collision)
        assert_ne!(
            guest_creds_path(110, "/mnt/backups"),
            guest_creds_path(200, "/mnt/backups")
        );
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "proxmox-gm-{name}-{}-{}",
            std::process::id(),
            plugin_toolkit::time::now().unix_seconds()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn creds_temp_file_is_0600_at_creation() {
        let dir = scratch("creds-mode");
        let (file, _tmp) = create_temp_beside(&dir.join("x.secret"), CREDS_FILE_MODE).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_write_leaves_no_temp_and_sets_mode() {
        let dir = scratch("atomic");
        let path = dir.join("x.secret");
        atomic_write(&path, b"username=a\n", CREDS_FILE_MODE, None).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "username=a\n");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("x.secret")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_replace_preserves_mode() {
        let dir = scratch("replace");
        let path = dir.join("110.conf");
        std::fs::write(&path, "arch: amd64\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        atomic_replace(&path, b"arch: arm64\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "arch: arm64\n");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o640);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn live_section_stops_at_first_snapshot_header() {
        let conf = "arch: amd64\nmemory: 512\n\n[snap1]\nlxc.mount.entry: a mnt/x cifs o 0 0\n";
        let (live, rest) = split_live_section(conf);
        assert_eq!(live, "arch: amd64\nmemory: 512\n\n");
        assert_eq!(rest, "[snap1]\nlxc.mount.entry: a mnt/x cifs o 0 0\n");
        assert_eq!(split_live_section("arch: amd64\n"), ("arch: amd64\n", ""));
    }

    #[test]
    fn edit_never_touches_snapshot_sections() {
        let snap = "[snap1]\nlxc.mount.entry: //old mnt/backups cifs o 0 0\n";
        let conf = format!("arch: amd64\n{snap}");
        let line = "lxc.mount.entry: //new mnt/backups cifs create=dir 0 0";
        let out = edit_live_section(&conf, |c| {
            let (r, changed) = upsert_entry(c, "mnt/backups", line);
            changed.then_some(r)
        })
        .unwrap();
        assert_eq!(out, format!("arch: amd64\n{line}\n{snap}"));
        let out = edit_live_section(&out, |c| {
            let (r, removed) = strip_entry(c, "mnt/backups");
            removed.then_some(r)
        })
        .unwrap();
        assert_eq!(out, conf);
    }

    fn pve_root(name: &str, vmid: u64, conf: &str) -> std::path::PathBuf {
        let root = scratch(name);
        std::fs::create_dir_all(root.join("etc/pve/lxc")).unwrap();
        std::fs::write(root.join(format!("etc/pve/lxc/{vmid}.conf")), conf).unwrap();
        root
    }

    #[test]
    fn edit_raw_conf_locks_rereads_and_replaces_live_section() {
        let conf = "arch: amd64\n[pve:pending]\nmemory: 1024\n";
        let root = pve_root("edit", 110, conf);
        let line = "lxc.mount.entry: //w/b mnt/b cifs create=dir 0 0";
        let upsert = |c: &str| {
            let (r, changed) = upsert_entry(c, "mnt/b", line);
            changed.then_some(r)
        };
        let lock = root.join("run/lock/lxc/pve-config-110.lock");
        let held = lock_exclusive(&lock, Duration::ZERO).unwrap();
        let err = edit_raw_conf_in(&root, 110, upsert).unwrap_err();
        assert!(err.contains("config lock"), "{err}");
        drop(held);

        assert_eq!(
            edit_raw_conf_in(&root, 110, upsert).unwrap(),
            RawEdit::Unverified
        );
        let path = root.join("etc/pve/lxc/110.conf");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("arch: amd64\n{line}\n[pve:pending]\nmemory: 1024\n")
        );
        assert_eq!(
            edit_raw_conf_in(&root, 110, upsert).unwrap(),
            RawEdit::Unchanged
        );
        assert_eq!(
            std::fs::read_dir(root.join("etc/pve/lxc")).unwrap().count(),
            1
        );

        std::fs::create_dir_all(root.join("sys/fs/cgroup/pids/lxc/110")).unwrap();
        let strip = |c: &str| {
            let (r, removed) = strip_entry(c, "mnt/b");
            removed.then_some(r)
        };
        assert_eq!(
            edit_raw_conf_in(&root, 110, strip).unwrap(),
            RawEdit::PendingRestart
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), conf);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn edit_raw_conf_refuses_a_vm() {
        let root = scratch("vm");
        std::fs::create_dir_all(root.join("etc/pve/qemu-server")).unwrap();
        std::fs::write(root.join("etc/pve/qemu-server/200.conf"), "").unwrap();
        let err = edit_raw_conf_in(&root, 200, |_| Some(String::new())).unwrap_err();
        assert!(err.contains("is a VM"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn ct_running_reads_v2_v1_and_hybrid_hierarchies() {
        let none = scratch("cg-none");
        assert_eq!(ct_running(&none, 110), CtState::Unknown);

        let v2 = scratch("cg-v2");
        std::fs::create_dir_all(v2.join("sys/fs/cgroup/lxc/110")).unwrap();
        std::fs::write(v2.join("sys/fs/cgroup/cgroup.controllers"), "pids\n").unwrap();
        assert_eq!(ct_running(&v2, 110), CtState::Running);
        assert_eq!(ct_running(&v2, 111), CtState::Stopped);

        let v1 = scratch("cg-v1");
        std::fs::create_dir_all(v1.join("sys/fs/cgroup/pids/lxc/110")).unwrap();
        assert_eq!(ct_running(&v1, 110), CtState::Running);
        assert_eq!(ct_running(&v1, 111), CtState::Stopped);

        let hybrid = scratch("cg-hybrid");
        std::fs::create_dir_all(hybrid.join("sys/fs/cgroup/unified/lxc/110")).unwrap();
        assert_eq!(ct_running(&hybrid, 110), CtState::Running);
        assert_eq!(ct_running(&hybrid, 111), CtState::Stopped);

        for d in [none, v2, v1, hybrid] {
            std::fs::remove_dir_all(&d).ok();
        }
    }

    #[test]
    fn sweep_removes_only_stale_conf_temps() {
        let root = pve_root("sweep", 110, "arch: amd64\n");
        let lxc = root.join("etc/pve/lxc");
        std::fs::write(lxc.join(".110.conf.tmp.42.0"), "x").unwrap();
        std::fs::write(lxc.join(".hidden"), "x").unwrap();
        sweep_stale_conf_temps_in(&root);
        let mut names: Vec<_> = std::fs::read_dir(&lxc)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec![".hidden", "110.conf"]);
        std::fs::remove_dir_all(&root).ok();
    }

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn first_free_mp_fills_gaps_from_live_section() {
        let conf = "mp0: /a,mp=/a\nmp2: /c,mp=/c\n[pve:pending]\nmp1: /b,mp=/b\n";
        let live = conf_mp_entries(conf);
        assert_eq!(live, entries(&[("mp0", "/a,mp=/a"), ("mp2", "/c,mp=/c")]));
        assert_eq!(first_free_mp(&live), Some("mp1".to_string()));
        assert_eq!(first_free_mp(&[]), Some("mp0".to_string()));
        let full: Vec<_> = (0..MAX_MP)
            .map(|i| (format!("mp{i}"), String::new()))
            .collect();
        assert_eq!(first_free_mp(&full), None);
    }

    #[test]
    fn bind_mps_matches_every_host_bind_for_target_only() {
        let e = entries(&[
            ("mp0", "/srv/a,mp=/mnt/a"),
            ("mp1", "local-lvm:vm-110-disk-1,mp=/mnt/b,size=8G"),
            ("mp3", "/srv/b,mp=/mnt/b,ro=1"),
            ("mp5", "/srv/b2,mp=/mnt/b"),
        ]);
        assert_eq!(
            bind_mps(&e, "/mnt/b"),
            vec![
                ("mp3", "/srv/b,mp=/mnt/b,ro=1"),
                ("mp5", "/srv/b2,mp=/mnt/b")
            ]
        );
        assert!(bind_mps(&e, "/mnt").is_empty());
        assert_eq!(
            render_mp_value("/srv/media", "/mnt/media", true),
            "/srv/media,mp=/mnt/media,ro=1"
        );
        assert_eq!(render_mp_value("/a", "/b", false), "/a,mp=/b");
    }

    #[test]
    fn pct_set_argv_builds_set_and_delete() {
        assert_eq!(
            pct_set_argv(110, Some(("mp1", "/srv/a,mp=/mnt/a")), &[]),
            ["set", "110", "-mp1", "/srv/a,mp=/mnt/a"]
        );
        assert_eq!(
            pct_set_argv(110, Some(("mp1", "/a,mp=/b")), &["mp3", "mp5"]),
            ["set", "110", "-mp1", "/a,mp=/b", "-delete", "mp3,mp5"]
        );
        assert_eq!(
            pct_set_argv(110, None, &["mp0"]),
            ["set", "110", "-delete", "mp0"]
        );
    }

    #[test]
    fn bind_detection_needs_bind_type_and_host_path() {
        assert!(is_bind("bind", "/srv/a"));
        assert!(is_bind("none", "/srv/a"));
        assert!(!is_bind("cifs", "//host/share"));
        assert!(!is_bind("nfs", "host:/export"));
    }

    #[test]
    fn lock_exclusive_times_out_while_held() {
        let dir = scratch("lock");
        let path = dir.join("pve-config-1.lock");
        let held = lock_exclusive(&path, Duration::ZERO).unwrap();
        assert!(lock_exclusive(&path, Duration::ZERO).is_err());
        drop(held);
        assert!(lock_exclusive(&path, Duration::ZERO).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_vmid_rejects_non_numeric() {
        assert_eq!(parse_vmid("110").unwrap(), 110);
        assert!(parse_vmid("baldur").is_err());
    }
}
