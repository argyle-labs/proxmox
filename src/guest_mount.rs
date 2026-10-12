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
//! The PVE config API cannot set raw `lxc.*` lines, and its `mpN` bind mounts
//! are refused for API tokens (`check_ct_modify_config_perm` allows non-volume
//! mount points only for `root@pam` itself), so every mount — host-path binds
//! included — is a raw `lxc.mount.entry`. All edits of
//! `/etc/pve/lxc/<vmid>.conf` go through [`edit_raw_conf`], which holds PVE's
//! own per-CT config flock (the one `pct set` and the API take), re-reads the
//! file under it, and replaces it atomically. Only the live section (before the
//! first `[snapshot]` header) is edited. A changed line on a running CT takes
//! effect on its next restart; that is reported as pending, never forced.
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
use std::path::{Path, PathBuf};
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
/// `lxc.mount.entry` for this mountpoint (and, for cifs, its creds file) only
/// when they diverge. A stopped CT mounts it on its next start; a running CT
/// reports a pending restart, since lxc reads `lxc.*` lines only at start.
fn apply(spec: &GuestMountSpec) -> Result<String, String> {
    let vmid = parse_vmid(&spec.guest)?;
    let conf_path = lxc_conf_path(vmid)?;
    let fs_spec = spec
        .sources
        .first()
        .ok_or_else(|| format!("guest {vmid}: share has no enabled source route"))?;
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
    })
}

/// Remove the mount at `target` inside `guest` — the counterpart to a deleted or
/// disabled placement. Idempotent: absent entry ⇒ `Ok`. Also removes the creds
/// file (best-effort; a missing file is not an error).
fn remove(guest: &str, target: &str) -> Result<String, String> {
    let vmid = parse_vmid(guest)?;
    let conf_path = lxc_conf_path(vmid)?;
    let mountpoint_rel = relative_mountpoint(target);

    let outcome = edit_raw_conf(vmid, |conf| {
        let (rewritten, removed) = strip_entry(conf, &mountpoint_rel);
        removed.then_some(rewritten)
    })?;
    std::fs::remove_file(guest_creds_path(vmid, target)).ok();

    Ok(match outcome {
        RawEdit::Unchanged => {
            format!("Guest mount {target} not present in {conf_path} (CT {vmid}).")
        }
        RawEdit::Written => format!("Removed guest mount {target} from {conf_path} (CT {vmid})."),
        RawEdit::PendingRestart => format!(
            "Pending restart: removed guest mount {target} from {conf_path}; CT {vmid} is \
             running and keeps it until a restart (`pct reboot {vmid}`)."
        ),
    })
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
fn lxc_conf_path(vmid: u64) -> Result<String, String> {
    let lxc = format!("/etc/pve/lxc/{vmid}.conf");
    if std::path::Path::new(&lxc).exists() {
        return Ok(lxc);
    }
    let qemu = format!("/etc/pve/qemu-server/{vmid}.conf");
    if std::path::Path::new(&qemu).exists() {
        return Err(format!(
            "guest {vmid} is a VM; VM guest mounts (cloud-init/fstab) are not yet supported"
        ));
    }
    Err(format!(
        "no LXC config found at {lxc} (guest {vmid} not on this node?)"
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
}

impl RawEdit {
    fn after_write(running: bool) -> Self {
        if running {
            Self::PendingRestart
        } else {
            Self::Written
        }
    }
}

/// PVE's per-CT config lock (`PVE::LXC::Config::config_file_lock`).
fn conf_lock_path(vmid: u64) -> PathBuf {
    PathBuf::from(format!("/run/lock/lxc/pve-config-{vmid}.lock"))
}

/// A running CT has its cgroup under `/sys/fs/cgroup/lxc/<vmid>`; a local fact,
/// so no API token or subprocess is needed.
fn ct_running(vmid: u64) -> bool {
    Path::new(&format!("/sys/fs/cgroup/lxc/{vmid}")).exists()
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

/// Raw `lxc.*` lines have no PVE API (and API tokens cannot set bind `mpN`s, which
/// are `root@pam`-only), so the conf is edited locally as root. The edit runs
/// under PVE's own config flock, re-reads the file under it, touches only the
/// live section, and replaces the file atomically. `edit` returns the new live
/// section, or `None` for no change.
pub(crate) fn edit_raw_conf<F>(vmid: u64, edit: F) -> Result<RawEdit, String>
where
    F: Fn(&str) -> Option<String>,
{
    let path = format!("/etc/pve/lxc/{vmid}.conf");
    let read = || std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"));
    if edit_live_section(&read()?, &edit).is_none() {
        return Ok(RawEdit::Unchanged);
    }
    let _lock = lock_exclusive(&conf_lock_path(vmid), CONF_LOCK_TIMEOUT)
        .map_err(|e| format!("CT {vmid} config lock: {e}"))?;
    let Some(rewritten) = edit_live_section(&read()?, &edit) else {
        return Ok(RawEdit::Unchanged);
    };
    atomic_replace(Path::new(&path), rewritten.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))?;
    Ok(RawEdit::after_write(ct_running(vmid)))
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

    #[test]
    fn running_ct_write_is_pending_restart_not_error() {
        assert_eq!(RawEdit::after_write(true), RawEdit::PendingRestart);
        assert_eq!(RawEdit::after_write(false), RawEdit::Written);
    }

    #[test]
    fn conf_lock_path_matches_pct() {
        assert_eq!(
            conf_lock_path(110),
            PathBuf::from("/run/lock/lxc/pve-config-110.lock")
        );
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
