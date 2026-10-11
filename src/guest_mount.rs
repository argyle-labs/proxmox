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
//! Two write paths:
//!
//! * a host-path bind (`fstype` `bind`/`none`, absolute source) is an `mpN`
//!   mount point, set and removed through `PUT /nodes/{node}/lxc/{vmid}/config`
//!   with the config `digest`, so a concurrent change fails instead of being
//!   overwritten;
//! * a cifs/nfs mount is a raw `lxc.mount.entry`, which the PVE config API does
//!   not expose. Only that path edits `/etc/pve/lxc/<vmid>.conf`, and only
//!   through [`edit_raw_conf`]: the CT must be stopped, the config digest must be
//!   unchanged across the edit, and the write is atomic.
//!
//! Core routes a guest-targeted storage placement here as a
//! [`GuestMountSpec`](plugin_toolkit::storage::GuestMountSpec): `guest` is the
//! LXC vmid, `target` the mountpoint inside it, `sources` the share's routes,
//! `options` its rendered `-o` string, and `credential` an opaque
//! [`SecretRef`](plugin_toolkit::storage::SecretRef) string. For cifs the
//! password is resolved through the secrets domain and written to a root-owned
//! `0600` creds file under [`SECRET_FILE_DIR`], referenced by `credentials=` in
//! the entry — the password never sits inline in the config.
//!
//! VM guests (their own kernel mounts via cloud-init/fstab) are a later phase;
//! this domain handles LXC and returns a clear error for a VM vmid.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json::{self, Value};
use plugin_toolkit::storage::{GuestMountSpec, SECRET_FILE_DIR, parse_option_string};
use serde::Deserialize;

use crate::responses::{ConfigField, GuestConfigData};
use crate::{GuestKind, generated};

/// Invoke-name prefix for this domain's ops (`proxmox.__guest_mount.*`).
pub const GM_PREFIX: &str = "proxmox.__guest_mount";
const PROVIDER: &str = "proxmox";
/// PVE allows `mp0`..`mp255`.
const MAX_MP: u32 = 256;
const CREDS_FILE_MODE: u32 = 0o600;

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
    let op = name.strip_prefix(GM_PREFIX)?.strip_prefix('.')?.to_string();
    Some(plugin_toolkit::reactor::block_on(async move {
        match op.as_str() {
            "guest_mount_apply" => {
                let a: GuestApplyArgs = serde_json::from_value(args)
                    .map_err(|e| err_val(format!("guest_mount_apply args: {e}")))?;
                apply(&a.spec).await.map(Value::String).map_err(err_val)
            }
            "guest_mount_remove" => {
                let a: GuestRemoveArgs = serde_json::from_value(args)
                    .map_err(|e| err_val(format!("guest_mount_remove args: {e}")))?;
                remove(&a.guest, &a.target)
                    .await
                    .map(Value::String)
                    .map_err(err_val)
            }
            other => Err(err_val(format!("unknown guest_mount op '{other}'"))),
        }
    }))
}

/// A message-only backend error is a plain JSON string.
fn err_val(msg: impl Into<String>) -> serde_json::Value {
    serde_json::Value::String(msg.into())
}

/// Reconcile the guest's mount for `spec` to present. Idempotent: rewrites the
/// `lxc.mount.entry` for this mountpoint (and, for cifs, its creds file) only
/// when they diverge. The mount goes live on the guest's next start; a running
/// guest picks it up on reboot (the converge loop re-applies each tick, so no
/// state is lost).
async fn apply(spec: &GuestMountSpec) -> Result<String, String> {
    let vmid = parse_vmid(&spec.guest)?;
    let conf_path = lxc_conf_path(vmid)?;
    let fs_spec = spec
        .sources
        .first()
        .ok_or_else(|| format!("guest {vmid}: share has no enabled source route"))?;
    if is_bind(&spec.fstype, fs_spec) {
        return apply_bind(vmid, &conf_path, fs_spec, spec).await;
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

    let changed = edit_raw_conf(vmid, |conf| {
        let (rewritten, changed) = upsert_entry(conf, &mountpoint_rel, &entry);
        changed.then_some(rewritten)
    })
    .await?;
    if changed {
        Ok(format!(
            "Set guest mount {} in {conf_path}; applies on next start of CT {vmid} (`pct reboot {vmid}`).",
            spec.target
        ))
    } else {
        Ok(format!(
            "Guest mount {} already present in {conf_path} (CT {vmid}).",
            spec.target
        ))
    }
}

/// Reconcile a host-path bind as an `mpN` mount point through the PVE API.
async fn apply_bind(
    vmid: u64,
    conf_path: &str,
    src: &str,
    spec: &GuestMountSpec,
) -> Result<String, String> {
    let ro = parse_option_string(&spec.options)
        .any(|o| o.key == "ro" && o.value.is_none_or(|v| v == "1"));
    let value = render_mp_value(src, &spec.target, ro);
    let conf = std::fs::read_to_string(conf_path).map_err(|e| format!("read {conf_path}: {e}"))?;
    if find_mp(&conf_mp_entries(&conf), &spec.target).is_some_and(|(_, v)| v == value) {
        return Ok(format!(
            "Bind mount {} already present on CT {vmid}.",
            spec.target
        ));
    }
    let ct = PveCt::locate(vmid).await?;
    let cfg = ct.config().await?;
    let digest = config_digest(&cfg)?;
    let entries = api_mp_entries(&cfg);
    let key = match find_mp(&entries, &spec.target) {
        Some((k, _)) => k.to_string(),
        None => first_free_mp(&entries)
            .ok_or_else(|| format!("CT {vmid}: all {MAX_MP} mount point slots are in use"))?,
    };
    ct.put_config(&mp_set_pairs(&key, &value, &digest)).await?;
    Ok(format!(
        "Set {key} bind mount {} on CT {vmid} via the PVE API.",
        spec.target
    ))
}

/// Remove the mount at `target` inside `guest` — the counterpart to a deleted or
/// disabled placement. Idempotent: absent entry ⇒ `Ok`. Also removes the creds
/// file (best-effort; a missing file is not an error).
async fn remove(guest: &str, target: &str) -> Result<String, String> {
    let vmid = parse_vmid(guest)?;
    let conf_path = lxc_conf_path(vmid)?;
    let mountpoint_rel = relative_mountpoint(target);

    let conf = std::fs::read_to_string(&conf_path).map_err(|e| format!("read {conf_path}: {e}"))?;
    if find_mp(&conf_mp_entries(&conf), target).is_some() {
        let ct = PveCt::locate(vmid).await?;
        let cfg = ct.config().await?;
        let digest = config_digest(&cfg)?;
        let entries = api_mp_entries(&cfg);
        if let Some((key, _)) = find_mp(&entries, target) {
            ct.put_config(&mp_delete_pairs(key, &digest)).await?;
            return Ok(format!(
                "Removed {key} bind mount {target} from CT {vmid} via the PVE API."
            ));
        }
    }

    let removed = edit_raw_conf(vmid, |conf| {
        let (rewritten, removed) = strip_entry(conf, &mountpoint_rel);
        removed.then_some(rewritten)
    })
    .await?;
    // Best-effort creds cleanup; a leftover/absent file is harmless.
    std::fs::remove_file(guest_creds_path(vmid, target)).ok();

    if removed {
        Ok(format!(
            "Removed guest mount {target} from {conf_path}; frees on next start of CT {vmid}."
        ))
    } else {
        Ok(format!(
            "Guest mount {target} not present in {conf_path} (CT {vmid})."
        ))
    }
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
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
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
    let tmp = path.with_file_name(format!(".{name}.tmp.{}", std::process::id()));
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

// ── PVE API ─────────────────────────────────────────────────────────────────

/// A CT on this node, reached through an enabled endpoint's API.
struct PveCt {
    http: reqwest::Client,
    client: generated::Client,
    base_url: String,
    node: String,
    vmid: u64,
}

impl PveCt {
    /// The first enabled endpoint whose cluster places `vmid` on this node.
    async fn locate(vmid: u64) -> Result<Self, String> {
        let local = crate::diagnostics::local_node();
        let mut errs = Vec::new();
        for name in crate::tools::enabled_endpoint_names() {
            let cfg = match crate::tools::resolve_config(&name).await {
                Ok(c) => c,
                Err(e) => {
                    errs.push(format!("{name}: {e:#}"));
                    continue;
                }
            };
            let (http, client) = match (cfg.build_reqwest_client(), cfg.build_generated_client()) {
                (Ok(h), Ok(c)) => (h, c),
                (Err(e), _) | (_, Err(e)) => {
                    errs.push(format!("{name}: {e}"));
                    continue;
                }
            };
            match crate::lxc_guest::find_ct(&client, vmid).await {
                Ok(ct) if ct.node == local => {
                    return Ok(Self {
                        http,
                        client,
                        base_url: cfg.base_url,
                        node: ct.node,
                        vmid,
                    });
                }
                Ok(ct) => errs.push(format!("{name}: CT {vmid} is on node '{}'", ct.node)),
                Err(e) => errs.push(format!("{name}: {e:#}")),
            }
        }
        Err(format!(
            "CT {vmid}: no enabled proxmox endpoint places it on node '{local}' ({})",
            errs.join("; ")
        ))
    }

    async fn config(&self) -> Result<GuestConfigData, String> {
        crate::fetch_guest_config(
            &self.http,
            &self.base_url,
            &self.node,
            GuestKind::Lxc,
            self.vmid,
        )
        .await
        .map(|r| r.data)
        .map_err(|e| format!("CT {} config: {e}", self.vmid))
    }

    async fn status(&self) -> Result<String, String> {
        self.client
            .get_vm_status_nodes_node_lxc_vmid_status_current(&self.node, self.vmid as i64)
            .await
            .map(|r| r.into_inner().status.to_string())
            .map_err(|e| format!("CT {} status: {e}", self.vmid))
    }

    async fn put_config(&self, pairs: &[(String, String)]) -> Result<(), String> {
        let url = format!(
            "{}/nodes/{}/lxc/{}/config",
            self.base_url.trim_end_matches('/'),
            crate::backup::enc(&self.node),
            self.vmid
        );
        crate::backup::put_form(&self.http, &url, pairs)
            .await
            .map_err(|e| format!("{e:#}"))
    }
}

fn config_digest(cfg: &GuestConfigData) -> Result<String, String> {
    cfg.get_str("digest")
        .map(str::to_string)
        .ok_or_else(|| "PVE config response carries no digest".to_string())
}

/// Raw `lxc.*` lines have no PVE API, so they are edited in the conf file under
/// guards: the CT must be stopped (a running CT's conf is live state PVE may
/// rewrite), the digest must not change between read and write, and the write
/// is atomic. `edit` returns the new conf, or `None` for no change. Returns
/// whether the file was written; a no-op never touches the API.
pub(crate) async fn edit_raw_conf<F>(vmid: u64, edit: F) -> Result<bool, String>
where
    F: Fn(&str) -> Option<String>,
{
    let path = format!("/etc/pve/lxc/{vmid}.conf");
    let read = || std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"));
    if edit(&read()?).is_none() {
        return Ok(false);
    }
    let ct = PveCt::locate(vmid).await?;
    require_stopped(vmid, &ct.status().await?)?;
    let before = config_digest(&ct.config().await?)?;
    let Some(rewritten) = edit(&read()?) else {
        return Ok(false);
    };
    let after = config_digest(&ct.config().await?)?;
    require_same_digest(vmid, &before, &after)?;
    atomic_replace(Path::new(&path), rewritten.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))?;
    Ok(true)
}

fn require_stopped(vmid: u64, status: &str) -> Result<(), String> {
    if status == "stopped" {
        Ok(())
    } else {
        Err(format!(
            "CT {vmid} is {status}; raw lxc.* config lines have no PVE API, so they are only \
             edited while the CT is stopped (`pct stop {vmid}`)"
        ))
    }
}

fn require_same_digest(vmid: u64, before: &str, after: &str) -> Result<(), String> {
    if before == after {
        Ok(())
    } else {
        Err(format!(
            "CT {vmid} config changed during the edit (digest {before} -> {after}); aborted"
        ))
    }
}

// ── Mount points (mpN) ──────────────────────────────────────────────────────

/// True for a host-path bind, which PVE models as an `mpN` mount point.
fn is_bind(fstype: &str, src: &str) -> bool {
    matches!(fstype, "bind" | "none") && src.starts_with('/')
}

fn is_mp_key(key: &str) -> bool {
    key.strip_prefix("mp")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// `mpN` entries from the conf's live section (before any `[snapshot]`).
fn conf_mp_entries(conf: &str) -> Vec<(String, String)> {
    conf.lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            let k = k.trim();
            is_mp_key(k).then(|| (k.to_string(), v.trim().to_string()))
        })
        .collect()
}

fn api_mp_entries(cfg: &GuestConfigData) -> Vec<(String, String)> {
    cfg.fields
        .iter()
        .filter_map(|(k, v)| match v {
            ConfigField::Str(s) if is_mp_key(k) => Some((k.clone(), s.clone())),
            _ => None,
        })
        .collect()
}

/// The `mpN` whose `mp=` is `target`.
fn find_mp<'a>(entries: &'a [(String, String)], target: &str) -> Option<(&'a str, &'a str)> {
    entries
        .iter()
        .find(|(_, v)| v.split(',').any(|p| p.strip_prefix("mp=") == Some(target)))
        .map(|(k, v)| (k.as_str(), v.as_str()))
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

fn mp_set_pairs(key: &str, value: &str, digest: &str) -> Vec<(String, String)> {
    vec![
        (key.to_string(), value.to_string()),
        ("digest".to_string(), digest.to_string()),
    ]
}

fn mp_delete_pairs(key: &str, digest: &str) -> Vec<(String, String)> {
    vec![
        ("delete".to_string(), key.to_string()),
        ("digest".to_string(), digest.to_string()),
    ]
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

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
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
    fn raw_edit_refused_unless_stopped() {
        assert!(require_stopped(110, "stopped").is_ok());
        let err = require_stopped(110, "running").unwrap_err();
        assert!(err.contains("running"));
    }

    #[test]
    fn raw_edit_aborts_on_digest_change() {
        assert!(require_same_digest(110, "abc", "abc").is_ok());
        assert!(require_same_digest(110, "abc", "def").is_err());
    }

    #[test]
    fn first_free_mp_fills_gaps() {
        assert_eq!(first_free_mp(&[]), Some("mp0".to_string()));
        let e = entries(&[("mp0", "/a,mp=/a"), ("mp2", "/c,mp=/c")]);
        assert_eq!(first_free_mp(&e), Some("mp1".to_string()));
        let full: Vec<_> = (0..MAX_MP)
            .map(|i| (format!("mp{i}"), String::new()))
            .collect();
        assert_eq!(first_free_mp(&full), None);
    }

    #[test]
    fn find_mp_matches_target_exactly() {
        let e = entries(&[
            ("mp0", "/srv/a,mp=/mnt/a"),
            ("mp3", "/srv/b,mp=/mnt/b,ro=1"),
        ]);
        assert_eq!(find_mp(&e, "/mnt/b").map(|(k, _)| k), Some("mp3"));
        assert!(find_mp(&e, "/mnt").is_none());
    }

    #[test]
    fn conf_mp_entries_reads_live_section_only() {
        let conf = "arch: amd64\nmp0: /srv/a,mp=/mnt/a\nmemory: 512\n[snap1]\nmp1: /x,mp=/y\n";
        assert_eq!(
            conf_mp_entries(conf),
            entries(&[("mp0", "/srv/a,mp=/mnt/a")])
        );
    }

    #[test]
    fn mp_requests_carry_value_and_digest() {
        let value = render_mp_value("/srv/media", "/mnt/media", true);
        assert_eq!(value, "/srv/media,mp=/mnt/media,ro=1");
        assert_eq!(
            mp_set_pairs("mp1", &value, "d1"),
            entries(&[("mp1", "/srv/media,mp=/mnt/media,ro=1"), ("digest", "d1")])
        );
        assert_eq!(
            mp_delete_pairs("mp1", "d1"),
            entries(&[("delete", "mp1"), ("digest", "d1")])
        );
        assert_eq!(render_mp_value("/a", "/b", false), "/a,mp=/b");
    }

    #[test]
    fn bind_detection_needs_bind_type_and_host_path() {
        assert!(is_bind("bind", "/srv/a"));
        assert!(is_bind("none", "/srv/a"));
        assert!(!is_bind("cifs", "//host/share"));
        assert!(!is_bind("nfs", "host:/export"));
    }

    #[test]
    fn parse_vmid_rejects_non_numeric() {
        assert_eq!(parse_vmid("110").unwrap(), 110);
        assert!(parse_vmid("baldur").is_err());
    }
}
