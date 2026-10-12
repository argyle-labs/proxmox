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
//! Everything goes through the PVE REST API except the one thing it cannot set:
//!
//! * Container state — run state from `status/current`, mount points and their
//!   pending changes from `config` + `pending`, read with the endpoint's token.
//! * Host-path binds (`fstype` `bind`/`none`) are `mpN` mount points, set with
//!   `PUT /nodes/{node}/lxc/{vmid}/config` guarded by the config `digest`. PVE
//!   allows a bind `mpN` only to `root@pam` and refuses API tokens
//!   (`check_ct_modify_config_perm`), so that one call authenticates with a
//!   `root@pam` ticket whose password is the orca secret
//!   `proxmox.<endpoint>.root_password`. A change PVE cannot hotplug lands in
//!   `[pve:pending]` and is reported as pending a restart.
//! * cifs/nfs kernel mounts are raw `lxc.mount.entry` lines. PVE has no API (or
//!   CLI) for `lxc.*` keys, so this is the escape hatch: the plugin runs as the
//!   unprivileged orca user, so the edit of `/etc/pve/lxc/<vmid>.conf` (and the
//!   root-owned creds file) runs as root through orca's verified `admin
//!   plugin-apply` seam ([`privileged_ops`]). There [`edit_raw_conf_in`] holds PVE's
//!   own per-CT config flock, re-reads the file under it, edits only the live
//!   section, and replaces it atomically. A changed line on a running CT takes
//!   effect on its next restart; that is reported as pending, never forced.
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
use std::time::{Duration, Instant, SystemTime};

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::privileged::PrivilegedOps;
use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json::{self, Value};
use plugin_toolkit::storage::{GuestMountSpec, SECRET_FILE_DIR, parse_option_string};
use serde::{Deserialize, Serialize};

use crate::Config;
use crate::generated::{self, types as gtypes};

/// Invoke-name prefix for this domain's ops (`proxmox.__guest_mount.*`).
pub const GM_PREFIX: &str = "proxmox.__guest_mount";
const PROVIDER: &str = "proxmox";
const CREDS_FILE_MODE: u32 = 0o600;
const CREDS_DIR_MODE: u32 = 0o700;
/// PVE's `lock_config` waits 10s for the config flock.
const CONF_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// A temp file older than this is stale even if its pid has been reused.
const TEMP_STALE_AGE: Duration = Duration::from_secs(600);
/// An unreferenced creds file younger than this may belong to an in-flight
/// apply that has written it but not yet its entry.
const CREDS_ORPHAN_AGE: Duration = Duration::from_secs(600);
/// The only PVE user allowed to set a bind `mpN`.
const ROOT_USER: &str = "root@pam";
/// Upper bound on a tmpfs resize, whatever the CT's memory.
const SHM_MAX_MB: u64 = 64 * 1024;
/// Privileged-seam op names (`<plugin> --privileged-op`).
pub const OP_SET_ENTRY: &str = "guest_mount.set_entry";
pub const OP_STRIP_ENTRY: &str = "guest_mount.strip_entry";
pub const OP_SHM_RESIZE: &str = "guest_mount.shm_resize";

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

/// Kernel network filesystems a raw `lxc.mount.entry` may carry.
const NETWORK_FSTYPES: &[&str] = &["cifs", "smb3", "smb", "nfs", "nfs4"];

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
                let a = serde_json::from_value::<GuestApplyArgs>(args)
                    .map_err(|e| err_val(format!("guest_mount_apply args: {e}")))?;
                apply(&a.spec).await.map(Value::String).map_err(err_val)
            }
            "guest_mount_remove" => {
                let a = serde_json::from_value::<GuestRemoveArgs>(args)
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

async fn apply(spec: &GuestMountSpec) -> Result<String, String> {
    let vmid = parse_vmid(&spec.guest)?;
    let plan = classify(spec)?;
    let io = PveIo::locate(vmid).await?;
    apply_with(&io, vmid, spec, plan).await
}

async fn remove(guest: &str, target: &str) -> Result<String, String> {
    let vmid = parse_vmid(guest)?;
    check_target(target)?;
    let io = PveIo::locate(vmid).await?;
    remove_with(&io, vmid, target).await
}

/// Reconcile the guest's mount for `spec` to present. Idempotent: writes only
/// when the mount (or, for cifs, its creds file) diverges.
async fn apply_with<I: GuestMountIo>(
    io: &I,
    vmid: u64,
    spec: &GuestMountSpec,
    plan: Plan<'_>,
) -> Result<String, String> {
    match plan {
        Plan::Bind { src, ro } => apply_bind(io, vmid, src, &spec.target, ro).await,
        Plan::Raw { fs_spec } => apply_raw(io, vmid, spec, fs_spec).await,
    }
}

/// A cifs/nfs mount as a raw `lxc.mount.entry`, written as root through the
/// privileged seam.
async fn apply_raw<I: GuestMountIo>(
    io: &I,
    vmid: u64,
    spec: &GuestMountSpec,
    fs_spec: &str,
) -> Result<String, String> {
    let target = spec.target.as_str();
    let conf = io.conf(vmid).await?;
    if let Some(slot) = conf.mps_on(target).first() {
        return Err(format!(
            "CT {vmid}: {} already mounts {} at {target}; remove it before placing a {} mount \
             there",
            slot.key,
            slot.effective().unwrap_or_default(),
            spec.fstype
        ));
    }
    let creds = if is_cifs(&spec.fstype) {
        spec.credential
            .as_deref()
            .map(|r| resolve_creds(r, &spec.options))
            .transpose()?
    } else {
        None
    };
    let op = SetEntryOp {
        vmid,
        target: target.to_string(),
        fs_spec: fs_spec.to_string(),
        fstype: spec.fstype.clone(),
        options: spec.options.clone(),
        creds,
    };
    // Without a creds file the rendered line is fully known here, so an identical
    // entry needs no root round-trip.
    let line = op.entry_line(None);
    let present = conf
        .raw_entries
        .iter()
        .any(|e| format!("lxc.mount.entry: {e}") == line);
    let edit = if op.creds.is_none() && present {
        RawEdit::Unchanged
    } else {
        io.set_entry(&op).await?
    };
    Ok(match raw_outcome(io, vmid, edit).await {
        Outcome::Unchanged => format!("Guest mount {target} already present on CT {vmid}."),
        Outcome::Written => {
            format!("Set guest mount {target} on CT {vmid}; mounts on its next start.")
        }
        Outcome::PendingRestart => format!(
            "Pending restart: set guest mount {target} on CT {vmid}; it is running and mounts \
             it after a restart."
        ),
        Outcome::Unverified(e) => format!(
            "Pending restart, verify: set guest mount {target} on CT {vmid}; its run state is \
             unknown ({e}), so if it is running it mounts it after a restart."
        ),
    })
}

/// A host-path bind as one `mpN`. An existing bind for the target is reused
/// (keeping its other options); duplicates for it are deleted in the same call.
/// A raw entry an older release wrote for the target is stripped only after the
/// API call succeeds.
async fn apply_bind<I: GuestMountIo>(
    io: &I,
    vmid: u64,
    src: &str,
    target: &str,
    ro: bool,
) -> Result<String, String> {
    let conf = io.conf(vmid).await?;
    let on_target = conf.mps_on(target);
    if let Some(vol) = on_target.iter().find(|s| !s.is_bind()) {
        return Err(format!(
            "CT {vmid}: {} already mounts storage volume {} at {target}; refusing to bind over it",
            vol.key,
            vol.effective().unwrap_or_default()
        ));
    }
    let (key, set, delete) = match on_target.split_first() {
        Some((first, rest)) => {
            let current = first.effective().unwrap_or_default();
            let set = (!mp_fields_match(current, src, target, ro))
                .then(|| render_mp_value(src, target, ro, &parse_mp(current).extras));
            (
                first.key.clone(),
                set,
                rest.iter().map(|s| s.key.clone()).collect::<Vec<_>>(),
            )
        }
        None => (
            conf.first_free_mp()
                .ok_or_else(|| format!("CT {vmid}: all {MAX_MP} mount point slots are in use"))?,
            Some(render_mp_value(src, target, ro, &[])),
            Vec::new(),
        ),
    };
    let changed = set.is_some() || !delete.is_empty();
    if changed {
        io.set_mps(
            vmid,
            &conf.digest,
            set.as_deref().map(|v| (key.as_str(), v)),
            &delete,
        )
        .await?;
    }
    if conf.has_raw_entry(target) {
        io.strip_entry(&StripEntryOp {
            vmid,
            target: target.to_string(),
        })
        .await?;
    }
    let after = io.conf(vmid).await?;
    let pending = after.slot(&key).is_some_and(MpSlot::is_pending);
    let pending_deletes: Vec<&str> = delete
        .iter()
        .filter(|k| after.slot(k).is_some())
        .map(String::as_str)
        .collect();
    let msg = match (changed, pending) {
        (false, false) => format!("Bind mount {target} already present as {key} on CT {vmid}."),
        (true, false) => format!("Set {key} bind mount {target} on CT {vmid}."),
        (_, true) => format!(
            "Pending restart: {key} bind mount {target} on CT {vmid} is held in [pve:pending] \
             until the CT restarts."
        ),
    };
    Ok(if pending_deletes.is_empty() {
        msg
    } else {
        format!(
            "{msg} Pending restart: delete of duplicate {} for {target} is held in \
             [pve:pending] until the CT restarts.",
            pending_deletes.join(",")
        )
    })
}

/// Remove the mount at `target` inside the CT. Idempotent: absent ⇒ `Ok`.
/// Deletes every host-path bind `mpN` on `target` through the API, then strips
/// any raw `lxc.mount.entry` for it (which also drops its unreferenced creds).
async fn remove_with<I: GuestMountIo>(io: &I, vmid: u64, target: &str) -> Result<String, String> {
    let conf = io.conf(vmid).await?;
    let keys: Vec<String> = conf
        .mps_on(target)
        .iter()
        .filter(|s| s.is_bind())
        .map(|s| s.key.clone())
        .collect();
    let mut msgs = Vec::new();
    if !keys.is_empty() {
        io.set_mps(vmid, &conf.digest, None, &keys).await?;
        let after = io.conf(vmid).await?;
        let joined = keys.join(",");
        msgs.push(if keys.iter().any(|k| after.slot(k).is_some()) {
            format!(
                "Pending restart: removed {joined} bind mount {target} from CT {vmid}; PVE \
                 holds the delete in [pve:pending] until the CT restarts."
            )
        } else {
            format!("Removed {joined} bind mount {target} from CT {vmid}.")
        });
    }
    if conf.has_raw_entry(target) {
        let edit = io
            .strip_entry(&StripEntryOp {
                vmid,
                target: target.to_string(),
            })
            .await?;
        msgs.push(match raw_outcome(io, vmid, edit).await {
            Outcome::Unchanged | Outcome::Written => {
                format!("Removed guest mount {target} from CT {vmid}.")
            }
            Outcome::PendingRestart => format!(
                "Pending restart: removed guest mount {target} from CT {vmid}; it is running \
                 and keeps the mount until a restart."
            ),
            Outcome::Unverified(e) => format!(
                "Pending restart, verify: removed guest mount {target} from CT {vmid}; its run \
                 state is unknown ({e}), so if it is running it keeps the mount until a restart."
            ),
        });
    }
    if msgs.is_empty() {
        msgs.push(format!("Guest mount {target} not present on CT {vmid}."));
    }
    Ok(msgs.join(" "))
}

/// What a raw-entry write means for the CT, read from the API run state.
enum Outcome {
    Unchanged,
    Written,
    PendingRestart,
    Unverified(String),
}

async fn raw_outcome<I: GuestMountIo>(io: &I, vmid: u64, edit: RawEdit) -> Outcome {
    if edit == RawEdit::Unchanged {
        return Outcome::Unchanged;
    }
    match io.running(vmid).await {
        Ok(true) => Outcome::PendingRestart,
        Ok(false) => Outcome::Written,
        Err(e) => Outcome::Unverified(e),
    }
}

// ── Validation ──────────────────────────────────────────────────────────────

/// How a spec is placed.
#[derive(Debug, PartialEq, Eq)]
enum Plan<'a> {
    Bind { src: &'a str, ro: bool },
    Raw { fs_spec: &'a str },
}

/// Validate every field of `spec` and pick how it is placed.
fn classify(spec: &GuestMountSpec) -> Result<Plan<'_>, String> {
    check_target(&spec.target)?;
    check_token("fstype", &spec.fstype)?;
    if !spec.options.is_empty() {
        check_token("options", &spec.options)?;
    }
    let src = spec
        .sources
        .first()
        .ok_or_else(|| format!("guest {}: share has no enabled source route", spec.guest))?;
    check_token("source", src)?;
    let opts = || parse_option_string(&spec.options);
    match spec.fstype.as_str() {
        "rbind" => Err("rbind mounts are not supported; a PVE mpN is a plain bind".to_string()),
        "bind" | "none" => {
            if opts().any(|o| o.key == "rbind") {
                return Err("rbind mounts are not supported; a PVE mpN is a plain bind".to_string());
            }
            if !src.starts_with('/') {
                return Err(format!("bind source '{src}' is not an absolute host path"));
            }
            check_abs_path("bind source", src)?;
            check_mp_field("bind source", src)?;
            check_mp_field("target", &spec.target)?;
            let ro = opts().any(|o| o.key == "ro" && o.value.is_none_or(truthy));
            Ok(Plan::Bind { src, ro })
        }
        t if NETWORK_FSTYPES.contains(&t) => {
            check_network_mount(t, src, &spec.options)?;
            Ok(Plan::Raw { fs_spec: src })
        }
        other => Err(format!(
            "unsupported guest mount fstype '{other}' (expected bind, cifs or nfs)"
        )),
    }
}

/// A config field that must stay one token: no control characters or whitespace.
fn check_token(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err(format!("{what} is empty"));
    }
    if let Some(c) = s.chars().find(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!("{what} '{}' contains {c:?}", s.escape_debug()));
    }
    Ok(())
}

/// An absolute path with no empty, `.` or `..` component and no trailing `/`.
fn check_abs_path(what: &str, p: &str) -> Result<(), String> {
    check_token(what, p)?;
    let rest = p
        .strip_prefix('/')
        .ok_or_else(|| format!("{what} '{p}' is not absolute"))?;
    if rest
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(format!("{what} '{p}' is not a normalized absolute path"));
    }
    Ok(())
}

fn check_target(target: &str) -> Result<(), String> {
    check_abs_path("target", target)
}

/// `,` and `=` would split or re-key a PVE property string.
fn check_mp_field(what: &str, s: &str) -> Result<(), String> {
    if s.contains([',', '=']) {
        return Err(format!("{what} '{s}' contains ',' or '='"));
    }
    Ok(())
}

/// Mount options that would turn a network entry into a host bind or change
/// mount propagation; refused by name so the error says why.
const DENIED_OPTION_KEYS: &[&str] = &[
    "bind",
    "rbind",
    "remount",
    "move",
    "shared",
    "rshared",
    "slave",
    "rslave",
    "private",
    "rprivate",
    "unbindable",
    "runbindable",
];

/// Option keys any network entry may carry.
const COMMON_OPTION_KEYS: &[&str] = &[
    "ro",
    "rw",
    "vers",
    "sec",
    "soft",
    "hard",
    "_netdev",
    "nofail",
    "create",
    "noexec",
    "nosuid",
    "nodev",
    "noatime",
    "nodiratime",
    "relatime",
];

const CIFS_OPTION_KEYS: &[&str] = &[
    "uid",
    "gid",
    "forceuid",
    "forcegid",
    "file_mode",
    "dir_mode",
    "noperm",
    "nobrl",
    "domain",
    "iocharset",
    "noserverino",
    "cache",
    "actimeo",
    "mfsymlinks",
    "seal",
    "echo_interval",
];

const NFS_OPTION_KEYS: &[&str] = &[
    "nfsvers",
    "timeo",
    "retrans",
    "rsize",
    "wsize",
    "proto",
    "port",
    "nolock",
    "lookupcache",
    "actimeo",
];

/// A raw network entry: the source is a remote share in its fstype's grammar
/// (never a local path) and every option is on the fstype's allowlist, so the
/// entry cannot bind a host path into the guest.
fn check_network_mount(fstype: &str, fs_spec: &str, options: &str) -> Result<(), String> {
    check_token("source", fs_spec)?;
    let fstype_keys = if is_cifs(fstype) {
        check_cifs_spec(fs_spec)?;
        CIFS_OPTION_KEYS
    } else if NETWORK_FSTYPES.contains(&fstype) {
        check_nfs_spec(fs_spec)?;
        NFS_OPTION_KEYS
    } else {
        return Err(format!("raw guest mount fstype '{fstype}' refused"));
    };
    if options.is_empty() {
        return Ok(());
    }
    check_token("options", options)?;
    for opt in parse_option_string(options) {
        if DENIED_OPTION_KEYS.contains(&opt.key) {
            return Err(format!("{fstype} mount option '{}' is refused", opt.key));
        }
        if opt.key == "create" && opt.value != Some("dir") {
            return Err(format!(
                "{fstype} mount option 'create={}' is refused; only create=dir",
                opt.value.unwrap_or_default()
            ));
        }
        let allowed = COMMON_OPTION_KEYS.contains(&opt.key)
            || fstype_keys.contains(&opt.key)
            || (is_cifs(fstype) && CREDENTIAL_KEYS.contains(&opt.key));
        if !allowed {
            return Err(format!(
                "{fstype} mount option '{}' is not on the allowlist",
                opt.key
            ));
        }
    }
    Ok(())
}

/// `//host/share[/path]`.
fn check_cifs_spec(fs_spec: &str) -> Result<(), String> {
    let bad = || format!("cifs source '{fs_spec}' is not //host/share[/path]");
    let rest = fs_spec.strip_prefix("//").ok_or_else(bad)?;
    let mut parts = rest.split('/');
    let host = parts.next().unwrap_or_default();
    if host.is_empty() || parts.clone().next().is_none() {
        return Err(bad());
    }
    if parts.any(|c| c.is_empty() || c == "." || c == "..") {
        return Err(bad());
    }
    Ok(())
}

/// `host:/path`.
fn check_nfs_spec(fs_spec: &str) -> Result<(), String> {
    let bad = || format!("nfs source '{fs_spec}' is not host:/path");
    let (host, path) = fs_spec
        .find(":/")
        .map(|i| (&fs_spec[..i], &fs_spec[i + 1..]))
        .ok_or_else(bad)?;
    if host.is_empty() || host.contains('/') {
        return Err(bad());
    }
    if path != "/" {
        check_abs_path("nfs export path", path).map_err(|_| bad())?;
    }
    Ok(())
}

fn truthy(v: &str) -> bool {
    matches!(v, "1" | "true" | "on" | "yes")
}

/// Parse the guest identifier as an LXC vmid.
fn parse_vmid(guest: &str) -> Result<u64, String> {
    guest
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("guest '{guest}' is not a numeric LXC vmid"))
}

// ── PVE API ─────────────────────────────────────────────────────────────────

/// The CT state and writes guest mounts need; [`PveIo`] is the real one.
pub(crate) trait GuestMountIo {
    async fn conf(&self, vmid: u64) -> Result<CtConf, String>;
    async fn running(&self, vmid: u64) -> Result<bool, String>;
    /// `PUT .../config` with `set`, `delete` and `digest`.
    async fn set_mps(
        &self,
        vmid: u64,
        digest: &str,
        set: Option<(&str, &str)>,
        delete: &[String],
    ) -> Result<(), String>;
    async fn set_entry(&self, op: &SetEntryOp) -> Result<RawEdit, String>;
    async fn strip_entry(&self, op: &StripEntryOp) -> Result<RawEdit, String>;
}

/// One `mpN` as `GET .../pending` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MpSlot {
    key: String,
    value: Option<String>,
    pending: Option<String>,
    delete: bool,
}

impl MpSlot {
    /// The value the CT has once pending changes apply.
    fn effective(&self) -> Option<&str> {
        if self.delete {
            None
        } else {
            self.pending.as_deref().or(self.value.as_deref())
        }
    }

    fn is_pending(&self) -> bool {
        self.delete || self.pending.is_some()
    }

    fn is_bind(&self) -> bool {
        self.effective()
            .and_then(|v| parse_mp(v).src)
            .is_some_and(|s| s.starts_with('/'))
    }
}

/// The parts of a CT's config guest mounts read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CtConf {
    digest: String,
    /// Every `mpN` key, current or pending.
    mps: Vec<MpSlot>,
    /// `lxc.mount.entry` values from the config's `lxc` pairs.
    raw_entries: Vec<String>,
}

impl CtConf {
    /// Every slot whose effective value mounts at `target`, in key order.
    fn mps_on(&self, target: &str) -> Vec<&MpSlot> {
        self.mps
            .iter()
            .filter(|s| s.effective().and_then(|v| parse_mp(v).mp) == Some(target))
            .collect()
    }

    fn slot(&self, key: &str) -> Option<&MpSlot> {
        self.mps.iter().find(|s| s.key == key)
    }

    /// The lowest `mpN` neither set nor pending.
    fn first_free_mp(&self) -> Option<String> {
        (0..MAX_MP)
            .map(|i| format!("mp{i}"))
            .find(|k| self.slot(k).is_none())
    }

    fn has_raw_entry(&self, target: &str) -> bool {
        let rel = relative_mountpoint(target);
        self.raw_entries
            .iter()
            .any(|e| e.split_whitespace().nth(1) == Some(rel.as_str()))
    }
}

/// Build a [`CtConf`] from the `data` of `GET .../config` and `GET .../pending`.
fn parse_ct_conf(config: &Value, pending: &Value) -> Result<CtConf, String> {
    let digest = config
        .get("digest")
        .and_then(Value::as_str)
        .ok_or("CT config has no digest")?
        .to_string();
    let raw_entries = config
        .get("lxc")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|pair| match pair.as_array()?.as_slice() {
            [k, v] if k.as_str() == Some("lxc.mount.entry") => v.as_str().map(str::to_string),
            _ => None,
        })
        .collect();
    let mut mps: Vec<MpSlot> = pending
        .as_array()
        .ok_or("CT pending is not a list")?
        .iter()
        .filter_map(|item| {
            let key = item.get("key")?.as_str()?;
            is_mp_key(key).then(|| MpSlot {
                key: key.to_string(),
                value: item.get("value").and_then(value_str),
                pending: item.get("pending").and_then(value_str),
                delete: item
                    .get("delete")
                    .and_then(Value::as_i64)
                    .is_some_and(|d| d != 0),
            })
        })
        .collect();
    mps.sort_by_key(|s| s.key[2..].parse::<usize>().unwrap_or(usize::MAX));
    Ok(CtConf {
        digest,
        mps,
        raw_entries,
    })
}

fn value_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// An enabled endpoint that sees the CT.
struct EndpointHit<C> {
    endpoint: String,
    node: String,
    url_local: bool,
    cfg: C,
}

/// The one endpoint to use for a CT on `local`.
fn pick_endpoint<C>(
    vmid: u64,
    local: &str,
    hits: Vec<EndpointHit<C>>,
    errors: &[String],
) -> Result<EndpointHit<C>, String> {
    let (mut here, elsewhere): (Vec<_>, Vec<_>) = hits.into_iter().partition(|h| h.node == local);
    if here.len() > 1 && here.iter().any(|h| h.url_local) {
        here.retain(|h| h.url_local);
    }
    match here.len() {
        1 => Ok(here.remove(0)),
        0 => match elsewhere.first() {
            Some(h) => Err(format!(
                "CT {vmid} runs on node '{}' but this proxmox plugin runs on '{local}'; apply \
                 its mounts from the orca instance on '{}'",
                h.node, h.node
            )),
            None => Err(format!(
                "guest {vmid}: no enabled proxmox endpoint hosts this LXC ({})",
                errors.join("; ")
            )),
        },
        _ => Err(format!(
            "guest {vmid}: endpoints {} all host this LXC on '{local}'; disable all but one",
            here.iter()
                .map(|h| format!("'{}'", h.endpoint))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// Whether `base_url`'s host resolves to an address bound on this machine.
fn url_is_this_host(base_url: &str) -> bool {
    use std::net::ToSocketAddrs;
    let Some(authority) = base_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
    else {
        return false;
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (h, p.parse().unwrap_or(443)),
        _ => (authority, 443),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (host, port).to_socket_addrs().is_ok_and(|mut addrs| {
        addrs.any(|a| a.ip().is_loopback() || std::net::UdpSocket::bind((a.ip(), 0)).is_ok())
    })
}

/// The API for one CT, on the enabled endpoint whose cluster hosts it.
struct PveIo {
    endpoint: String,
    cfg: Config,
    node: String,
}

impl PveIo {
    /// Find the endpoint that hosts LXC `vmid` on this node: a raw entry and its
    /// creds file are written locally. Endpoints that see the CT on another node
    /// are skipped; when several see it here, the one whose URL is this host wins.
    async fn locate(vmid: u64) -> Result<Self, String> {
        let local = crate::diagnostics::local_node();
        let mut hits = Vec::new();
        let mut errors = Vec::new();
        for name in crate::tools::enabled_endpoint_names() {
            let found = async {
                let cfg = crate::tools::resolve_config(&name).await?;
                let ct = crate::lxc_guest::find_ct(&cfg.build_generated_client()?, vmid).await?;
                Ok::<_, plugin_toolkit::anyhow::Error>((cfg, ct))
            }
            .await;
            match found {
                Ok((cfg, ct)) => hits.push(EndpointHit {
                    url_local: url_is_this_host(&cfg.base_url),
                    endpoint: name,
                    node: ct.node,
                    cfg,
                }),
                Err(e) => errors.push(format!("{name}: {e:#}")),
            }
        }
        let hit = pick_endpoint(vmid, &local, hits, &errors)?;
        Ok(Self {
            endpoint: hit.endpoint,
            cfg: hit.cfg,
            node: hit.node,
        })
    }

    fn ct_url(&self, vmid: u64) -> String {
        format!(
            "{}/nodes/{}/lxc/{vmid}",
            self.cfg.base_url.trim_end_matches('/'),
            plugin_toolkit::progenitor_client::encode_path(&self.node)
        )
    }

    /// A client carrying a fresh `root@pam` ticket and its CSRF token.
    async fn root_client(&self) -> Result<reqwest::Client, String> {
        refuse_insecure_root(&self.endpoint, self.cfg.insecure)?;
        let name = root_password_secret(&self.endpoint);
        let stored = plugin_toolkit::secrets::get(&name)
            .map_err(|e| format!("read secret '{name}': {e:#}"))?;
        let password = require_root_password(&self.endpoint, stored)?;
        let anon = plugin_toolkit::api_client::ApiClientBuilder::new()
            .build()
            .map_err(|e| format!("http client: {e:#}"))?;
        let body = gtypes::PostCreateTicketAccessTicketBody {
            new_format: None,
            otp: None,
            password,
            path: None,
            privs: None,
            realm: None,
            tfa_challenge: None,
            username: ROOT_USER.parse().map_err(|e| format!("{ROOT_USER}: {e}"))?,
        };
        let ticket = generated::Client::new_with_client(&self.cfg.base_url, anon)
            .post_create_ticket_access_ticket(&body)
            .await
            .map_err(|e| format!("{ROOT_USER} login on endpoint '{}': {e}", self.endpoint))?
            .into_inner();
        let (ticket, csrf) =
            root_session(&self.endpoint, ticket.ticket, ticket.csrf_prevention_token)?;
        plugin_toolkit::api_client::ApiClientBuilder::new()
            .header("cookie", format!("PVEAuthCookie={ticket}"))
            .and_then(|b| b.header("csrfpreventiontoken", csrf))
            .and_then(|b| b.build())
            .map_err(|e| format!("http client: {e:#}"))
    }
}

impl GuestMountIo for PveIo {
    async fn conf(&self, vmid: u64) -> Result<CtConf, String> {
        let http = self.cfg.build_reqwest_client().map_err(|e| e.to_string())?;
        let base = self.ct_url(vmid);
        let config = get_data(&http, &format!("{base}/config")).await?;
        let pending = get_data(&http, &format!("{base}/pending")).await?;
        parse_ct_conf(&config, &pending)
    }

    async fn running(&self, vmid: u64) -> Result<bool, String> {
        use gtypes::GetVmStatusNodesNodeLxcVmidStatusCurrentResponseStatus as Status;
        let status = self
            .cfg
            .build_generated_client()
            .map_err(|e| e.to_string())?
            .get_vm_status_nodes_node_lxc_vmid_status_current(&self.node, vmid as i64)
            .await
            .map_err(|e| format!("CT {vmid} status: {e}"))?
            .into_inner()
            .status;
        Ok(status == Status::Running)
    }

    async fn set_mps(
        &self,
        vmid: u64,
        digest: &str,
        set: Option<(&str, &str)>,
        delete: &[String],
    ) -> Result<(), String> {
        let http = self.root_client().await?;
        crate::backup::put_form(
            &http,
            &format!("{}/config", self.ct_url(vmid)),
            &config_put_pairs(digest, set, delete),
        )
        .await
        .map_err(|e| format!("CT {vmid} config: {e:#}"))
    }

    async fn set_entry(&self, op: &SetEntryOp) -> Result<RawEdit, String> {
        privileged(OP_SET_ENTRY, op).await
    }

    async fn strip_entry(&self, op: &StripEntryOp) -> Result<RawEdit, String> {
        privileged(OP_STRIP_ENTRY, op).await
    }
}

/// The `root@pam` password must not cross an unverified TLS link, and the HTTP
/// client has no certificate pinning, so an `insecure` endpoint is refused.
fn refuse_insecure_root(endpoint: &str, insecure: bool) -> Result<(), String> {
    if insecure {
        return Err(format!(
            "endpoint '{endpoint}' skips TLS verification (insecure), so orca will not send \
             the {ROOT_USER} password over it. Give the PVE node a certificate the host trusts \
             and turn insecure off for this endpoint."
        ));
    }
    Ok(())
}

/// The session from a ticket login. With two-factor on, PVE answers a password
/// with a half-ticket (`PVE:!tfa!...`, plus `NeedTFA`) that needs a second step;
/// the generated response type drops `NeedTFA`, so the ticket prefix decides.
fn root_session(
    endpoint: &str,
    ticket: Option<String>,
    csrf: Option<String>,
) -> Result<(String, String), String> {
    let tfa = || {
        format!(
            "{ROOT_USER} has two-factor enabled on endpoint '{endpoint}'; orca cannot complete \
             a two-factor login, so bind mount points cannot be set through this endpoint"
        )
    };
    match (ticket, csrf) {
        (Some(t), _) if t.starts_with("PVE:!tfa!") => Err(tfa()),
        (Some(t), Some(c)) => Ok((t, c)),
        _ => Err(format!(
            "{ROOT_USER} login on endpoint '{endpoint}' returned no ticket"
        )),
    }
}

/// The orca secret holding the `root@pam` password for `endpoint`.
pub(crate) fn root_password_secret(endpoint: &str) -> String {
    plugin_toolkit::secrets::scoped_name(PROVIDER, endpoint, "root_password")
}

fn require_root_password(endpoint: &str, stored: Option<String>) -> Result<String, String> {
    stored.filter(|p| !p.is_empty()).ok_or_else(|| {
        format!(
            "bind mount points need a {ROOT_USER} ticket: PVE refuses bind mpN to API tokens. \
             Store the {ROOT_USER} password for endpoint '{endpoint}' as the orca secret '{}'.",
            root_password_secret(endpoint)
        )
    })
}

fn config_put_pairs(
    digest: &str,
    set: Option<(&str, &str)>,
    delete: &[String],
) -> Vec<(String, String)> {
    let mut pairs = vec![("digest".to_string(), digest.to_string())];
    if let Some((k, v)) = set {
        pairs.push((k.to_string(), v.to_string()));
    }
    if !delete.is_empty() {
        pairs.push(("delete".to_string(), delete.join(",")));
    }
    pairs
}

/// `GET url` and return its `data`.
async fn get_data(http: &reqwest::Client, url: &str) -> Result<Value, String> {
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| format!("GET {url}: {e}"))?;
    if !status.is_success() {
        return Err(format!("GET {url}: HTTP {}: {body}", status.as_u16()));
    }
    serde_json::from_str::<Value>(&body)
        .map_err(|e| format!("GET {url}: {e}"))?
        .get_mut("data")
        .map(Value::take)
        .ok_or_else(|| format!("GET {url}: no data"))
}

async fn privileged<P: Serialize>(op: &str, payload: &P) -> Result<RawEdit, String> {
    let detail = plugin_toolkit::privileged::apply(PROVIDER, op, Some(payload))
        .await
        .map_err(|e| format!("{op} via orca's privileged seam: {e:#}"))?;
    RawEdit::from_detail(&detail)
}

// ── Mount point values ──────────────────────────────────────────────────────

/// PVE allows `mp0`..`mp255`.
const MAX_MP: usize = 256;

fn is_mp_key(key: &str) -> bool {
    key.strip_prefix("mp")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The fields of an `mpN` property string orca compares; everything else is
/// kept verbatim in `extras`.
#[derive(Debug, Default, PartialEq, Eq)]
struct MpFields<'a> {
    src: Option<&'a str>,
    mp: Option<&'a str>,
    ro: bool,
    extras: Vec<&'a str>,
}

fn parse_mp(value: &str) -> MpFields<'_> {
    let mut f = MpFields::default();
    for (i, part) in value.split(',').enumerate() {
        if let Some(v) = part.strip_prefix("volume=") {
            f.src = Some(v);
        } else if i == 0 && !part.contains('=') {
            f.src = Some(part);
        } else if let Some(v) = part.strip_prefix("mp=") {
            f.mp = Some(v);
        } else if let Some(v) = part.strip_prefix("ro=") {
            f.ro = truthy(v);
        } else {
            f.extras.push(part);
        }
    }
    f
}

fn mp_fields_match(value: &str, src: &str, target: &str, ro: bool) -> bool {
    let f = parse_mp(value);
    f.src == Some(src) && f.mp == Some(target) && f.ro == ro
}

fn render_mp_value(src: &str, target: &str, ro: bool, extras: &[&str]) -> String {
    let mut out = format!("{src},mp={target}");
    if ro {
        out.push_str(",ro=1");
    }
    for e in extras {
        out.push(',');
        out.push_str(e);
    }
    out
}

// ── Privileged raw-entry ops (run as root) ──────────────────────────────────

/// Payload of [`OP_SET_ENTRY`]. Carries the cifs password, so it is never logged.
#[derive(Serialize, Deserialize)]
pub(crate) struct SetEntryOp {
    vmid: u64,
    target: String,
    fs_spec: String,
    fstype: String,
    options: String,
    creds: Option<CifsCreds>,
}

impl SetEntryOp {
    /// The full `lxc.mount.entry:` line, referencing `cred_path` when given.
    fn entry_line(&self, cred_path: Option<&str>) -> String {
        render_lxc_mount_entry(
            &self.fs_spec,
            &relative_mountpoint(&self.target),
            &self.fstype,
            &render_entry_options(&self.options, cred_path),
        )
    }

    fn validate(&self) -> Result<(), String> {
        check_target(&self.target)?;
        check_network_mount(&self.fstype, &self.fs_spec, &self.options)?;
        if let Some(c) = &self.creds {
            check_token("username", &c.username)?;
            if let Some(d) = &c.domain {
                check_token("domain", d)?;
            }
            if c.password.chars().any(char::is_control) {
                return Err("cifs password contains a control character".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct CifsCreds {
    username: String,
    password: String,
    domain: Option<String>,
}

/// Payload of [`OP_STRIP_ENTRY`].
#[derive(Serialize, Deserialize)]
pub(crate) struct StripEntryOp {
    vmid: u64,
    target: String,
}

/// Payload of [`OP_SHM_RESIZE`]: the `size=` of a CT's tmpfs `lxc.mount.entry`,
/// which has no PVE API. `target` is the entry's relative mountpoint (`dev/shm`).
#[derive(Serialize, Deserialize)]
pub(crate) struct ShmResizeOp {
    pub(crate) vmid: u64,
    pub(crate) target: String,
    pub(crate) size_mb: u64,
}

impl ShmResizeOp {
    fn validate(&self) -> Result<(), String> {
        if self.target.starts_with('/') {
            return Err(format!("tmpfs target '{}' must be relative", self.target));
        }
        check_abs_path("tmpfs target", &format!("/{}", self.target))?;
        if self.size_mb == 0 {
            return Err("tmpfs size must be > 0 MiB".to_string());
        }
        if self.size_mb > SHM_MAX_MB {
            return Err(format!(
                "tmpfs size {} MiB exceeds the {SHM_MAX_MB} MiB cap",
                self.size_mb
            ));
        }
        Ok(())
    }
}

/// Resize a CT's tmpfs through orca's privileged seam.
pub(crate) async fn shm_resize(op: &ShmResizeOp) -> Result<RawEdit, String> {
    privileged(OP_SHM_RESIZE, op).await
}

/// The closed op set this plugin serves as root in `--privileged-op` mode.
pub fn privileged_ops() -> PrivilegedOps {
    PrivilegedOps::new()
        .op(OP_SET_ENTRY, |op: SetEntryOp| async move {
            root_set_entry(Path::new("/"), &op)
                .map(|e| e.detail().to_string())
                .map_err(plugin_toolkit::anyhow::Error::msg)
        })
        .op(OP_STRIP_ENTRY, |op: StripEntryOp| async move {
            root_strip_entry(Path::new("/"), &op)
                .map(|e| e.detail().to_string())
                .map_err(plugin_toolkit::anyhow::Error::msg)
        })
        .op(OP_SHM_RESIZE, |op: ShmResizeOp| async move {
            root_shm_resize(Path::new("/"), &op)
                .map(|e| e.detail().to_string())
                .map_err(plugin_toolkit::anyhow::Error::msg)
        })
}

/// Root side of [`OP_SET_ENTRY`]: write the creds file (if any), then upsert the
/// entry under PVE's config lock.
fn root_set_entry(root: &Path, op: &SetEntryOp) -> Result<RawEdit, String> {
    op.validate()?;
    let clash = |key: String| {
        format!(
            "CT {}: {key} already mounts {}; remove it before placing a {} mount there",
            op.vmid, op.target, op.fstype
        )
    };
    let path = lxc_conf_path_in(root, op.vmid)?;
    if let Some(key) = mp_on_target(split_live_section(&read_conf(&path)?).0, &op.target) {
        return Err(clash(key));
    }
    sweep_stale_temps_in(root, pid_alive);
    let cred_path = op
        .creds
        .as_ref()
        .map(|c| write_creds_file_in(root, op.vmid, &op.target, c))
        .transpose()?;
    let rel = relative_mountpoint(&op.target);
    let line = op.entry_line(cred_path.as_deref());
    let mp_clash = std::cell::RefCell::new(None);
    let edit = edit_raw_conf_in(root, op.vmid, |conf| {
        // Re-checked under the lock: an mpN may have landed since the read above.
        if let Some(key) = mp_on_target(conf, &op.target) {
            *mp_clash.borrow_mut() = Some(key);
            return None;
        }
        let (rewritten, changed) = upsert_entry(conf, &rel, &line);
        changed.then_some(rewritten)
    });
    if let Some(key) = mp_clash.into_inner() {
        return Err(clash(key));
    }
    let edit = edit?;
    if cred_path.is_none() {
        remove_creds_if_unreferenced(root, &guest_creds_path(op.vmid, &op.target));
    }
    sweep_orphan_creds_in(root);
    Ok(edit)
}

/// The `mpN` key in a live config section whose `mp=` is `target`.
fn mp_on_target(live: &str, target: &str) -> Option<String> {
    live.lines().find_map(|l| {
        let (key, value) = l.split_once(':')?;
        let key = key.trim();
        (is_mp_key(key) && parse_mp(value.trim()).mp == Some(target)).then(|| key.to_string())
    })
}

/// Root side of [`OP_STRIP_ENTRY`]: drop the entry, then its creds file once no
/// config references it.
fn root_strip_entry(root: &Path, op: &StripEntryOp) -> Result<RawEdit, String> {
    check_target(&op.target)?;
    sweep_stale_temps_in(root, pid_alive);
    let rel = relative_mountpoint(&op.target);
    let edit = edit_raw_conf_in(root, op.vmid, |conf| {
        let (rewritten, removed) = strip_entry(conf, &rel);
        removed.then_some(rewritten)
    })?;
    remove_creds_if_unreferenced(root, &guest_creds_path(op.vmid, &op.target));
    sweep_orphan_creds_in(root);
    Ok(edit)
}

/// Root side of [`OP_SHM_RESIZE`].
fn root_shm_resize(root: &Path, op: &ShmResizeOp) -> Result<RawEdit, String> {
    op.validate()?;
    sweep_stale_temps_in(root, pid_alive);
    let path = lxc_conf_path_in(root, op.vmid)?;
    if let Some(mem) = ct_memory_mb(split_live_section(&read_conf(&path)?).0)
        && op.size_mb > mem
    {
        return Err(format!(
            "tmpfs size {} MiB exceeds CT {} memory ({mem} MiB)",
            op.size_mb, op.vmid
        ));
    }
    edit_raw_conf_in(root, op.vmid, |conf| {
        let (rewritten, changed) =
            crate::shm_trap::rewrite_tmpfs_size(conf, &op.target, op.size_mb);
        changed.then_some(rewritten)
    })
}

/// The CT's `memory:` (MiB) from its live config section.
fn ct_memory_mb(live: &str) -> Option<u64> {
    live.lines()
        .find_map(|l| l.strip_prefix("memory:"))
        .and_then(|v| v.trim().parse().ok())
}

// ── Node-local paths ────────────────────────────────────────────────────────

/// `abs` resolved under `root` (`/` in production, a scratch dir in tests).
fn under(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
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

/// Filesystem-safe, reversible slug of a mountpoint: ASCII alphanumerics stay,
/// every other byte becomes `_xx` hex, so distinct targets never share a slug.
fn slug(target: &str) -> String {
    target
        .trim_start_matches('/')
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b).to_string()
            } else {
                format!("_{b:02x}")
            }
        })
        .collect()
}

// ── Credential handling ─────────────────────────────────────────────────────

/// Resolve the credential ref to a password and pair it with the identity in
/// the options. Runs plugin-side, where the secrets domain is reachable.
fn resolve_creds(cred_ref: &str, options: &str) -> Result<CifsCreds, String> {
    let password = plugin_toolkit::secrets::get_required(cred_ref)
        .map_err(|e| format!("resolve credential '{cred_ref}': {e}"))?;
    let (username, domain) = extract_identity(options);
    let username =
        username.ok_or("cifs mount has a credential but no `username=` in its options")?;
    Ok(CifsCreds {
        username,
        password,
        domain,
    })
}

/// Write the creds file root-owned `0600`; returns its absolute path for the
/// entry's `credentials=`.
fn write_creds_file_in(
    root: &Path,
    vmid: u64,
    target: &str,
    creds: &CifsCreds,
) -> Result<String, String> {
    let contents = render_creds_file(&creds.username, &creds.password, creds.domain.as_deref());
    let path = guest_creds_path(vmid, target);
    let file = under(root, &path);
    if let Some(parent) = file.parent() {
        ensure_private_dir(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    if creds_file_current(&file, contents.as_bytes()) {
        return Ok(path);
    }
    atomic_write(&file, contents.as_bytes(), CREDS_FILE_MODE, Some((0, 0)))
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

/// Every `credentials=` path any LXC config on this node references, snapshots
/// and pending sections included. `None` when the configs can't be read, so a
/// caller never deletes on a partial view.
fn referenced_creds(root: &Path) -> Option<Vec<String>> {
    let mut refs = Vec::new();
    for entry in std::fs::read_dir(root.join("etc/pve/lxc")).ok()? {
        let path = entry.ok()?.path();
        if path.extension().is_none_or(|e| e != "conf") {
            continue;
        }
        let conf = std::fs::read_to_string(&path).ok()?;
        refs.extend(
            conf.split([',', ' ', '\t', '\n'])
                .filter_map(|t| t.strip_prefix("credentials="))
                .map(str::to_string),
        );
    }
    Some(refs)
}

fn remove_creds_if_unreferenced(root: &Path, path: &str) {
    if referenced_creds(root).is_some_and(|refs| !refs.iter().any(|r| r == path)) {
        std::fs::remove_file(under(root, path)).ok();
    }
}

/// Delete `guest-*.secret` files no LXC config references, past
/// [`CREDS_ORPHAN_AGE`].
fn sweep_orphan_creds_in(root: &Path) {
    let Some(refs) = referenced_creds(root) else {
        return;
    };
    let Ok(dir) = std::fs::read_dir(under(root, SECRET_FILE_DIR)) else {
        return;
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("guest-") && name.ends_with(".secret")) {
            continue;
        }
        let abs = format!("{SECRET_FILE_DIR}/{name}");
        if !refs.contains(&abs) && older_than(&entry.path(), CREDS_ORPHAN_AGE) {
            std::fs::remove_file(entry.path()).ok();
        }
    }
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
/// contents are never readable under a looser mode. Named
/// `.<name>.tmp.<pid>.<seq>` for [`sweep_stale_temps_in`].
fn create_temp_beside(path: &Path, mode: u32) -> std::io::Result<(std::fs::File, PathBuf)> {
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

fn older_than(path: &Path, age: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|d| d > age)
}

fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// The pid in a `.<name>.tmp.<pid>.<seq>` temp name ending in `.conf` or
/// `.secret`, or `None` if `name` is not one of ours.
fn temp_pid(name: &str) -> Option<u32> {
    let (head, seq) = name.strip_prefix('.')?.rsplit_once('.')?;
    let (head, pid) = head.rsplit_once('.')?;
    let base = head.strip_suffix(".tmp")?;
    (seq.bytes().all(|b| b.is_ascii_digit())
        && (base.ends_with(".conf") || base.ends_with(".secret")))
    .then(|| pid.parse().ok())?
}

/// Delete temp files a crashed write left in `/etc/pve/lxc` or the creds dir:
/// those whose writer is gone, or that are older than [`TEMP_STALE_AGE`] (the
/// pid may have been reused). A live writer's fresh temp is left alone.
fn sweep_stale_temps_in(root: &Path, alive: impl Fn(u32) -> bool) {
    let me = std::process::id();
    for dir in [root.join("etc/pve/lxc"), under(root, SECRET_FILE_DIR)] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(pid) = temp_pid(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            if pid != me && (!alive(pid) || older_than(&entry.path(), TEMP_STALE_AGE)) {
                std::fs::remove_file(entry.path()).ok();
            }
        }
    }
}

// ── Raw conf edits ──────────────────────────────────────────────────────────

/// Result of [`edit_raw_conf_in`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RawEdit {
    Unchanged,
    /// Written; lxc reads `lxc.*` lines only at container start.
    Written,
}

impl RawEdit {
    fn detail(&self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Written => "written",
        }
    }

    fn from_detail(detail: &str) -> Result<Self, String> {
        match detail.trim() {
            "unchanged" => Ok(Self::Unchanged),
            "written" => Ok(Self::Written),
            other => Err(format!("unexpected privileged reply '{other}'")),
        }
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

fn read_conf(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))
}

/// Raw `lxc.*` lines have no PVE API or CLI, so the conf is edited locally as
/// root. The edit runs under PVE's own config flock, re-reads the file under it,
/// touches only the live section, and replaces the file atomically. `edit`
/// returns the new live section, or `None` for no change. Errors for a VM vmid.
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
    Ok(RawEdit::Written)
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
    use plugin_toolkit::serde_json::json;
    use std::sync::Mutex;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "proxmox-gm-{name}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&d).ok();
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // ── fake API ────────────────────────────────────────────────────────────

    /// `(key, value, pending, delete)` rows as `GET .../pending` returns them.
    type Row<'a> = (&'a str, Option<&'a str>, Option<&'a str>, bool);

    fn ct_conf(rows: &[Row], raw: &[&str]) -> CtConf {
        let pending: Vec<Value> = rows
            .iter()
            .map(|(k, v, p, d)| json!({"key": k, "value": v, "pending": p, "delete": u8::from(*d)}))
            .collect();
        let lxc: Vec<Value> = raw.iter().map(|e| json!(["lxc.mount.entry", e])).collect();
        parse_ct_conf(&json!({"digest": "d1", "lxc": lxc}), &Value::Array(pending)).unwrap()
    }

    struct Fake {
        /// Successive `conf()` answers; the last one repeats.
        confs: Mutex<Vec<CtConf>>,
        running: Result<bool, String>,
        set_err: Option<String>,
        calls: Mutex<Vec<String>>,
    }

    impl Fake {
        fn new(confs: Vec<CtConf>) -> Self {
            Self {
                confs: Mutex::new(confs),
                running: Ok(false),
                set_err: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl GuestMountIo for Fake {
        async fn conf(&self, _vmid: u64) -> Result<CtConf, String> {
            let mut confs = self.confs.lock().unwrap();
            Ok(if confs.len() > 1 {
                confs.remove(0)
            } else {
                confs[0].clone()
            })
        }

        async fn running(&self, _vmid: u64) -> Result<bool, String> {
            self.running.clone()
        }

        async fn set_mps(
            &self,
            _vmid: u64,
            digest: &str,
            set: Option<(&str, &str)>,
            delete: &[String],
        ) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("put {:?}", config_put_pairs(digest, set, delete)));
            self.set_err.clone().map_or(Ok(()), Err)
        }

        async fn set_entry(&self, op: &SetEntryOp) -> Result<RawEdit, String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("set_entry {}", op.entry_line(None)));
            Ok(RawEdit::Written)
        }

        async fn strip_entry(&self, op: &StripEntryOp) -> Result<RawEdit, String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("strip {}", op.target));
            Ok(RawEdit::Written)
        }
    }

    fn spec(fstype: &str, src: &str, target: &str, options: &str) -> GuestMountSpec {
        GuestMountSpec {
            guest: "110".to_string(),
            target: target.to_string(),
            backend: "nfs".to_string(),
            fstype: fstype.to_string(),
            sources: vec![src.to_string()],
            options: options.to_string(),
            credential: None,
        }
    }

    fn bind(fake: &Fake, src: &str, target: &str, ro: bool) -> Result<String, String> {
        rt().block_on(apply_bind(fake, 110, src, target, ro))
    }

    // ── API config ──────────────────────────────────────────────────────────

    #[test]
    fn parse_ct_conf_reads_digest_raw_entries_and_mp_slots() {
        let config = json!({
            "digest": "abc",
            "lxc": [["lxc.mount.entry", "//w/b mnt/b cifs create=dir 0 0"], ["lxc.cgroup2.x", "1"]],
        });
        let pending = json!([
            {"key": "memory", "value": 512},
            {"key": "mp2", "value": "/c,mp=/c"},
            {"key": "mp0", "value": "/a,mp=/a", "delete": 1},
            {"key": "mp1", "pending": "/b,mp=/b"},
        ]);
        let c = parse_ct_conf(&config, &pending).unwrap();
        assert_eq!(c.digest, "abc");
        assert_eq!(c.raw_entries, vec!["//w/b mnt/b cifs create=dir 0 0"]);
        assert_eq!(
            c.mps.iter().map(|s| s.key.as_str()).collect::<Vec<_>>(),
            ["mp0", "mp1", "mp2"]
        );
        assert_eq!(c.mps[0].effective(), None);
        assert!(c.mps[0].is_pending());
        assert_eq!(c.mps[1].effective(), Some("/b,mp=/b"));
        assert!(!c.mps[2].is_pending());
        assert!(c.has_raw_entry("/mnt/b"));
        assert!(!c.has_raw_entry("/mnt"));
        assert!(parse_ct_conf(&json!({}), &json!([])).is_err());
    }

    #[test]
    fn first_free_mp_counts_pending_keys() {
        let c = ct_conf(
            &[
                ("mp0", Some("/a,mp=/a"), None, false),
                ("mp1", None, Some("/b,mp=/b"), false),
            ],
            &[],
        );
        assert_eq!(c.first_free_mp(), Some("mp2".to_string()));
        assert_eq!(ct_conf(&[], &[]).first_free_mp(), Some("mp0".to_string()));
    }

    #[test]
    fn mp_values_compare_field_by_field() {
        assert!(mp_fields_match(
            "/srv/a,backup=0,ro=1,mp=/mnt/a",
            "/srv/a",
            "/mnt/a",
            true
        ));
        assert!(mp_fields_match(
            "volume=/srv/a,mp=/mnt/a,ro=0",
            "/srv/a",
            "/mnt/a",
            false
        ));
        assert!(!mp_fields_match(
            "/srv/a,mp=/mnt/a",
            "/srv/a",
            "/mnt/a",
            true
        ));
        assert!(!mp_fields_match(
            "/srv/b,mp=/mnt/a",
            "/srv/a",
            "/mnt/a",
            false
        ));
        assert!(!mp_fields_match(
            "/srv/a,mp=/mnt/ab",
            "/srv/a",
            "/mnt/a",
            false
        ));
        assert_eq!(
            render_mp_value("/s", "/t", true, &["backup=0"]),
            "/s,mp=/t,ro=1,backup=0"
        );
    }

    // ── bind mounts ─────────────────────────────────────────────────────────

    #[test]
    fn bind_new_takes_first_free_slot_past_pending_ones() {
        let c = ct_conf(&[("mp0", None, Some("/x,mp=/x"), false)], &[]);
        let fake = Fake::new(vec![c.clone(), c]);
        let msg = bind(&fake, "/srv/a", "/mnt/a", false).unwrap();
        assert_eq!(
            fake.calls(),
            [r#"put [("digest", "d1"), ("mp1", "/srv/a,mp=/mnt/a")]"#]
        );
        assert!(msg.starts_with("Set mp1 bind mount /mnt/a"), "{msg}");
    }

    #[test]
    fn bind_reuses_slot_keeps_extras_and_deletes_duplicates() {
        let c = ct_conf(
            &[
                ("mp3", Some("/srv/old,mp=/mnt/b,backup=0"), None, false),
                ("mp5", Some("/srv/dup,mp=/mnt/b"), None, false),
            ],
            &[],
        );
        let fake = Fake::new(vec![c]);
        bind(&fake, "/srv/new", "/mnt/b", true).unwrap();
        assert_eq!(
            fake.calls(),
            [
                r#"put [("digest", "d1"), ("mp3", "/srv/new,mp=/mnt/b,ro=1,backup=0"), ("delete", "mp5")]"#
            ]
        );
    }

    #[test]
    fn bind_matching_with_extras_is_a_no_op() {
        let c = ct_conf(
            &[("mp3", Some("/srv/a,backup=0,mp=/mnt/b"), None, false)],
            &[],
        );
        let fake = Fake::new(vec![c]);
        let msg = bind(&fake, "/srv/a", "/mnt/b", false).unwrap();
        assert!(fake.calls().is_empty());
        assert!(msg.contains("already present as mp3"), "{msg}");
    }

    #[test]
    fn bind_already_pending_reports_pending_without_writing() {
        let c = ct_conf(&[("mp1", None, Some("/srv/a,mp=/mnt/a"), false)], &[]);
        let fake = Fake::new(vec![c]);
        let msg = bind(&fake, "/srv/a", "/mnt/a", false).unwrap();
        assert!(fake.calls().is_empty());
        assert!(msg.starts_with("Pending restart"), "{msg}");
    }

    #[test]
    fn bind_strips_raw_entry_only_after_api_success() {
        let raw = ["/srv/a mnt/a none bind,create=dir 0 0"];
        let mut fake = Fake::new(vec![ct_conf(&[], &raw)]);
        fake.set_err = Some("HTTP 403: Permission check failed".to_string());
        let err = bind(&fake, "/srv/a", "/mnt/a", false).unwrap_err();
        assert!(err.contains("403"), "{err}");
        assert_eq!(fake.calls().len(), 1);
        assert!(fake.calls()[0].starts_with("put"));

        fake.set_err = None;
        fake.calls.lock().unwrap().clear();
        bind(&fake, "/srv/a", "/mnt/a", false).unwrap();
        let calls = fake.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with("put"));
        assert_eq!(calls[1], "strip /mnt/a");
    }

    #[test]
    fn bind_refuses_a_volume_on_the_target() {
        let c = ct_conf(
            &[(
                "mp0",
                Some("local-lvm:vm-110-disk-1,mp=/mnt/a,size=8G"),
                None,
                false,
            )],
            &[],
        );
        let fake = Fake::new(vec![c]);
        let err = bind(&fake, "/srv/a", "/mnt/a", false).unwrap_err();
        assert!(
            err.contains("storage volume local-lvm:vm-110-disk-1"),
            "{err}"
        );
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn root_auth_without_a_password_names_the_secret() {
        for stored in [None, Some(String::new())] {
            let err = require_root_password("pve1", stored).unwrap_err();
            assert!(err.contains("root@pam"), "{err}");
            assert!(err.contains("API tokens"), "{err}");
            assert!(err.contains("'proxmox.pve1.root_password'"), "{err}");
        }
        assert_eq!(
            require_root_password("pve1", Some("pw".to_string())).unwrap(),
            "pw"
        );
    }

    #[test]
    fn config_put_carries_digest_set_and_delete() {
        assert_eq!(
            config_put_pairs("d", Some(("mp1", "/a,mp=/b")), &["mp3".to_string()]),
            [
                ("digest".to_string(), "d".to_string()),
                ("mp1".to_string(), "/a,mp=/b".to_string()),
                ("delete".to_string(), "mp3".to_string()),
            ]
        );
        assert_eq!(config_put_pairs("d", None, &[]).len(), 1);
    }

    #[test]
    fn remove_deletes_binds_then_strips_raw_entry() {
        let before = ct_conf(
            &[
                ("mp0", Some("/srv/a,mp=/mnt/a"), None, false),
                ("mp1", Some("/srv/x,mp=/mnt/x"), None, false),
            ],
            &["//w/a mnt/a cifs create=dir 0 0"],
        );
        let after = ct_conf(&[("mp1", Some("/srv/x,mp=/mnt/x"), None, false)], &[]);
        let fake = Fake::new(vec![before, after]);
        let msg = rt().block_on(remove_with(&fake, 110, "/mnt/a")).unwrap();
        assert_eq!(
            fake.calls(),
            [
                r#"put [("digest", "d1"), ("delete", "mp0")]"#,
                "strip /mnt/a"
            ]
        );
        assert!(msg.starts_with("Removed mp0 bind mount /mnt/a"), "{msg}");

        let fake = Fake::new(vec![ct_conf(&[], &[])]);
        let msg = rt().block_on(remove_with(&fake, 110, "/mnt/a")).unwrap();
        assert!(fake.calls().is_empty());
        assert!(msg.contains("not present"), "{msg}");
    }

    // ── raw entries ─────────────────────────────────────────────────────────

    #[test]
    fn raw_mount_goes_through_the_seam_unless_identical() {
        let s = spec("nfs4", "nas:/export", "/mnt/n", "vers=4.2");
        let line = "nas:/export mnt/n nfs4 vers=4.2,create=dir 0 0";
        let mut fake = Fake::new(vec![ct_conf(&[], &[])]);
        fake.running = Ok(true);
        let msg = rt()
            .block_on(apply_raw(&fake, 110, &s, "nas:/export"))
            .unwrap();
        assert_eq!(fake.calls(), [format!("set_entry lxc.mount.entry: {line}")]);
        assert!(msg.starts_with("Pending restart:"), "{msg}");

        let fake = Fake::new(vec![ct_conf(&[], &[line])]);
        let msg = rt()
            .block_on(apply_raw(&fake, 110, &s, "nas:/export"))
            .unwrap();
        assert!(fake.calls().is_empty());
        assert!(msg.contains("already present"), "{msg}");

        let mut fake = Fake::new(vec![ct_conf(&[], &[])]);
        fake.running = Err("HTTP 500".to_string());
        let msg = rt()
            .block_on(apply_raw(&fake, 110, &s, "nas:/export"))
            .unwrap();
        assert!(msg.starts_with("Pending restart, verify"), "{msg}");
    }

    #[test]
    fn raw_mount_refuses_an_mp_on_the_target() {
        let s = spec("cifs", "//w/a", "/mnt/a", "");
        let fake = Fake::new(vec![ct_conf(
            &[("mp0", Some("/srv/a,mp=/mnt/a"), None, false)],
            &[],
        )]);
        let err = rt()
            .block_on(apply_raw(&fake, 110, &s, "//w/a"))
            .unwrap_err();
        assert!(err.contains("mp0 already mounts"), "{err}");
        assert!(fake.calls().is_empty());
    }

    // ── validation ──────────────────────────────────────────────────────────

    #[test]
    fn classify_routes_binds_and_network_mounts() {
        assert_eq!(
            classify(&spec("bind", "/srv/a", "/mnt/a", "ro")).unwrap(),
            Plan::Bind {
                src: "/srv/a",
                ro: true
            }
        );
        assert_eq!(
            classify(&spec("none", "/srv/a", "/mnt/a", "rw")).unwrap(),
            Plan::Bind {
                src: "/srv/a",
                ro: false
            }
        );
        assert_eq!(
            classify(&spec("cifs", "//w/a", "/mnt/a", "vers=3.1.1")).unwrap(),
            Plan::Raw { fs_spec: "//w/a" }
        );
    }

    #[test]
    fn classify_rejects_injection_and_unsafe_paths() {
        let bad = [
            spec(
                "bind",
                "/srv/a",
                "/mnt/a\nlxc.apparmor.profile: unconfined",
                "",
            ),
            spec("cifs", "//w/a b", "/mnt/a", ""),
            spec("cifs", "//w/a", "/mnt/a", "vers=3 0 0\nx"),
            spec("cifs", "//w/a", "/mnt/a", "a\u{7}"),
            spec("bind", "/srv/a,mp=/etc", "/mnt/a", ""),
            spec("bind", "/srv/a", "/mnt/a,ro=0", ""),
            spec("bind", "/srv/a=b", "/mnt/a", ""),
            spec("bind", "/srv/a", "mnt/a", ""),
            spec("bind", "/srv/a", "/mnt/../etc", ""),
            spec("bind", "/srv/a", "/mnt/./a", ""),
            spec("bind", "/srv/a", "/mnt//a", ""),
            spec("bind", "/srv/a", "/mnt/a/", ""),
            spec("bind", "/srv/a", "/", ""),
            spec("bind", "/srv/../etc", "/mnt/a", ""),
            spec("bind", "srv/a", "/mnt/a", ""),
            spec("rbind", "/srv/a", "/mnt/a", ""),
            spec("bind", "/srv/a", "/mnt/a", "rbind"),
            spec("proc", "proc", "/mnt/a", ""),
            spec("", "/srv/a", "/mnt/a", ""),
        ];
        for s in &bad {
            assert!(
                classify(s).is_err(),
                "accepted {:?} {:?} {:?}",
                s.fstype,
                s.sources,
                s.target
            );
        }
        assert!(
            classify(&GuestMountSpec {
                sources: vec![],
                ..spec("cifs", "", "/mnt/a", "")
            })
            .is_err()
        );
    }

    #[test]
    fn network_mounts_cannot_bind_a_host_path() {
        let bad = [
            spec("nfs", "/", "/mnt/a", "rbind,rw"),
            spec("nfs", "/srv", "/mnt/a", ""),
            spec("nfs", "nas:/srv", "/mnt/a", "bind"),
            spec("nfs", "nas:/srv", "/mnt/a", "rshared"),
            spec("nfs", "nas:/srv", "/mnt/a", "remount,rw"),
            spec("nfs", "nas:/srv/../etc", "/mnt/a", ""),
            spec("nfs", ":/srv", "/mnt/a", ""),
            spec("nfs", "nas:srv", "/mnt/a", ""),
            spec("nfs4", "nas:/srv", "/mnt/a", "create=file"),
            spec("nfs4", "nas:/srv", "/mnt/a", "x-systemd.automount"),
            spec("cifs", "/srv/a", "/mnt/a", ""),
            spec("cifs", "//w", "/mnt/a", ""),
            spec("cifs", "///a", "/mnt/a", ""),
            spec("cifs", "//w/a/../b", "/mnt/a", ""),
            spec("cifs", "//w/a", "/mnt/a", "move"),
            spec("cifs", "//w/a", "/mnt/a", "private"),
            spec("cifs", "//w/a", "/mnt/a", "timeo=5"),
        ];
        for s in &bad {
            assert!(
                classify(s).is_err(),
                "accepted {} {:?} {:?}",
                s.fstype,
                s.sources,
                s.options
            );
        }
        for s in [
            spec(
                "nfs",
                "nas:/",
                "/mnt/a",
                "ro,soft,timeo=50,retrans=3,_netdev,nofail",
            ),
            spec(
                "nfs4",
                "[fe80::1]:/srv/a",
                "/mnt/a",
                "vers=4.2,hard,create=dir",
            ),
            spec(
                "cifs",
                "//w/a/sub",
                "/mnt/a",
                "vers=3.1.1,uid=1000,gid=1000,file_mode=0644,dir_mode=0755,noperm,nobrl,\
                 username=alice,credentials=/x",
            ),
        ] {
            assert!(
                classify(&s).is_ok(),
                "refused {:?} {:?}",
                s.sources,
                s.options
            );
        }
    }

    #[test]
    fn root_side_refuses_a_host_bind_payload() {
        let op = SetEntryOp {
            vmid: 110,
            target: "/mnt/a".to_string(),
            fs_spec: "/".to_string(),
            fstype: "nfs".to_string(),
            options: "rbind,rw".to_string(),
            creds: None,
        };
        assert!(op.validate().is_err());
        let root = pve_root("hostbind", 110, "arch: amd64\n");
        assert!(root_set_entry(&root, &op).is_err());
        assert_eq!(
            std::fs::read_to_string(root.join("etc/pve/lxc/110.conf")).unwrap(),
            "arch: amd64\n"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn root_set_entry_refuses_a_target_an_mp_already_mounts() {
        let conf = "arch: amd64\nmp2: /srv/a,mp=/mnt/a,ro=1\n";
        let root = pve_root("mpclash", 110, conf);
        let mut op = set_op("cifs", "pw");
        op.creds = None;
        let err = root_set_entry(&root, &op).unwrap_err();
        assert!(err.contains("mp2"), "{err}");
        assert_eq!(
            std::fs::read_to_string(root.join("etc/pve/lxc/110.conf")).unwrap(),
            conf
        );
        std::fs::remove_dir_all(&root).ok();
    }

    fn hit(endpoint: &str, node: &str, url_local: bool) -> EndpointHit<()> {
        EndpointHit {
            endpoint: endpoint.to_string(),
            node: node.to_string(),
            url_local,
            cfg: (),
        }
    }

    #[test]
    fn locate_skips_remote_hits_and_prefers_a_local_url() {
        let pick = |hits| pick_endpoint(110, "pve1", hits, &[]).map(|h| h.endpoint);
        assert_eq!(
            pick(vec![
                hit("remote", "pve2", false),
                hit("here", "pve1", false)
            ])
            .unwrap(),
            "here"
        );
        assert_eq!(
            pick(vec![hit("a", "pve1", false), hit("b", "pve1", true)]).unwrap(),
            "b"
        );
        let err = pick(vec![hit("a", "pve1", false), hit("b", "pve1", false)]).unwrap_err();
        assert!(err.contains("'a', 'b'"), "{err}");
        let err = pick(vec![hit("a", "pve1", true), hit("b", "pve1", true)]).unwrap_err();
        assert!(err.contains("disable all but one"), "{err}");
        let err = pick(vec![hit("remote", "pve2", false)]).unwrap_err();
        assert!(err.contains("runs on node 'pve2'"), "{err}");
        let err = pick_endpoint::<()>(110, "pve1", vec![], &["x: down".to_string()])
            .map(|h| h.endpoint)
            .unwrap_err();
        assert!(err.contains("x: down"), "{err}");
    }

    #[test]
    fn root_login_refuses_insecure_tls_and_two_factor() {
        assert!(refuse_insecure_root("pve", false).is_ok());
        let err = refuse_insecure_root("pve", true).unwrap_err();
        assert!(err.contains("insecure"), "{err}");
        let err = root_session("pve", Some("PVE:!tfa!%7B%7D::sig".into()), None).unwrap_err();
        assert!(err.contains("two-factor enabled"), "{err}");
        let err = root_session("pve", Some("PVE:!tfa!x".into()), Some("csrf".into())).unwrap_err();
        assert!(err.contains("two-factor enabled"), "{err}");
        assert_eq!(
            root_session("pve", Some("PVE:root@pam:1".into()), Some("c".into())).unwrap(),
            ("PVE:root@pam:1".to_string(), "c".to_string())
        );
        assert!(root_session("pve", None, None).is_err());
    }

    #[test]
    fn bind_reports_a_pending_duplicate_delete() {
        let before = ct_conf(
            &[
                ("mp3", Some("/srv/a,mp=/mnt/b"), None, false),
                ("mp5", Some("/srv/dup,mp=/mnt/b"), None, false),
            ],
            &[],
        );
        let after = ct_conf(
            &[
                ("mp3", Some("/srv/a,mp=/mnt/b"), None, false),
                ("mp5", Some("/srv/dup,mp=/mnt/b"), None, true),
            ],
            &[],
        );
        let fake = Fake::new(vec![before, after]);
        let msg = bind(&fake, "/srv/a", "/mnt/b", false).unwrap();
        assert!(msg.contains("delete of duplicate mp5"), "{msg}");
    }

    #[test]
    fn shm_resize_is_capped() {
        let op = |size_mb| ShmResizeOp {
            vmid: 120,
            target: "dev/shm".to_string(),
            size_mb,
        };
        assert!(op(SHM_MAX_MB).validate().is_ok());
        assert!(op(SHM_MAX_MB + 1).validate().is_err());
        let root = pve_root(
            "shmcap",
            120,
            "memory: 2048\nlxc.mount.entry: tmpfs dev/shm tmpfs size=1g,mode=1777 0 0\n",
        );
        let err = root_shm_resize(&root, &op(4096)).unwrap_err();
        assert!(err.contains("2048"), "{err}");
        assert_eq!(root_shm_resize(&root, &op(1536)).unwrap(), RawEdit::Written);
        std::fs::remove_dir_all(&root).ok();
    }

    fn set_op(fstype: &str, password: &str) -> SetEntryOp {
        SetEntryOp {
            vmid: 110,
            target: "/mnt/a".to_string(),
            fs_spec: "//w/a".to_string(),
            fstype: fstype.to_string(),
            options: "vers=3.1.1".to_string(),
            creds: Some(CifsCreds {
                username: "alice".to_string(),
                password: password.to_string(),
                domain: None,
            }),
        }
    }

    #[test]
    fn root_side_revalidates_the_payload() {
        assert!(set_op("cifs", "p w").validate().is_ok());
        assert!(set_op("cifs", "pw\nusername=root").validate().is_err());
        assert!(set_op("bind", "pw").validate().is_err());
        let mut op = set_op("cifs", "pw");
        op.target = "/mnt/a\n".to_string();
        assert!(op.validate().is_err());
        let err = root_strip_entry(
            Path::new("/nonexistent"),
            &StripEntryOp {
                vmid: 110,
                target: "../etc".to_string(),
            },
        )
        .unwrap_err();
        assert!(err.contains("not absolute"), "{err}");
    }

    #[test]
    fn parse_vmid_rejects_non_numeric() {
        assert_eq!(parse_vmid("110").unwrap(), 110);
        assert!(parse_vmid("baldur").is_err());
    }

    // ── root-side files ─────────────────────────────────────────────────────

    fn pve_root(name: &str, vmid: u64, conf: &str) -> PathBuf {
        let root = scratch(name);
        std::fs::create_dir_all(root.join("etc/pve/lxc")).unwrap();
        std::fs::write(root.join(format!("etc/pve/lxc/{vmid}.conf")), conf).unwrap();
        root
    }

    fn creds_dir(root: &Path) -> PathBuf {
        let d = under(root, SECRET_FILE_DIR);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn age(path: &Path, by: Duration) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - by)
            .unwrap();
    }

    #[test]
    fn root_set_entry_writes_entry_and_drops_unreferenced_creds() {
        let root = pve_root("set", 110, "arch: amd64\n");
        let creds = creds_dir(&root);
        let mine = under(&root, &guest_creds_path(110, "/mnt/a"));
        std::fs::write(&mine, "x").unwrap();
        let orphan = creds.join("guest-999-mnt-x.secret");
        std::fs::write(&orphan, "x").unwrap();
        age(&orphan, CREDS_ORPHAN_AGE * 2);
        let fresh = creds.join("guest-998-mnt-x.secret");
        std::fs::write(&fresh, "x").unwrap();
        let mut op = set_op("nfs4", "");
        op.creds = None;
        op.fs_spec = "w:/a".to_string();
        op.options = "vers=4.2".to_string();

        assert_eq!(root_set_entry(&root, &op).unwrap(), RawEdit::Written);
        assert_eq!(
            std::fs::read_to_string(root.join("etc/pve/lxc/110.conf")).unwrap(),
            "arch: amd64\nlxc.mount.entry: w:/a mnt/a nfs4 vers=4.2,create=dir 0 0\n"
        );
        assert!(!mine.exists());
        assert!(!orphan.exists());
        assert!(
            fresh.exists(),
            "a fresh unreferenced creds file may be in flight"
        );
        assert_eq!(root_set_entry(&root, &op).unwrap(), RawEdit::Unchanged);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn root_strip_keeps_creds_a_snapshot_still_references() {
        let path = guest_creds_path(110, "/mnt/a");
        let conf = format!(
            "arch: amd64\nlxc.mount.entry: //w/a mnt/a cifs credentials={path},create=dir 0 0\n\
             [snap1]\nlxc.mount.entry: //w/a mnt/a cifs credentials={path},create=dir 0 0\n"
        );
        let root = pve_root("strip", 110, &conf);
        creds_dir(&root);
        std::fs::write(under(&root, &path), "x").unwrap();
        let op = StripEntryOp {
            vmid: 110,
            target: "/mnt/a".to_string(),
        };
        assert_eq!(root_strip_entry(&root, &op).unwrap(), RawEdit::Written);
        assert!(under(&root, &path).exists());

        let conf_path = root.join("etc/pve/lxc/110.conf");
        std::fs::write(&conf_path, "arch: amd64\n").unwrap();
        assert_eq!(root_strip_entry(&root, &op).unwrap(), RawEdit::Unchanged);
        assert!(!under(&root, &path).exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn temp_names_parse_their_pid() {
        assert_eq!(temp_pid(".110.conf.tmp.42.0"), Some(42));
        assert_eq!(temp_pid(".guest-110-mnt-a.secret.tmp.7.3"), Some(7));
        assert_eq!(temp_pid(".hidden"), None);
        assert_eq!(temp_pid("110.conf"), None);
        assert_eq!(temp_pid(".x.tmp.1.2"), None);
        assert_eq!(temp_pid(".110.conf.tmp.x.0"), None);
    }

    #[test]
    fn sweep_removes_dead_or_old_temps_only() {
        let root = pve_root("sweep", 110, "arch: amd64\n");
        let lxc = root.join("etc/pve/lxc");
        let creds = creds_dir(&root);
        let me = std::process::id();
        let files = [
            lxc.join(".110.conf.tmp.1000001.0"),
            lxc.join(".110.conf.tmp.1000002.0"),
            lxc.join(".110.conf.tmp.1000003.0"),
            lxc.join(format!(".110.conf.tmp.{me}.0")),
            lxc.join(".hidden"),
            creds.join(".guest-110-mnt-a.secret.tmp.1000001.1"),
        ];
        for f in &files {
            std::fs::write(f, "x").unwrap();
        }
        age(&files[2], TEMP_STALE_AGE * 2);
        sweep_stale_temps_in(&root, |pid| pid != 1_000_001);
        let left: Vec<bool> = files.iter().map(|f| f.exists()).collect();
        assert_eq!(left, [false, true, false, true, true, false]);
        std::fs::remove_dir_all(&root).ok();
    }

    // ── rendering + conf edits ──────────────────────────────────────────────

    #[test]
    fn relative_mountpoint_strips_leading_slash() {
        assert_eq!(relative_mountpoint("/mnt/backups"), "mnt/backups");
        assert_eq!(relative_mountpoint("mnt/backups"), "mnt/backups");
    }

    #[test]
    fn entry_mountpoint_parses_second_field() {
        let line =
            "lxc.mount.entry: //willow/backups mnt/backups cifs credentials=/x,create=dir 0 0";
        assert_eq!(entry_mountpoint(line), Some("mnt/backups"));
        assert_eq!(entry_mountpoint("memory: 512"), None);
    }

    #[test]
    fn render_entry_drops_inline_creds_and_adds_credentials_and_create() {
        let opts = "vers=3.1.1,uid=1000,username=alice,password=secret,domain=WORK";
        let got = render_entry_options(opts, Some("/etc/orca/secret-files/g.secret"));
        assert!(!got.contains("username="));
        assert!(!got.contains("password="));
        assert!(got.contains("vers=3.1.1"));
        assert!(got.contains("uid=1000"));
        assert!(got.contains("credentials=/etc/orca/secret-files/g.secret"));
        assert!(got.contains("create=dir"));
    }

    #[test]
    fn render_entry_preserves_existing_create_and_omits_credentials_when_none() {
        let got = render_entry_options("vers=4.2,hard,create=dir", None);
        assert!(got.contains("hard"));
        assert!(!got.contains("credentials="));
        assert_eq!(got.matches("create=dir").count(), 1);
    }

    #[test]
    fn upsert_and_strip_touch_only_the_matching_entry() {
        let conf = "arch: amd64\nlxc.mount.entry: //old mnt/b cifs o 0 0\nmemory: 512\n";
        let line = "lxc.mount.entry: //new mnt/b cifs o 0 0";
        let (out, changed) = upsert_entry(conf, "mnt/b", line);
        assert!(changed);
        assert_eq!(out, format!("arch: amd64\n{line}\nmemory: 512\n"));
        assert!(!upsert_entry(&out, "mnt/b", line).1);
        let (stripped, removed) = strip_entry(&out, "mnt/b");
        assert!(removed);
        assert_eq!(stripped, "arch: amd64\nmemory: 512\n");
        assert!(!strip_entry(&stripped, "mnt/b").1);
    }

    #[test]
    fn extract_identity_and_creds_grammar() {
        let (u, d) = extract_identity("vers=3.1.1,username=alice,domain=WORK,password=secret");
        assert_eq!(u.as_deref(), Some("alice"));
        assert_eq!(d.as_deref(), Some("WORK"));
        assert_eq!(
            render_creds_file("alice", "secret", Some("WORK")),
            "username=alice\npassword=secret\ndomain=WORK\n"
        );
    }

    #[test]
    fn guest_creds_path_keys_by_vmid_and_target() {
        assert!(guest_creds_path(110, "/mnt/b").starts_with(SECRET_FILE_DIR));
        assert_ne!(
            guest_creds_path(110, "/mnt/b"),
            guest_creds_path(200, "/mnt/b")
        );
        assert_ne!(
            guest_creds_path(110, "/mnt/a-b"),
            guest_creds_path(110, "/mnt/a/b")
        );
        assert_ne!(
            guest_creds_path(110, "/mnt/a_b"),
            guest_creds_path(110, "/mnt/a/b")
        );
    }

    #[test]
    fn creds_temp_file_is_0600_at_creation() {
        let dir = scratch("creds-mode");
        let (file, _tmp) = create_temp_beside(&dir.join("x.secret"), CREDS_FILE_MODE).unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn atomic_replace_preserves_mode_and_leaves_no_temp() {
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
    fn edit_never_touches_snapshot_sections() {
        let snap = "[snap1]\nlxc.mount.entry: //old mnt/b cifs o 0 0\n";
        let conf = format!("arch: amd64\n{snap}");
        let line = "lxc.mount.entry: //new mnt/b cifs create=dir 0 0";
        let out = edit_live_section(&conf, |c| {
            let (r, changed) = upsert_entry(c, "mnt/b", line);
            changed.then_some(r)
        })
        .unwrap();
        assert_eq!(out, format!("arch: amd64\n{line}\n{snap}"));
    }

    #[test]
    fn edit_raw_conf_waits_on_the_pve_lock_and_refuses_a_vm() {
        let root = pve_root("edit", 110, "arch: amd64\n[pve:pending]\nmemory: 1024\n");
        let upsert = |c: &str| {
            let (r, changed) = upsert_entry(c, "mnt/b", "lxc.mount.entry: //w/b mnt/b cifs o 0 0");
            changed.then_some(r)
        };
        let held = lock_exclusive(
            &root.join("run/lock/lxc/pve-config-110.lock"),
            Duration::ZERO,
        )
        .unwrap();
        let err = edit_raw_conf_in(&root, 110, upsert).unwrap_err();
        assert!(err.contains("config lock"), "{err}");
        drop(held);
        assert_eq!(
            edit_raw_conf_in(&root, 110, upsert).unwrap(),
            RawEdit::Written
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/pve/lxc/110.conf")).unwrap(),
            "arch: amd64\nlxc.mount.entry: //w/b mnt/b cifs o 0 0\n[pve:pending]\nmemory: 1024\n"
        );

        std::fs::create_dir_all(root.join("etc/pve/qemu-server")).unwrap();
        std::fs::write(root.join("etc/pve/qemu-server/200.conf"), "").unwrap();
        let err = edit_raw_conf_in(&root, 200, |_| Some(String::new())).unwrap_err();
        assert!(err.contains("is a VM"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn root_shm_resize_rewrites_the_tmpfs_size_and_validates() {
        let root = pve_root(
            "shm",
            120,
            "arch: amd64\nlxc.mount.entry: tmpfs dev/shm tmpfs size=6g,mode=1777 0 0\n",
        );
        let op = |target: &str, size_mb| ShmResizeOp {
            vmid: 120,
            target: target.to_string(),
            size_mb,
        };
        assert_eq!(
            root_shm_resize(&root, &op("dev/shm", 512)).unwrap(),
            RawEdit::Written
        );
        assert_eq!(
            std::fs::read_to_string(root.join("etc/pve/lxc/120.conf")).unwrap(),
            "arch: amd64\nlxc.mount.entry: tmpfs dev/shm tmpfs size=512m,mode=1777 0 0\n"
        );
        assert_eq!(
            root_shm_resize(&root, &op("dev/shm", 512)).unwrap(),
            RawEdit::Unchanged
        );
        for (target, mb) in [
            ("/dev/shm", 512),
            ("dev/../etc", 512),
            ("dev/shm x", 512),
            ("", 512),
            ("dev/shm", 0),
        ] {
            assert!(root_shm_resize(&root, &op(target, mb)).is_err(), "{target}");
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn raw_edit_detail_round_trips() {
        for e in [RawEdit::Unchanged, RawEdit::Written] {
            assert_eq!(RawEdit::from_detail(e.detail()).unwrap(), e);
        }
        assert!(RawEdit::from_detail("pending").is_err());
    }
}
