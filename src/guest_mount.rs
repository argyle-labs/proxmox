//! `guest_mount` domain — place storage mounts INTO a Proxmox LXC guest.
//!
//! Every guest mount is a PVE `mpN` bind of a host path, set through the PVE
//! REST API:
//!
//! * Host-path binds (`fstype` `bind`/`none`) bind the given path directly.
//! * cifs/nfs shares are staged on the host first: the plugin authors an
//!   ordinary host placement for the same share at
//!   `/mnt/orca-guest/<vmid>/<slug>` in orca's `mounts` table — the record
//!   `storage.mount.create` writes — and orca's mount convergence mounts it
//!   there with the share's own backend (credentials, `addr=`, failover). Once
//!   that placement reports `ok`, the host path is bound into the CT. The CT
//!   stays unprivileged and never sees the share's credentials.
//!
//! Container state — mount points and their pending changes — comes from
//! `config` + `pending`, read with the endpoint's token. Mount points are set
//! with `PUT /nodes/{node}/lxc/{vmid}/config` guarded by the config `digest`.
//! PVE allows a bind `mpN` only to `root@pam` and refuses API tokens
//! (`check_ct_modify_config_perm`), so that call authenticates with a `root@pam`
//! ticket whose password is the orca secret `proxmox.<endpoint>.root_password`.
//! A change PVE cannot hotplug lands in `[pve:pending]` and is reported as
//! pending a restart.
//!
//! VM guests (their own kernel mounts via cloud-init/fstab) are a later phase;
//! this domain handles LXC and returns a clear error for a VM vmid.

use std::net::IpAddr;

use plugin_toolkit::abi::{BackendDef, DbOp, DbRow, DbValue};
use plugin_toolkit::reqwest;
use plugin_toolkit::runtime::{ToDbValue, db_op, field_from_row};
use plugin_toolkit::serde_json::{self, Value};
use plugin_toolkit::storage::{GuestMountSpec, MountHealth, parse_option_string};
use serde::Deserialize;

use crate::Config;

/// Invoke-name prefix for this domain's ops (`proxmox.__guest_mount.*`).
pub const GM_PREFIX: &str = "proxmox.__guest_mount";
const PROVIDER: &str = "proxmox";
/// The only PVE user allowed to set a bind `mpN`.
const ROOT_USER: &str = "root@pam";
/// orca core's settings table and the key holding this host's system id.
const SETTINGS_TABLE: &str = "settings";
const LOCAL_SYSTEM_ID_SETTING: &str = "host.system_id";

/// Kernel network filesystems staged on the host and bound into the CT.
const NETWORK_FSTYPES: &[&str] = &["cifs", "smb3", "smb", "nfs", "nfs4"];
/// Host directory network shares are staged under, per vmid.
const HOST_STAGE_DIR: &str = "/mnt/orca-guest";
/// Longest slug kept verbatim in a staging path; longer ones are hashed.
const MAX_SLUG_LEN: usize = 64;
/// orca core's mount-placement table (`storage.mount.*`).
const MOUNTS_TABLE: &str = "mounts";

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
    /// The spec's host-path source; without it every path bind at `target` is removed.
    #[serde(default)]
    source: Option<String>,
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
                remove(&a.guest, &a.target, a.source.as_deref())
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
    let io = PveIo::locate(vmid)
        .await?
        .ok_or_else(|| format!("guest {vmid}: no enabled proxmox endpoint hosts this LXC"))?;
    apply_with(&io, vmid, spec, plan).await
}

/// Idempotent: a guest no endpoint hosts (destroyed) has nothing mounted to
/// remove.
async fn remove(guest: &str, target: &str, source: Option<&str>) -> Result<String, String> {
    let vmid = parse_vmid(guest)?;
    check_target(target)?;
    let Some(io) = PveIo::locate(vmid).await? else {
        return Ok(not_present(guest, target));
    };
    let msg = match remove_with(&io, vmid, target, source).await {
        Err(e) if ct_missing(&e) => return Ok(not_present(guest, target)),
        r => r?,
    };
    Ok(with_sweep(&io, msg).await)
}

fn not_present(guest: &str, target: &str) -> String {
    format!("guest {guest} not present; no mount at {target} to remove")
}

/// Reconcile the guest's mount for `spec` to present. Idempotent: writes only
/// when the mount (or its host staging placement) diverges.
async fn apply_with<I: GuestMountIo>(
    io: &I,
    vmid: u64,
    spec: &GuestMountSpec,
    plan: Plan<'_>,
) -> Result<String, String> {
    let msg = match plan {
        Plan::Bind { src, ro } => apply_bind(io, vmid, src, &spec.target, ro).await,
        Plan::Staged { ro } => apply_staged(io, vmid, spec, ro).await,
    }?;
    Ok(with_sweep(io, msg).await)
}

/// Append the stale-stage sweep's outcome; a failed sweep never fails the call.
async fn with_sweep<I: GuestMountIo>(io: &I, msg: String) -> String {
    match sweep_stages(io).await {
        Ok(released) if released.is_empty() => msg,
        Ok(released) => format!(
            "{msg} Released stale host staging mount(s) {}.",
            released.join(", ")
        ),
        Err(e) => format!("{msg} Stale staging sweep failed: {e}"),
    }
}

/// Release this host's staging placements for CTs on this node that no
/// enabled guest placement stages and no `mpN` (current or pending) binds.
/// Catches stages a remove kept while a bind delete was pending.
async fn sweep_stages<I: GuestMountIo>(io: &I) -> Result<Vec<String>, String> {
    let local = io.local_host().await?;
    let placements = io.placements().await?;
    let prefix = format!("guest-{}-", io.node());
    let wanted = |vmid: u64, name: &str| {
        placements.iter().any(|g| {
            g.enabled
                && g.host == local
                && g.guest.as_deref().map(str::trim) == Some(vmid.to_string().as_str())
                && stage_name(io.node(), vmid, &g.target) == name
        })
    };
    // Only a CT PVE says is gone from this node frees its stage; any other
    // read failure keeps it, since a bind may still use it.
    let lookup = |vmid: u64| async move {
        match io.conf(vmid).await {
            Ok(c) => Ok(Some(c)),
            Err(e) if ct_missing(&e) => Ok(None),
            Err(_) => Err(()),
        }
    };
    let mut confs: Vec<(u64, Result<Option<CtConf>, ()>)> = Vec::new();
    let mut released = Vec::new();
    for p in &placements {
        if p.guest.is_some() || p.host != local {
            continue;
        }
        let Some(vmid) = p
            .name
            .strip_prefix(&prefix)
            .and_then(|rest| rest.split_once('-'))
            .and_then(|(v, _)| v.parse::<u64>().ok())
        else {
            continue;
        };
        if !p.target.starts_with(&format!("{HOST_STAGE_DIR}/{vmid}/")) || wanted(vmid, &p.name) {
            continue;
        }
        let conf = match confs.iter().find(|(v, _)| *v == vmid) {
            Some((_, c)) => c.clone(),
            None => {
                let c = lookup(vmid).await;
                confs.push((vmid, c.clone()));
                c
            }
        };
        match conf {
            Err(()) => continue,
            Ok(Some(c)) if c.binds_source(&p.target) => continue,
            Ok(_) => {}
        }
        io.delete_placement(&p.id).await?;
        released.push(p.target.clone());
    }
    Ok(released)
}

/// A cifs/nfs share: ensure a host placement for the guest placement's share at
/// the staging path, then bind that path once orca reports it mounted. Binding
/// before the host mount exists would pin the empty directory in the CT.
async fn apply_staged<I: GuestMountIo>(
    io: &I,
    vmid: u64,
    spec: &GuestMountSpec,
    ro: bool,
) -> Result<String, String> {
    let host_path = host_stage_path(vmid, &spec.target);
    let name = stage_name(io.node(), vmid, &spec.target);
    let placements = io.placements().await?;
    let guest_row = placements
        .iter()
        .find(|p| {
            p.enabled
                && p.guest.as_deref().map(str::trim) == Some(spec.guest.trim())
                && p.target == spec.target
        })
        .ok_or_else(|| {
            format!(
                "CT {vmid}: orca has no enabled guest placement for {}; nothing to stage",
                spec.target
            )
        })?;
    let local = io.local_host().await?;
    if guest_row.host != local {
        return Err(format!(
            "CT {vmid}: guest placement for {} targets host '{}', not this orca host '{local}'; \
             the staging mount must land on the host running the CT",
            spec.target, guest_row.host
        ));
    }
    let existing = placements
        .iter()
        .find(|p| p.host == guest_row.host && p.name == name);
    let stage = match existing {
        Some(p) if p.guest.is_some() || p.target != host_path => {
            return Err(format!(
                "host placement '{name}' already exists for {} and is not CT {vmid}'s staging \
                 mount; remove it with storage.mount.delete",
                p.guest.as_deref().unwrap_or(&p.target)
            ));
        }
        Some(p) if p.enabled && p.share_id == guest_row.share_id => p.clone(),
        Some(p) => {
            // The old health describes the previous share or a disabled mount;
            // the bind waits for the next convergence report.
            let fixed = Placement {
                share_id: guest_row.share_id.clone(),
                enabled: true,
                health: MountHealth::Missing,
                ..p.clone()
            };
            io.update_placement(&fixed).await?;
            fixed
        }
        None => {
            if let Some(other) = placements
                .iter()
                .find(|p| p.enabled && p.host == guest_row.host && p.target == host_path)
            {
                return Err(format!(
                    "host placement '{}' already mounts {host_path}; stacking two mounts at one \
                     target is blocked",
                    other.name
                ));
            }
            let p = Placement {
                id: plugin_toolkit::mint_uuidv7(),
                name,
                share_id: guest_row.share_id.clone(),
                host: local,
                target: host_path.clone(),
                guest: None,
                enabled: true,
                health: MountHealth::Missing,
            };
            io.insert_placement(&p).await?;
            p
        }
    };
    if stage.health != MountHealth::Ok {
        return Ok(format!(
            "Staging {} for CT {vmid} at {host_path} on the host (mount health: {}); it is bound \
             into the CT once orca reports that mount ok.",
            spec.target,
            health_label(stage.health)
        ));
    }
    apply_bind(io, vmid, &host_path, &spec.target, ro).await
}

fn health_label(h: MountHealth) -> String {
    serde_json::to_value(h)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{h:?}"))
}

/// A host-path bind as one `mpN`. An existing bind for the target is reused
/// (keeping its other options); duplicates for it are deleted in the same call.
async fn apply_bind<I: GuestMountIo>(
    io: &I,
    vmid: u64,
    src: &str,
    target: &str,
    ro: bool,
) -> Result<String, String> {
    let conf = io.conf(vmid).await?;
    if conf.has_raw_entry(target) {
        return Err(raw_entry_unsupported(vmid, target));
    }
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
    let msg = if pending_deletes.is_empty() {
        msg
    } else {
        format!(
            "{msg} Pending restart: delete of duplicate {} for {target} is held in \
             [pve:pending] until the CT restarts.",
            pending_deletes.join(",")
        )
    };
    Ok(msg)
}

fn raw_entry_unsupported(vmid: u64, target: &str) -> String {
    format!(
        "CT {vmid}: a raw lxc.mount.entry mounts {target}; removing it is unsupported: needs \
         in-guest orca member (the PVE REST API cannot write raw lxc.* keys); remove it by hand"
    )
}

/// Remove the mount at `target` inside the CT. Idempotent: absent ⇒ `Ok`.
/// Deletes the bind `mpN`s on `target` whose source is the staging path or
/// `source` (every path bind there when `source` is `None`), then the host
/// staging placement once no bind of it is left pending.
async fn remove_with<I: GuestMountIo>(
    io: &I,
    vmid: u64,
    target: &str,
    source: Option<&str>,
) -> Result<String, String> {
    let host_path = host_stage_path(vmid, target);
    let source = match source {
        // The share address is not recorded in the bind; the staging path is
        // per-target, so a share matches the staging bind by target alone.
        Some(src) if is_share_addr(src) => {
            check_token("source", src)?;
            Some(host_path.as_str())
        }
        Some(src) => {
            check_abs_path("source", src)?;
            Some(src)
        }
        None => None,
    };
    let mut msgs = Vec::new();
    let conf = io.conf(vmid).await?;
    if conf.has_raw_entry(target) {
        return Err(raw_entry_unsupported(vmid, target));
    }
    let keys: Vec<String> = conf
        .mps_on(target)
        .iter()
        .filter(|s| s.is_bind())
        .filter(|s| {
            let src = s.effective().and_then(|v| parse_mp(v).src);
            src.is_some() && (source.is_none() || src == Some(host_path.as_str()) || src == source)
        })
        .map(|s| s.key.clone())
        .collect();
    let mut bind_pending = false;
    if !keys.is_empty() {
        io.set_mps(vmid, &conf.digest, None, &keys).await?;
        let after = io.conf(vmid).await?;
        let joined = keys.join(",");
        bind_pending = keys.iter().any(|k| after.slot(k).is_some());
        msgs.push(if bind_pending {
            format!(
                "Pending restart: removed {joined} bind mount {target} from CT {vmid}; PVE \
                 holds the delete in [pve:pending] until the CT restarts."
            )
        } else {
            format!("Removed {joined} bind mount {target} from CT {vmid}.")
        });
    }
    let name = stage_name(io.node(), vmid, target);
    let staged: Vec<Placement> = io
        .placements()
        .await?
        .into_iter()
        .filter(|p| p.guest.is_none() && p.name == name && p.target == host_path)
        .collect();
    if !staged.is_empty() {
        if bind_pending {
            msgs.push(format!(
                "Kept host staging mount {host_path} until the CT restarts and releases it."
            ));
        } else {
            for p in &staged {
                io.delete_placement(&p.id).await?;
            }
            msgs.push(format!("Released host staging mount {host_path}."));
        }
    }
    if msgs.is_empty() {
        msgs.push(format!("Guest mount {target} not present on CT {vmid}."));
    }
    Ok(msgs.join(" "))
}

// ── Validation ──────────────────────────────────────────────────────────────

/// How a spec is placed.
#[derive(Debug, PartialEq, Eq)]
enum Plan<'a> {
    Bind { src: &'a str, ro: bool },
    Staged { ro: bool },
}

/// Validate every field of `spec` and pick how it is placed.
fn classify(spec: &GuestMountSpec) -> Result<Plan<'_>, String> {
    check_target(&spec.target)?;
    check_mp_field("target", &spec.target)?;
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
    let ro = opts().any(|o| o.key == "ro" && o.value.is_none_or(truthy));
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
            Ok(Plan::Bind { src, ro })
        }
        t if NETWORK_FSTYPES.contains(&t) => Ok(Plan::Staged { ro }),
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

/// `host:/export` (NFS, `[v6]:/export` allowed) or `//host/share` (SMB).
fn is_share_addr(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix("//") {
        return rest
            .split_once('/')
            .is_some_and(|(host, share)| !host.is_empty() && !share.is_empty());
    }
    let host_end = if s.starts_with('[') {
        s.find("]:").map(|i| i + 1)
    } else {
        s.find(':').filter(|&i| !s[..i].contains('/'))
    };
    host_end.is_some_and(|i| i > 0 && s[i + 1..].starts_with('/'))
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

// ── PVE API + orca placements ───────────────────────────────────────────────

/// The CT state, placements and writes guest mounts need; [`PveIo`] is the
/// real one.
pub(crate) trait GuestMountIo {
    /// The PVE node the CT runs on.
    fn node(&self) -> &str;
    async fn conf(&self, vmid: u64) -> Result<CtConf, String>;
    /// `PUT .../config` with `set`, `delete` and `digest`.
    async fn set_mps(
        &self,
        vmid: u64,
        digest: &str,
        set: Option<(&str, &str)>,
        delete: &[String],
    ) -> Result<(), String>;
    async fn placements(&self) -> Result<Vec<Placement>, String>;
    async fn insert_placement(&self, p: &Placement) -> Result<(), String>;
    async fn update_placement(&self, p: &Placement) -> Result<(), String>;
    async fn delete_placement(&self, id: &str) -> Result<(), String>;
    /// This orca host's system id, the `host` of placements it converges.
    async fn local_host(&self) -> Result<String, String>;
}

/// The columns of an orca `mounts` row guest mounts read or author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Placement {
    id: String,
    name: String,
    share_id: String,
    host: String,
    target: String,
    guest: Option<String>,
    enabled: bool,
    /// Host-local, written by orca's convergence tick; never authored here.
    health: MountHealth,
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

    /// A host-path bind; storage volume ids and `/dev/` device mounts are not.
    fn is_bind(&self) -> bool {
        self.effective()
            .and_then(|v| parse_mp(v).src)
            .is_some_and(|s| s.starts_with('/') && !s.starts_with("/dev/"))
    }

    /// Whether the current or pending value binds `src`.
    fn binds(&self, src: &str) -> bool {
        [self.value.as_deref(), self.pending.as_deref()]
            .into_iter()
            .flatten()
            .any(|v| parse_mp(v).src == Some(src))
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

    fn binds_source(&self, src: &str) -> bool {
        self.mps.iter().any(|s| s.binds(src))
            || self
                .raw_entries
                .iter()
                .any(|e| e.split_whitespace().next().map(|f| f.trim_end_matches('/')) == Some(src))
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
            .any(|e| entry_mountpoint(e) == Some(rel.as_str()))
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

/// The one endpoint to use for a CT on `local`; `None` when every endpoint
/// answered and none has the CT. An endpoint that failed may still host it, so
/// any failure without a hit is an error.
fn pick_endpoint<C>(
    vmid: u64,
    local: &str,
    hits: Vec<EndpointHit<C>>,
    errors: &[String],
) -> Result<Option<EndpointHit<C>>, String> {
    let (mut here, elsewhere): (Vec<_>, Vec<_>) = hits.into_iter().partition(|h| h.node == local);
    if here.len() > 1 && here.iter().any(|h| h.url_local) {
        here.retain(|h| h.url_local);
    }
    match here.len() {
        1 => Ok(Some(here.remove(0))),
        0 if elsewhere.is_empty() && errors.is_empty() => Ok(None),
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

/// Whether `base_url`'s host is an address bound on this machine.
async fn url_is_this_host(base_url: &str) -> bool {
    let Ok(url) = url::Url::parse(base_url) else {
        return false;
    };
    let ips: Vec<IpAddr> = match url.host() {
        Some(url::Host::Ipv4(ip)) => vec![ip.into()],
        Some(url::Host::Ipv6(ip)) => vec![ip.into()],
        Some(url::Host::Domain(d)) => {
            let port = url.port_or_known_default().unwrap_or(443);
            match tokio::net::lookup_host((d, port)).await {
                Ok(addrs) => addrs.map(|a| a.ip()).collect(),
                Err(_) => return false,
            }
        }
        None => return false,
    };
    ips.into_iter().any(ip_is_local)
}

/// An unspecified address (`0.0.0.0`, `::`) binds anywhere, so it says nothing
/// about which host a URL names.
fn ip_is_local(ip: IpAddr) -> bool {
    !ip.is_unspecified() && (ip.is_loopback() || std::net::UdpSocket::bind((ip, 0)).is_ok())
}

/// The API for one CT, on the enabled endpoint whose cluster hosts it.
struct PveIo {
    endpoint: String,
    cfg: Config,
    node: String,
}

impl PveIo {
    /// Find the endpoint that hosts LXC `vmid` on this node: the staging mount
    /// lands on this host. Endpoints that see the CT on another node are
    /// skipped; when several see it here, the one whose URL is this host wins.
    async fn locate(vmid: u64) -> Result<Option<Self>, String> {
        let local = crate::diagnostics::local_node();
        let names = crate::tools::enabled_endpoint_names();
        if names.is_empty() {
            return Err(format!("guest {vmid}: no enabled proxmox endpoint"));
        }
        let mut hits = Vec::new();
        let mut errors = Vec::new();
        for name in names {
            let found = async {
                let cfg = crate::tools::resolve_config(&name).await?;
                let ct = crate::lxc_guest::find_ct_opt(&name, vmid)?;
                Ok::<_, plugin_toolkit::anyhow::Error>((cfg, ct))
            }
            .await;
            match found {
                Ok((_, None)) => {}
                Ok((cfg, Some(ct))) => hits.push(EndpointHit {
                    url_local: url_is_this_host(&cfg.base_url).await,
                    endpoint: name,
                    node: ct.node,
                    cfg,
                }),
                Err(e) => errors.push(format!("{name}: {e:#}")),
            }
        }
        Ok(pick_endpoint(vmid, &local, hits, &errors)?.map(|hit| Self {
            endpoint: hit.endpoint,
            cfg: hit.cfg,
            node: hit.node,
        }))
    }

    fn ct_url(&self, vmid: u64) -> String {
        format!(
            "{}/nodes/{}/lxc/{vmid}",
            self.cfg.base_url.trim_end_matches('/'),
            plugin_toolkit::progenitor_client::encode_path(&self.node)
        )
    }

    async fn root_client(&self) -> Result<reqwest::Client, String> {
        root_client(&self.endpoint, &self.cfg).await
    }
}

/// A client carrying a fresh `root@pam` ticket and its CSRF token.
pub(crate) async fn root_client(endpoint: &str, cfg: &Config) -> Result<reqwest::Client, String> {
    refuse_insecure_root(endpoint, cfg.insecure)?;
    let name = root_password_secret(endpoint)?;
    let stored = plugin_toolkit::secrets::get(&name)
        .map_err(|e| format!("read secret '{name}': {e:#}"))?
        .map(|s| s.expose_secret().clone());
    let password = require_root_password(endpoint, stored)?;
    let anon = plugin_toolkit::api_client::ApiClientBuilder::new()
        .build()
        .map_err(|e| format!("http client: {e:#}"))?;
    let url = format!("{}/access/ticket", cfg.base_url.trim_end_matches('/'));
    let ticket = crate::backup::post_form_data(
        &anon,
        &url,
        &[
            ("username".to_string(), ROOT_USER.to_string()),
            ("password".to_string(), password),
        ],
    )
    .await
    .map_err(|e| format!("{ROOT_USER} login on endpoint '{}': {e:#}", endpoint))?;
    let field = |k: &str| ticket.get(k).and_then(Value::as_str).map(String::from);
    let (ticket, csrf) = root_session(endpoint, field("ticket"), field("CSRFPreventionToken"))?;
    plugin_toolkit::api_client::ApiClientBuilder::new()
        .header("cookie", format!("PVEAuthCookie={ticket}"))
        .and_then(|b| b.header("csrfpreventiontoken", csrf))
        .and_then(|b| b.build())
        .map_err(|e| format!("http client: {e:#}"))
}

impl GuestMountIo for PveIo {
    fn node(&self) -> &str {
        &self.node
    }

    async fn conf(&self, vmid: u64) -> Result<CtConf, String> {
        let http = self.cfg.build_reqwest_client().map_err(|e| e.to_string())?;
        let base = self.ct_url(vmid);
        let config = get_data(&http, &format!("{base}/config")).await?;
        let pending = get_data(&http, &format!("{base}/pending")).await?;
        parse_ct_conf(&config, &pending)
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

    async fn placements(&self) -> Result<Vec<Placement>, String> {
        placement_db::list().map_err(|e| format!("read orca mounts: {e:#}"))
    }

    async fn insert_placement(&self, p: &Placement) -> Result<(), String> {
        placement_db::insert(p).map_err(|e| format!("author host placement {}: {e:#}", p.target))
    }

    async fn update_placement(&self, p: &Placement) -> Result<(), String> {
        placement_db::update(p).map_err(|e| format!("update host placement {}: {e:#}", p.target))
    }

    async fn delete_placement(&self, id: &str) -> Result<(), String> {
        placement_db::remove(id).map_err(|e| format!("delete host placement {id}: {e:#}"))
    }

    async fn local_host(&self) -> Result<String, String> {
        placement_db::local_host_id().map_err(|e| format!("read orca host id: {e:#}"))
    }
}

/// orca core's `mounts` table over `db_op`, mirroring the row `storage.mount`
/// writes. Only config columns are written; `health` and the other per-tick
/// columns keep their defaults and belong to the convergence loop.
///
/// Plugins have no plugin→core tool call yet, so rows are written directly;
/// this moves to `tool.call storage.mount.*` with orca #794.
mod placement_db {
    use super::*;
    use plugin_toolkit::anyhow::Result;

    fn to_dbrow(p: &Placement) -> DbRow {
        let mut m = DbRow::new();
        m.insert("id".to_string(), DbValue::Text(p.id.clone()));
        m.insert("name".to_string(), DbValue::Text(p.name.clone()));
        m.insert("share_id".to_string(), DbValue::Text(p.share_id.clone()));
        m.insert("host".to_string(), DbValue::Text(p.host.clone()));
        m.insert("target".to_string(), DbValue::Text(p.target.clone()));
        m.insert("guest".to_string(), ToDbValue::to_dbvalue(&p.guest));
        m.insert("enabled".to_string(), DbValue::Bool(p.enabled));
        m.insert(
            "updated_at".to_string(),
            DbValue::Int(plugin_toolkit::now_millis_since_epoch()),
        );
        m
    }

    fn from_dbrow(m: &DbRow) -> Result<Placement> {
        let health: Option<String> = field_from_row(m, "health")?;
        Ok(Placement {
            id: field_from_row(m, "id")?,
            name: field_from_row(m, "name")?,
            share_id: field_from_row(m, "share_id")?,
            host: field_from_row(m, "host")?,
            target: field_from_row(m, "target")?,
            guest: field_from_row::<Option<String>>(m, "guest")?.filter(|g| !g.trim().is_empty()),
            enabled: field_from_row(m, "enabled")?,
            health: health
                .and_then(|h| serde_json::from_value(Value::String(h)).ok())
                .unwrap_or(MountHealth::Missing),
        })
    }

    pub(super) fn list() -> Result<Vec<Placement>> {
        let reply = db_op(&DbOp::List {
            namespace: String::new(),
            table: MOUNTS_TABLE.to_string(),
        })?;
        reply.rows.iter().map(from_dbrow).collect()
    }

    pub(super) fn local_host_id() -> Result<String> {
        let reply = db_op(&DbOp::List {
            namespace: String::new(),
            table: SETTINGS_TABLE.to_string(),
        })?;
        for row in &reply.rows {
            let key: String = field_from_row(row, "key")?;
            if key == LOCAL_SYSTEM_ID_SETTING {
                let id: String = field_from_row(row, "value")?;
                if !id.trim().is_empty() {
                    return Ok(id);
                }
            }
        }
        plugin_toolkit::anyhow::bail!("setting '{LOCAL_SYSTEM_ID_SETTING}' is not set")
    }

    pub(super) fn insert(p: &Placement) -> Result<()> {
        db_op(&DbOp::Insert {
            namespace: String::new(),
            table: MOUNTS_TABLE.to_string(),
            row: to_dbrow(p),
        })?;
        Ok(())
    }

    pub(super) fn update(p: &Placement) -> Result<()> {
        db_op(&DbOp::Update {
            namespace: String::new(),
            table: MOUNTS_TABLE.to_string(),
            key_col: "id".to_string(),
            row: to_dbrow(p),
        })?;
        Ok(())
    }

    pub(super) fn remove(id: &str) -> Result<()> {
        db_op(&DbOp::Delete {
            namespace: String::new(),
            table: MOUNTS_TABLE.to_string(),
            key_col: "id".to_string(),
            key: id.to_string(),
        })?;
        Ok(())
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
pub(crate) fn root_password_secret(endpoint: &str) -> Result<String, String> {
    plugin_toolkit::secrets::scoped_name(PROVIDER, endpoint, "root_password")
        .map(|r| r.to_string())
        .map_err(|e| format!("{e:#}"))
}

fn require_root_password(endpoint: &str, stored: Option<String>) -> Result<String, String> {
    stored.filter(|p| !p.is_empty()).ok_or_else(|| {
        format!(
            "bind mount points need a {ROOT_USER} ticket: PVE refuses bind mpN to API tokens. \
             Store the {ROOT_USER} password for endpoint '{endpoint}' as the orca secret '{}'.",
            root_password_secret(endpoint).unwrap_or_else(|e| e)
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

/// Whether a [`get_data`] error is PVE saying the CT does not exist: 404, or
/// the 500 its config loader answers for a missing vmid.
fn ct_missing(err: &str) -> bool {
    err.contains(": HTTP 404:") || (err.contains(": HTTP 500:") && err.contains("does not exist"))
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

// ── Node-local paths ────────────────────────────────────────────────────────

/// Host path a CT's network share is staged at: `/mnt/orca-guest/<vmid>/<slug>`.
fn host_stage_path(vmid: u64, target: &str) -> String {
    format!("{HOST_STAGE_DIR}/{vmid}/{}", stage_slug(target))
}

/// Name of the host placement staging `target` for CT `vmid` on `node`. The
/// node keeps CTs of separate clusters that share a vmid apart.
fn stage_name(node: &str, vmid: u64, target: &str) -> String {
    format!("guest-{node}-{vmid}-{}", stage_slug(target))
}

/// [`slug`], capped at [`MAX_SLUG_LEN`]: a longer one keeps its prefix and ends
/// in a hash of the full target, so distinct targets stay distinct.
fn stage_slug(target: &str) -> String {
    let s = slug(target);
    if s.len() <= MAX_SLUG_LEN {
        return s;
    }
    let hash = plugin_toolkit::hash::sha256_hex(target.as_bytes());
    format!("{}-{}", &s[..MAX_SLUG_LEN - 17], &hash[..16])
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

/// Strip the leading `/` from an absolute guest mountpoint — an
/// `lxc.mount.entry` mountpoint is relative to the guest rootfs.
fn relative_mountpoint(target: &str) -> String {
    target.trim_start_matches('/').to_string()
}

/// An `lxc.mount.entry`'s mountpoint field, normalized: lxc resolves it
/// against the rootfs, so `./mnt/a`, `/mnt/a` and `mnt/a/` all name `mnt/a`.
fn entry_mountpoint(entry: &str) -> Option<&str> {
    let mut mp = entry.split_whitespace().nth(1)?;
    loop {
        let next = mp.trim_start_matches('/');
        let next = next.strip_prefix("./").unwrap_or(next);
        if next == mp {
            break;
        }
        mp = next;
    }
    Some(mp.trim_end_matches('/'))
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
        placements: Mutex<Vec<Placement>>,
        set_err: Option<String>,
        conf_err: Option<String>,
        calls: Mutex<Vec<String>>,
    }

    impl Fake {
        fn new(confs: Vec<CtConf>) -> Self {
            Self {
                confs: Mutex::new(confs),
                placements: Mutex::new(Vec::new()),
                set_err: None,
                conf_err: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_placements(mut self, rows: Vec<Placement>) -> Self {
            self.placements = Mutex::new(rows);
            self
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn rows(&self) -> Vec<Placement> {
            self.placements.lock().unwrap().clone()
        }

        fn log(&self, s: String) {
            self.calls.lock().unwrap().push(s);
        }
    }

    impl GuestMountIo for Fake {
        fn node(&self) -> &str {
            "pve1"
        }

        async fn conf(&self, _vmid: u64) -> Result<CtConf, String> {
            if let Some(e) = &self.conf_err {
                return Err(e.clone());
            }
            let mut confs = self.confs.lock().unwrap();
            Ok(if confs.len() > 1 {
                confs.remove(0)
            } else {
                confs[0].clone()
            })
        }

        async fn set_mps(
            &self,
            _vmid: u64,
            digest: &str,
            set: Option<(&str, &str)>,
            delete: &[String],
        ) -> Result<(), String> {
            self.log(format!("put {:?}", config_put_pairs(digest, set, delete)));
            self.set_err.clone().map_or(Ok(()), Err)
        }

        async fn placements(&self) -> Result<Vec<Placement>, String> {
            Ok(self.rows())
        }

        async fn insert_placement(&self, p: &Placement) -> Result<(), String> {
            self.log(format!("insert {} {} {}", p.name, p.target, p.share_id));
            self.placements.lock().unwrap().push(p.clone());
            Ok(())
        }

        async fn update_placement(&self, p: &Placement) -> Result<(), String> {
            self.log(format!("update {} {} {}", p.id, p.share_id, p.enabled));
            for r in self.placements.lock().unwrap().iter_mut() {
                if r.id == p.id {
                    *r = p.clone();
                }
            }
            Ok(())
        }

        async fn delete_placement(&self, id: &str) -> Result<(), String> {
            self.log(format!("delete {id}"));
            self.placements.lock().unwrap().retain(|r| r.id != id);
            Ok(())
        }

        async fn local_host(&self) -> Result<String, String> {
            Ok("host-a".to_string())
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

    fn placement(id: &str, name: &str, target: &str, guest: Option<&str>) -> Placement {
        Placement {
            id: id.to_string(),
            name: name.to_string(),
            share_id: "share-1".to_string(),
            host: "host-a".to_string(),
            target: target.to_string(),
            guest: guest.map(str::to_string),
            enabled: true,
            health: MountHealth::Missing,
        }
    }

    fn guest_row() -> Placement {
        placement("g1", "media", "/mnt/media", Some("110"))
    }

    fn staged(fake: &Fake, options: &str) -> Result<String, String> {
        let s = spec("nfs4", "nas:/media", "/mnt/media", options);
        let plan = classify(&s).unwrap();
        rt().block_on(apply_with(fake, 110, &s, plan))
    }

    const STAGE_PATH: &str = "/mnt/orca-guest/110/mnt_2fmedia";
    const STAGE_NAME: &str = "guest-pve1-110-mnt_2fmedia";

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
    fn bind_refuses_a_raw_entry_and_surfaces_api_errors() {
        let raw = ["//w/a mnt/a cifs create=dir 0 0"];
        let fake = Fake::new(vec![ct_conf(&[], &raw), ct_conf(&[], &[])]);
        let err = bind(&fake, "/srv/a", "/mnt/a", false).unwrap_err();
        assert!(
            err.contains("unsupported: needs in-guest orca member"),
            "{err}"
        );
        assert!(fake.calls().is_empty());

        let mut fake = Fake::new(vec![ct_conf(&[], &[])]);
        fake.set_err = Some("HTTP 403: Permission check failed".to_string());
        let err = bind(&fake, "/srv/a", "/mnt/a", false).unwrap_err();
        assert!(err.contains("403"), "{err}");
        assert_eq!(fake.calls().len(), 1);
    }

    #[test]
    fn device_and_volume_slots_are_not_binds() {
        let c = ct_conf(
            &[
                ("mp0", Some("/dev/sdb1,mp=/mnt/a"), None, false),
                (
                    "mp1",
                    Some("local-lvm:vm-110-disk-1,mp=/mnt/b"),
                    None,
                    false,
                ),
                ("mp2", Some("/srv/c,mp=/mnt/c"), None, false),
            ],
            &[],
        );
        assert!(!c.mps[0].is_bind());
        assert!(!c.mps[1].is_bind());
        assert!(c.mps[2].is_bind());

        let fake = Fake::new(vec![c]);
        let err = bind(&fake, "/srv/a", "/mnt/a", false).unwrap_err();
        assert!(err.contains("/dev/sdb1"), "{err}");
        assert!(fake.calls().is_empty());
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

    // ── staged network shares ───────────────────────────────────────────────

    #[test]
    fn staged_first_apply_authors_a_host_placement_and_waits_for_it() {
        let fake = Fake::new(vec![ct_conf(&[], &[])]).with_placements(vec![guest_row()]);
        let msg = staged(&fake, "vers=4.2").unwrap();
        assert_eq!(
            fake.calls(),
            [format!("insert {STAGE_NAME} {STAGE_PATH} share-1")]
        );
        let stage = fake
            .rows()
            .into_iter()
            .find(|p| p.target == STAGE_PATH)
            .unwrap();
        assert_eq!(stage.host, "host-a");
        assert_eq!(stage.guest, None);
        assert!(stage.enabled);
        assert!(plugin_toolkit::id::is_valid(&stage.id), "{}", stage.id);
        assert!(msg.starts_with("Staging /mnt/media"), "{msg}");
        assert!(msg.contains("missing"), "{msg}");

        fake.calls.lock().unwrap().clear();
        staged(&fake, "vers=4.2").unwrap();
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    }

    #[test]
    fn staged_binds_the_host_path_once_orca_reports_it_ok() {
        let mut stage = placement("s1", STAGE_NAME, STAGE_PATH, None);
        stage.health = MountHealth::Ok;
        let fake = Fake::new(vec![ct_conf(&[], &[])]).with_placements(vec![guest_row(), stage]);
        let msg = staged(&fake, "ro,vers=4.2").unwrap();
        assert_eq!(
            fake.calls(),
            [format!(
                r#"put [("digest", "d1"), ("mp0", "{STAGE_PATH},mp=/mnt/media,ro=1")]"#
            )]
        );
        assert!(msg.starts_with("Set mp0 bind mount /mnt/media"), "{msg}");
    }

    #[test]
    fn staged_repairs_a_disabled_or_repointed_stage() {
        let mut stage = placement("s1", STAGE_NAME, STAGE_PATH, None);
        stage.enabled = false;
        stage.share_id = "share-old".to_string();
        stage.health = MountHealth::Ok;
        let fake = Fake::new(vec![ct_conf(&[], &[])]).with_placements(vec![guest_row(), stage]);
        let msg = staged(&fake, "").unwrap();
        assert_eq!(fake.calls(), ["update s1 share-1 true"]);
        assert!(msg.starts_with("Staging /mnt/media"), "{msg}");
        assert!(msg.contains("missing"), "{msg}");
    }

    #[test]
    fn staged_refuses_a_guest_placement_for_another_host() {
        let mut row = guest_row();
        row.host = "host-b".to_string();
        let fake = Fake::new(vec![ct_conf(&[], &[])]).with_placements(vec![row]);
        let err = staged(&fake, "").unwrap_err();
        assert!(
            err.contains("'host-b', not this orca host 'host-a'"),
            "{err}"
        );
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn sweep_releases_only_unreferenced_stages_of_this_host() {
        let stage = |id: &str, t: &str| {
            placement(
                id,
                &stage_name("pve1", 110, t),
                &host_stage_path(110, t),
                None,
            )
        };
        let referenced = host_stage_path(110, "/mnt/held");
        let mut foreign = stage("f1", "/mnt/foreign");
        foreign.host = "host-b".to_string();
        let mut other_node = stage("n1", "/mnt/other");
        other_node.name = stage_name("pve2", 110, "/mnt/other");
        let fake = Fake::new(vec![ct_conf(
            &[(
                "mp0",
                Some(format!("{referenced},mp=/mnt/held").as_str()),
                None,
                true,
            )],
            &[],
        )])
        .with_placements(vec![
            guest_row(),
            stage("s1", "/mnt/media"),
            stage("s2", "/mnt/gone"),
            stage("s3", "/mnt/held"),
            foreign,
            other_node,
        ]);
        let released = rt().block_on(sweep_stages(&fake)).unwrap();
        assert_eq!(released, [host_stage_path(110, "/mnt/gone")]);
        assert_eq!(fake.calls(), ["delete s2"]);
    }

    #[test]
    fn remove_refuses_a_raw_entry() {
        let before = ct_conf(
            &[
                (
                    "mp0",
                    Some(format!("{STAGE_PATH},mp=/mnt/media").as_str()),
                    None,
                    false,
                ),
                ("mp1", Some("/srv/other,mp=/mnt/media"), None, false),
                ("mp2", Some("/srv/mine,mp=/mnt/media"), None, false),
            ],
            &["//w/m mnt/media cifs create=dir 0 0"],
        );
        let fake = Fake::new(vec![before]);
        let err = rt()
            .block_on(remove_with(&fake, 110, "/mnt/media", Some("/srv/mine")))
            .unwrap_err();
        assert!(
            err.contains("unsupported: needs in-guest orca member"),
            "{err}"
        );
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn remove_without_source_deletes_every_path_bind_at_the_target() {
        let c = ct_conf(
            &[
                (
                    "mp0",
                    Some(format!("{STAGE_PATH},mp=/mnt/media").as_str()),
                    None,
                    false,
                ),
                ("mp1", Some("/srv/other,mp=/mnt/media"), None, false),
                (
                    "mp2",
                    Some("local-lvm:vm-110-disk-1,mp=/mnt/media"),
                    None,
                    false,
                ),
            ],
            &[],
        );
        let fake = Fake::new(vec![c, ct_conf(&[], &[])]);
        let msg = rt()
            .block_on(remove_with(&fake, 110, "/mnt/media", None))
            .unwrap();
        assert_eq!(
            fake.calls(),
            [r#"put [("digest", "d1"), ("delete", "mp0,mp1")]"#]
        );
        assert!(!msg.contains("not present"), "{msg}");

        for bad in ["srv/x", "/srv/../etc", "/srv/x/"] {
            let fake = Fake::new(vec![ct_conf(&[], &[])]);
            assert!(
                rt().block_on(remove_with(&fake, 110, "/mnt/media", Some(bad)))
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn raw_entry_forms_match() {
        for e in [
            "//w/a mnt/a cifs 0 0",
            "//w/a ./mnt/a cifs 0 0",
            "//w/a /mnt/a/ cifs 0 0",
            "  //w/a .//mnt/a cifs 0 0",
        ] {
            assert!(ct_conf(&[], &[e]).has_raw_entry("/mnt/a"), "{e}");
        }
        assert!(!ct_conf(&[], &["//w/a mnt/ab cifs 0 0"]).has_raw_entry("/mnt/a"));
    }

    #[test]
    fn sweep_releases_a_stage_only_when_its_ct_is_gone() {
        let rows = || {
            vec![placement(
                "s1",
                &stage_name("pve1", 110, "/mnt/x"),
                &host_stage_path(110, "/mnt/x"),
                None,
            )]
        };
        let sweep = |err: &str| {
            let mut fake = Fake::new(vec![ct_conf(&[], &[])]).with_placements(rows());
            fake.conf_err = Some(err.to_string());
            rt().block_on(sweep_stages(&fake)).unwrap()
        };
        assert_eq!(
            sweep("GET u: HTTP 500: Configuration file 'nodes/pve1/lxc/110.conf' does not exist"),
            [host_stage_path(110, "/mnt/x")]
        );
        assert_eq!(
            sweep("GET u: HTTP 404: no such"),
            [host_stage_path(110, "/mnt/x")]
        );
        assert!(sweep("GET u: HTTP 401: no ticket").is_empty());
        assert!(sweep("GET u: HTTP 500: proxy timeout").is_empty());
        assert!(sweep("GET u: error sending request").is_empty());
    }

    #[test]
    fn sweep_counts_a_raw_entry_on_the_stage_as_a_reference() {
        let path = host_stage_path(110, "/mnt/x");
        let rows = vec![placement(
            "s1",
            &stage_name("pve1", 110, "/mnt/x"),
            &path,
            None,
        )];
        let entry = format!("{path} mnt/x none bind 0 0");
        let fake = Fake::new(vec![ct_conf(&[], &[entry.as_str()])]).with_placements(rows);
        assert!(rt().block_on(sweep_stages(&fake)).unwrap().is_empty());
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn staged_refuses_without_a_guest_placement_or_over_another_mount() {
        let fake = Fake::new(vec![ct_conf(&[], &[])]);
        let err = staged(&fake, "").unwrap_err();
        assert!(err.contains("no enabled guest placement"), "{err}");

        let other = placement("o1", "nas-media", STAGE_PATH, None);
        let fake = Fake::new(vec![ct_conf(&[], &[])]).with_placements(vec![guest_row(), other]);
        let err = staged(&fake, "").unwrap_err();
        assert!(err.contains("'nas-media' already mounts"), "{err}");
        assert!(fake.calls().is_empty());

        let clash = placement("c1", STAGE_NAME, "/srv/elsewhere", None);
        let fake = Fake::new(vec![ct_conf(&[], &[])]).with_placements(vec![guest_row(), clash]);
        let err = staged(&fake, "").unwrap_err();
        assert!(err.contains("not CT 110's staging mount"), "{err}");
        assert!(fake.calls().is_empty());
    }

    #[test]
    fn remove_deletes_binds_then_releases_the_stage() {
        let before = ct_conf(
            &[
                (
                    "mp0",
                    Some(format!("{STAGE_PATH},mp=/mnt/media").as_str()),
                    None,
                    false,
                ),
                ("mp1", Some("/srv/x,mp=/mnt/x"), None, false),
            ],
            &[],
        );
        let after = ct_conf(&[("mp1", Some("/srv/x,mp=/mnt/x"), None, false)], &[]);
        let fake = Fake::new(vec![before, after]).with_placements(vec![
            guest_row(),
            placement("s1", STAGE_NAME, STAGE_PATH, None),
        ]);
        let msg = rt()
            .block_on(remove_with(&fake, 110, "/mnt/media", None))
            .unwrap();
        assert_eq!(
            fake.calls(),
            [r#"put [("digest", "d1"), ("delete", "mp0")]"#, "delete s1"]
        );
        assert!(
            msg.starts_with("Removed mp0 bind mount /mnt/media"),
            "{msg}"
        );
        assert!(msg.contains("Released host staging mount"), "{msg}");

        let fake = Fake::new(vec![ct_conf(&[], &[])]);
        let msg = rt()
            .block_on(remove_with(&fake, 110, "/mnt/a", None))
            .unwrap();
        assert!(fake.calls().is_empty());
        assert!(msg.contains("not present"), "{msg}");
    }

    #[test]
    fn remove_keeps_the_stage_while_the_bind_delete_is_pending() {
        let value = format!("{STAGE_PATH},mp=/mnt/media");
        let before = ct_conf(&[("mp0", Some(value.as_str()), None, false)], &[]);
        let after = ct_conf(&[("mp0", Some(value.as_str()), None, true)], &[]);
        let fake = Fake::new(vec![before, after])
            .with_placements(vec![placement("s1", STAGE_NAME, STAGE_PATH, None)]);
        let msg = rt()
            .block_on(remove_with(&fake, 110, "/mnt/media", None))
            .unwrap();
        assert_eq!(fake.calls().len(), 1);
        assert_eq!(fake.rows().len(), 1);
        assert!(msg.contains("Kept host staging mount"), "{msg}");
    }

    #[test]
    fn stage_paths_are_deterministic_distinct_and_bounded() {
        assert_eq!(host_stage_path(110, "/mnt/media"), STAGE_PATH);
        assert_ne!(
            host_stage_path(110, "/mnt/a-b"),
            host_stage_path(110, "/mnt/a/b")
        );
        assert_ne!(
            host_stage_path(110, "/mnt/b"),
            host_stage_path(200, "/mnt/b")
        );
        let long_a = format!("/{}", "a/".repeat(60) + "x");
        let long_b = format!("/{}", "a/".repeat(60) + "y");
        let (sa, sb) = (stage_slug(&long_a), stage_slug(&long_b));
        assert_eq!(sa.len(), MAX_SLUG_LEN);
        assert_ne!(sa, sb);
        assert_eq!(sa, stage_slug(&long_a));
        assert_eq!(stage_slug("/mnt/media"), "mnt_2fmedia");
    }

    // ── validation ──────────────────────────────────────────────────────────

    #[test]
    fn classify_routes_binds_and_network_shares() {
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
            classify(&spec("cifs", "//w/a", "/mnt/a", "vers=3.1.1,ro=1")).unwrap(),
            Plan::Staged { ro: true }
        );
        assert_eq!(
            classify(&spec("nfs4", "nas:/a", "/mnt/a", "")).unwrap(),
            Plan::Staged { ro: false }
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
            spec("cifs", "//w/a", "/mnt/a,ro=0", ""),
            spec("nfs", "nas:/a", "/mnt/../etc", ""),
            spec("bind", "/srv/a,mp=/etc", "/mnt/a", ""),
            spec("bind", "/srv/a", "/mnt/a,ro=0", ""),
            spec("bind", "/srv/a=b", "/mnt/a", ""),
            spec("bind", "/srv/a", "mnt/a", ""),
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
        let pick = |hits| pick_endpoint(110, "pve1", hits, &[]).map(|h| h.unwrap().endpoint);
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
            .map(|h| h.is_some())
            .unwrap_err();
        assert!(err.contains("x: down"), "{err}");
    }

    #[test]
    fn pick_endpoint_reports_absent_only_when_every_endpoint_answered() {
        assert!(
            pick_endpoint::<()>(110, "pve1", vec![], &[])
                .unwrap()
                .is_none()
        );
        let err = pick_endpoint::<()>(110, "pve1", vec![], &["x: HTTP 401".to_string()])
            .map(|h| h.is_some())
            .unwrap_err();
        assert!(err.contains("HTTP 401"), "{err}");
        let err = pick_endpoint(110, "pve1", vec![hit("remote", "pve2", false)], &[])
            .map(|h| h.is_some())
            .unwrap_err();
        assert!(err.contains("orca instance on 'pve2'"), "{err}");
    }

    #[test]
    fn remove_of_a_non_numeric_guest_is_an_error() {
        let err = rt()
            .block_on(remove("my-host", "/mnt/media", None))
            .unwrap_err();
        assert!(err.contains("not a numeric LXC vmid"), "{err}");
    }

    #[test]
    fn ct_missing_matches_get_data_errors() {
        let url = "https://pve:8006/api2/json/nodes/pve1/lxc/110/config";
        assert!(ct_missing(&format!(
            "GET {url}: HTTP 404: {{\"data\":null}}"
        )));
        assert!(ct_missing(&format!(
            "GET {url}: HTTP 500: {{\"data\":null,\"message\":\"Configuration file 'nodes/pve1/lxc/110.conf' does not exist\\n\"}}"
        )));
        assert!(!ct_missing(&format!(
            "GET {url}: HTTP 500: {{\"data\":null}}"
        )));
        assert!(!ct_missing(&format!("GET {url}: HTTP 403: does not exist")));
    }

    #[test]
    fn remove_with_a_share_source_matches_the_staging_bind() {
        let c = ct_conf(
            &[
                (
                    "mp0",
                    Some(format!("{STAGE_PATH},mp=/mnt/media").as_str()),
                    None,
                    false,
                ),
                ("mp1", Some("/srv/mine,mp=/mnt/media"), None, false),
            ],
            &[],
        );
        let fake = Fake::new(vec![c, ct_conf(&[], &[])]);
        rt().block_on(remove_with(
            &fake,
            110,
            "/mnt/media",
            Some("10.0.0.1:/export"),
        ))
        .unwrap();
        assert_eq!(
            fake.calls(),
            [r#"put [("digest", "d1"), ("delete", "mp0")]"#]
        );
        for addr in ["//10.0.0.1/share", "10.0.0.1:/export", "[::1]:/x"] {
            assert!(is_share_addr(addr), "{addr}");
        }
        for path in [
            "/srv/x", "srv/x", "host:rel", "C:\\x", "///x", "foo:bar", "//host/", ":/x", "a/b:/x",
        ] {
            assert!(!is_share_addr(path), "{path}");
        }
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
    fn parse_vmid_rejects_non_numeric() {
        assert_eq!(parse_vmid("110").unwrap(), 110);
        assert!(parse_vmid("baldur").is_err());
    }

    #[test]
    fn url_host_check_parses_and_ignores_unspecified_addresses() {
        let rt = rt();
        assert!(rt.block_on(url_is_this_host("https://127.0.0.1:8006/api2/json")));
        assert!(rt.block_on(url_is_this_host("https://[::1]:8006")));
        assert!(!rt.block_on(url_is_this_host("https://0.0.0.0:8006")));
        assert!(!rt.block_on(url_is_this_host("https://[::]:8006")));
        assert!(!rt.block_on(url_is_this_host("not a url")));
        assert!(!rt.block_on(url_is_this_host("https://192.0.2.1:8006")));
        assert!(!ip_is_local("0.0.0.0".parse().unwrap()));
        assert!(ip_is_local("127.0.0.1".parse().unwrap()));
    }
}
