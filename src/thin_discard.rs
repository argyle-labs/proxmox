//! LVM-thin discard drift and allocation divergence.
//!
//! A thin volume only returns blocks to its pool when the guest's deletes reach
//! it as discards. Without `mountoptions=discard` (LXC) or `discard=on` (QEMU
//! disk), thin allocation only ever grows, so the pool can fill while every
//! guest filesystem on it still reports free space.
//!
//! Two verbs:
//!
//! * `proxmox.thin.audit` (read) — per guest, every disk on `lvmthin` storage:
//!   whether discard is active, staged for the next start, or missing (with the
//!   exact config value the remediation would write); and, for running LXC root
//!   filesystems, thin allocation vs in-guest usage.
//! * `proxmox.thin.enable_discard` (mutating, dry-run by default via orca's
//!   central execute gate) — rewrites the disk lines to carry discard.
//!
//! The PVE API cannot report whether anything schedules `fstrim` (that is a
//! host systemd unit), and it reports in-guest usage only for LXC root
//! filesystems, so VM divergence is not measured here.

use std::collections::{HashMap, HashSet};

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::backup::{enc, put_form, raw_get_data};
use crate::generated::{self, types as gtypes};
use crate::responses::{ConfigField, GuestConfigData};
use crate::tools::{EndpointFailure, fan_out_enabled_endpoints, resolve_config};
use crate::{Config, GuestKind, fetch_guest_config};

/// Thin allocation exceeding in-guest usage by this many percentage points of
/// the volume size is flagged. A volume with working discard tracks its
/// filesystem within a few points.
pub const DIVERGENCE_WARN_PCT: f64 = 15.0;

const THIN_PLUGIN: &str = "lvmthin";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiscardState {
    Enabled,
    /// Written to the config but held in `[pve:pending]` until the guest's next
    /// start.
    PendingRestart,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ThinVolumeAudit {
    /// Config key: `rootfs`, `mp0`, `scsi0`, …
    pub key: String,
    pub volid: String,
    pub storage: String,
    pub discard: DiscardState,
    /// The config value `proxmox.thin.enable_discard` would write. Only set
    /// when `discard` is `missing`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Blocks the thin pool has actually allocated to this volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allocated_bytes: Option<u64>,
    /// Filesystem usage reported from inside the guest. LXC root filesystems of
    /// running containers only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_used_bytes: Option<u64>,
    /// `(allocated - fs_used) / size`, in percentage points.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub divergence_pct: Option<f64>,
    /// `divergence_pct` is at or above [`DIVERGENCE_WARN_PCT`].
    pub diverged: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ThinGuestAudit {
    pub endpoint: String,
    pub node: String,
    pub vmid: u64,
    /// `lxc` or `qemu`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub running: bool,
    pub volumes: Vec<ThinVolumeAudit>,
}

/// Something the audit could not read. Guests or volumes behind it are absent
/// from (or incomplete in) the report rather than clean.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ThinAuditError {
    /// `None` when the endpoint registry itself could not be listed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Set when a storage content listing failed: allocation is unknown for
    /// every volume on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    /// Set when a guest's config could not be read: the guest is not audited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vmid: Option<u64>,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ThinAuditReport {
    pub guests: Vec<ThinGuestAudit>,
    pub errors: Vec<ThinAuditError>,
}

/// One config key as `/nodes/{node}/{kind}/{vmid}/pending` reports it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PendingEntry {
    pub key: String,
    pub value: Option<String>,
    pub pending: Option<String>,
    pub delete: bool,
}

/// Thin-pool usage of one volume from a storage content listing.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct VolumeUsage {
    pub size: Option<u64>,
    pub used: Option<u64>,
}

fn scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

pub fn parse_pending(data: &Value) -> Vec<PendingEntry> {
    data.as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| {
                    Some(PendingEntry {
                        key: i.get("key")?.as_str()?.to_string(),
                        value: i.get("value").and_then(scalar_string),
                        pending: i.get("pending").and_then(scalar_string),
                        delete: i.get("delete").and_then(Value::as_u64).unwrap_or(0) != 0,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `volid → usage` from a `/nodes/{node}/storage/{storage}/content` listing.
pub fn parse_content(data: &Value) -> HashMap<String, VolumeUsage> {
    data.as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| {
                    let volid = i.get("volid")?.as_str()?.to_string();
                    Some((
                        volid,
                        VolumeUsage {
                            size: i.get("size").and_then(Value::as_u64),
                            used: i.get("used").and_then(Value::as_u64),
                        },
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `key` names a guest disk that could sit on thin storage. `unusedN`,
/// EFI vars and TPM state are excluded: nothing writes through them.
fn is_disk_key(kind: GuestKind, key: &str) -> bool {
    let indexed = |prefix: &str| {
        key.strip_prefix(prefix)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    match kind {
        GuestKind::Lxc => key == "rootfs" || indexed("mp"),
        GuestKind::Qemu => ["scsi", "virtio", "sata", "ide"].iter().any(|p| indexed(p)),
    }
}

/// `(volid, storage)` of a disk line, or `None` for bind mounts, CD-ROMs and
/// empty drives.
pub fn volume_of(kind: GuestKind, value: &str) -> Option<(String, String)> {
    let mut parts = value.split(',');
    let first = parts.next()?.trim();
    let prefix = match kind {
        GuestKind::Lxc => "volume=",
        GuestKind::Qemu => "file=",
    };
    let vol = first.strip_prefix(prefix).unwrap_or(first);
    if kind == GuestKind::Qemu && (vol == "none" || value.split(',').any(|p| p == "media=cdrom")) {
        return None;
    }
    let (storage, _) = vol.split_once(':')?;
    if storage.is_empty() || vol.starts_with('/') {
        return None;
    }
    Some((vol.to_string(), storage.to_string()))
}

fn option<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    value
        .split(',')
        .find_map(|p| p.trim().strip_prefix(name)?.strip_prefix('='))
}

pub fn has_discard(kind: GuestKind, value: &str) -> bool {
    match kind {
        GuestKind::Lxc => option(value, "mountoptions")
            .is_some_and(|opts| opts.split(';').any(|o| o.trim() == "discard")),
        GuestKind::Qemu => option(value, "discard") == Some("on"),
    }
}

/// `value` with discard turned on, every other option preserved. LXC mount
/// options are `;`-separated inside one `mountoptions=`, so an existing set is
/// extended rather than given a second key; QEMU's `discard=ignore` is
/// replaced.
pub fn with_discard(kind: GuestKind, value: &str) -> String {
    if has_discard(kind, value) {
        return value.to_string();
    }
    let (name, set) = match kind {
        GuestKind::Lxc => ("mountoptions", None),
        GuestKind::Qemu => ("discard", Some("on")),
    };
    let mut found = false;
    let parts: Vec<String> = value
        .split(',')
        .map(|p| {
            match p
                .trim()
                .strip_prefix(name)
                .and_then(|r| r.strip_prefix('='))
            {
                Some(cur) => {
                    found = true;
                    match set {
                        Some(v) => format!("{name}={v}"),
                        None if cur.is_empty() => format!("{name}=discard"),
                        None => format!("{name}={cur};discard"),
                    }
                }
                None => p.to_string(),
            }
        })
        .collect();
    let mut out = parts.join(",");
    if !found {
        match kind {
            GuestKind::Lxc => out.push_str(",mountoptions=discard"),
            GuestKind::Qemu => out.push_str(",discard=on"),
        }
    }
    out
}

pub fn divergence_pct(size: u64, allocated: u64, fs_used: u64) -> Option<f64> {
    (size > 0).then(|| allocated.saturating_sub(fs_used) as f64 / size as f64 * 100.0)
}

/// Pure: audit one guest's thin volumes from its pending listing (which
/// carries both the active and the staged value of every key).
///
/// `thin` is the set of `lvmthin` storage ids on the guest's node; `usage` maps
/// volid to pool allocation on that same node (volids repeat across nodes);
/// `rootfs_used` is the in-guest root filesystem usage of a running container.
pub fn audit_volumes(
    kind: GuestKind,
    pending: &[PendingEntry],
    thin: &HashSet<String>,
    usage: &HashMap<String, VolumeUsage>,
    rootfs_used: Option<u64>,
) -> Vec<ThinVolumeAudit> {
    let mut out = Vec::new();
    for e in pending {
        if e.delete || !is_disk_key(kind, &e.key) {
            continue;
        }
        let effective = e.pending.as_deref().or(e.value.as_deref());
        let Some(effective) = effective else { continue };
        let Some((volid, storage)) = volume_of(kind, effective) else {
            continue;
        };
        if !thin.contains(&storage) {
            continue;
        }
        let active = e.value.as_deref().is_some_and(|v| has_discard(kind, v));
        let discard = if active {
            DiscardState::Enabled
        } else if has_discard(kind, effective) {
            DiscardState::PendingRestart
        } else {
            DiscardState::Missing
        };
        let u = usage.get(&volid).copied().unwrap_or_default();
        let fs_used = (kind == GuestKind::Lxc && e.key == "rootfs")
            .then_some(rootfs_used)
            .flatten();
        let divergence = match (u.size, u.used, fs_used) {
            (Some(size), Some(used), Some(fs)) => divergence_pct(size, used, fs),
            _ => None,
        };
        out.push(ThinVolumeAudit {
            key: e.key.clone(),
            volid,
            storage,
            discard,
            proposed: (discard == DiscardState::Missing).then(|| with_discard(kind, effective)),
            size_bytes: u.size,
            allocated_bytes: u.used,
            fs_used_bytes: fs_used,
            divergence_pct: divergence,
            diverged: divergence.is_some_and(|d| d >= DIVERGENCE_WARN_PCT),
        });
    }
    out
}

struct GuestRef {
    node: String,
    vmid: u64,
    kind: GuestKind,
    name: Option<String>,
    running: bool,
    /// In-guest root filesystem usage, meaningful only for a running LXC.
    disk: Option<u64>,
}

/// Audit every non-template guest on one endpoint (optionally one node). Fails
/// only when the guest inventory itself is unreadable; anything narrower is
/// recorded in [`ThinAuditReport::errors`].
pub async fn audit_endpoint(
    cfg: &Config,
    endpoint: &str,
    node: Option<&str>,
) -> Result<ThinAuditReport> {
    use gtypes::GetResourcesClusterResourcesResponseItemType as Kind;

    let http = cfg.build_reqwest_client()?;
    let client = generated::Client::new_with_client(&cfg.base_url, http.clone());
    let items = client
        .get_resources_cluster_resources(None)
        .await
        .map_err(|e| anyhow::anyhow!("cluster resources: {e}"))?
        .into_inner();

    let mut thin: HashMap<String, HashSet<String>> = HashMap::new();
    let mut guests = Vec::new();
    for item in items {
        let Some(n) = item.node.clone() else { continue };
        if node.is_some_and(|want| want != n) {
            continue;
        }
        let kind = match item.type_ {
            Kind::Storage => {
                if item.plugintype.as_deref() == Some(THIN_PLUGIN)
                    && let Some(s) = item.storage.clone()
                {
                    thin.entry(n).or_default().insert(s);
                }
                continue;
            }
            Kind::Qemu => GuestKind::Qemu,
            Kind::Lxc => GuestKind::Lxc,
            _ => continue,
        };
        let Some(vmid) = item.vmid.filter(|v| *v > 0) else {
            continue;
        };
        if item.template.unwrap_or(false) {
            continue;
        }
        let running = item.status.as_deref() == Some("running");
        guests.push(GuestRef {
            node: n,
            vmid: vmid as u64,
            kind,
            name: item.name.clone(),
            running,
            disk: (running && kind == GuestKind::Lxc)
                .then_some(item.disk)
                .flatten(),
        });
    }

    let mut report = ThinAuditReport::default();
    let mut usage: HashMap<String, HashMap<String, VolumeUsage>> = HashMap::new();
    for (n, stores) in &thin {
        for s in stores {
            let path = format!("nodes/{}/storage/{}/content", enc(n), enc(s));
            match raw_get_data(&http, &cfg.base_url, &path).await {
                Ok(data) => usage
                    .entry(n.clone())
                    .or_default()
                    .extend(parse_content(&data)),
                Err(e) => {
                    tracing::warn!(endpoint, node = %n, storage = %s, error = %e,
                        "thin audit: storage content listing failed");
                    report.errors.push(ThinAuditError {
                        endpoint: Some(endpoint.to_string()),
                        node: Some(n.clone()),
                        storage: Some(s.clone()),
                        vmid: None,
                        error: format!("storage content listing: {e:#}"),
                    });
                }
            }
        }
    }

    let empty = HashSet::new();
    let no_usage = HashMap::new();
    for g in guests {
        let node_thin = thin.get(&g.node).unwrap_or(&empty);
        if node_thin.is_empty() {
            continue;
        }
        let path = format!(
            "nodes/{}/{}/{}/pending",
            enc(&g.node),
            g.kind.as_str(),
            g.vmid
        );
        let pending = match raw_get_data(&http, &cfg.base_url, &path).await {
            Ok(data) => parse_pending(&data),
            Err(e) => {
                tracing::warn!(endpoint, node = %g.node, vmid = g.vmid, error = %e,
                    "thin audit: pending config read failed");
                report.errors.push(ThinAuditError {
                    endpoint: Some(endpoint.to_string()),
                    node: Some(g.node.clone()),
                    storage: None,
                    vmid: Some(g.vmid),
                    error: format!("pending config read: {e:#}"),
                });
                continue;
            }
        };
        let node_usage = usage.get(&g.node).unwrap_or(&no_usage);
        let volumes = audit_volumes(g.kind, &pending, node_thin, node_usage, g.disk);
        if volumes.is_empty() {
            continue;
        }
        report.guests.push(ThinGuestAudit {
            endpoint: endpoint.to_string(),
            node: g.node,
            vmid: g.vmid,
            kind: g.kind.as_str().to_string(),
            name: g.name,
            running: g.running,
            volumes,
        });
    }
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DiscardChange {
    pub key: String,
    pub before: String,
    pub after: String,
    /// Measured from the guest's pending config after the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<DiscardState>,
}

/// Pure: the disk lines of `cfg` (pending values applied) that need discard.
/// `only` narrows to named keys; naming a key that is not a thin disk is an
/// error rather than a silent no-op.
pub fn plan_discard(
    kind: GuestKind,
    cfg: &GuestConfigData,
    thin: &HashSet<String>,
    only: &[String],
) -> Result<Vec<DiscardChange>> {
    let thin_disk = |key: &str| -> Option<&str> {
        if !is_disk_key(kind, key) {
            return None;
        }
        let value = cfg.get_str(key)?;
        let (_, storage) = volume_of(kind, value)?;
        thin.contains(&storage).then_some(value)
    };
    for key in only {
        if thin_disk(key).is_none() {
            bail!("'{key}' is not a disk on lvmthin storage in this guest's config");
        }
    }
    let mut out = Vec::new();
    for key in cfg.fields.keys() {
        if !only.is_empty() && !only.contains(key) {
            continue;
        }
        let Some(value) = thin_disk(key) else {
            continue;
        };
        if has_discard(kind, value) {
            continue;
        }
        out.push(DiscardChange {
            key: key.clone(),
            before: value.to_string(),
            after: with_discard(kind, value),
            state: None,
        });
    }
    Ok(out)
}

/// `lvmthin` storage ids on one node.
pub fn parse_thin_storages(data: &Value) -> HashSet<String> {
    data.as_array()
        .map(|items| {
            items
                .iter()
                .filter(|i| i.get("type").and_then(Value::as_str) == Some(THIN_PLUGIN))
                .filter_map(|i| Some(i.get("storage")?.as_str()?.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ThinDiscardOutcome {
    pub endpoint: String,
    pub node: String,
    pub vmid: u64,
    pub kind: String,
    pub changes: Vec<DiscardChange>,
    /// At least one change is staged until the guest's next start.
    pub restart_required: bool,
    /// The write landed but something after it could not be confirmed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Write discard onto every thin disk of one guest that lacks it.
pub async fn enable_discard(
    cfg: &Config,
    endpoint: &str,
    node: &str,
    kind: GuestKind,
    vmid: u64,
    only: &[String],
) -> Result<ThinDiscardOutcome> {
    let http = cfg.build_reqwest_client()?;
    let storages = raw_get_data(
        &http,
        &cfg.base_url,
        &format!("nodes/{}/storage", enc(node)),
    )
    .await?;
    let thin = parse_thin_storages(&storages);
    let config = fetch_guest_config(&http, &cfg.base_url, node, kind, vmid).await?;
    if config.data.get_int("template").unwrap_or(0) != 0 {
        bail!(
            "{} {vmid} is a template; change discard on the guests cloned from it",
            kind.as_str()
        );
    }
    let mut changes = plan_discard(kind, &config.data, &thin, only)?;
    let mut warnings = Vec::new();

    if !changes.is_empty() {
        let mut pairs: Vec<(String, String)> = changes
            .iter()
            .map(|c| (c.key.clone(), c.after.clone()))
            .collect();
        // PVE rejects the write if the config changed since it was read; without
        // the digest the PUT could clobber a concurrent edit.
        let Some(ConfigField::Str(digest)) = config.data.fields.get("digest") else {
            bail!(
                "{} {vmid} config read returned no digest; refusing an unguarded write",
                kind.as_str()
            );
        };
        pairs.push(("digest".to_string(), digest.clone()));
        let url = format!(
            "{}/nodes/{}/{}/{}/config",
            cfg.base_url.trim_end_matches('/'),
            enc(node),
            kind.as_str(),
            vmid
        );
        put_form(&http, &url, &pairs).await?;

        let path = format!("nodes/{}/{}/{}/pending", enc(node), kind.as_str(), vmid);
        match raw_get_data(&http, &cfg.base_url, &path).await {
            Ok(data) => {
                let pending = parse_pending(&data);
                for c in &mut changes {
                    c.state = pending.iter().find(|e| e.key == c.key).map(|e| {
                        if e.value.as_deref().is_some_and(|v| has_discard(kind, v)) {
                            DiscardState::Enabled
                        } else if e.pending.as_deref().is_some_and(|v| has_discard(kind, v)) {
                            DiscardState::PendingRestart
                        } else {
                            DiscardState::Missing
                        }
                    });
                }
            }
            Err(e) => warnings.push(format!(
                "config written, but re-reading the pending config failed so each change's state is unknown: {e:#}"
            )),
        }
    }

    Ok(ThinDiscardOutcome {
        endpoint: endpoint.to_string(),
        node: node.to_string(),
        vmid,
        kind: kind.as_str().to_string(),
        restart_required: changes
            .iter()
            .any(|c| c.state == Some(DiscardState::PendingRestart)),
        changes,
        warnings,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// proxmox.thin.audit / proxmox.thin.enable_discard
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ThinAuditArgs {
    /// Registered endpoint. Omit to audit every enabled endpoint.
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Limit to one node.
    #[arg(long)]
    #[serde(default)]
    pub node: Option<String>,
}

/// Audit every guest disk on LVM-thin storage: discard active / staged /
/// missing (with the value `proxmox.thin.enable_discard` would write), and thin
/// allocation vs in-guest usage for running LXC root filesystems. Anything that
/// could not be read is listed in `errors`; the audit fails outright when no
/// endpoint could be read at all.
#[orca_tool(domain = "proxmox", verb = "thin.audit")]
async fn proxmox_thin_audit(args: ThinAuditArgs, _ctx: &ToolCtx) -> Result<ThinAuditReport> {
    let node = args.node.clone();
    if let Some(name) = &args.endpoint {
        let cfg = resolve_config(name).await?;
        return audit_endpoint(&cfg, name, node.as_deref()).await;
    }
    let fan = fan_out_enabled_endpoints("thin.audit", |cfg, ep| {
        let node = node.clone();
        async move { Ok(vec![audit_endpoint(&cfg, &ep.name, node.as_deref()).await?]) }
    })
    .await;
    merge_fan_out(fan.items, fan.failures, fan.attempted)
}

/// Fold per-endpoint reports and endpoint-level failures into one report.
/// Nothing read is an error, never an empty report that reads as all-clean.
fn merge_fan_out(
    reports: Vec<ThinAuditReport>,
    failures: Vec<EndpointFailure>,
    attempted: usize,
) -> Result<ThinAuditReport> {
    if reports.is_empty() {
        if attempted == 0 && failures.is_empty() {
            bail!("no enabled proxmox endpoints to audit");
        }
        let detail: Vec<String> = failures
            .iter()
            .map(|f| match &f.endpoint {
                Some(ep) => format!("{ep}: {}", f.error),
                None => f.error.clone(),
            })
            .collect();
        bail!("thin audit read no endpoint: {}", detail.join("; "));
    }
    let mut out = ThinAuditReport::default();
    for r in reports {
        out.guests.extend(r.guests);
        out.errors.extend(r.errors);
    }
    out.errors
        .extend(failures.into_iter().map(|f| ThinAuditError {
            endpoint: f.endpoint,
            node: None,
            storage: None,
            vmid: None,
            error: f.error,
        }));
    Ok(out)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ThinEnableDiscardArgs {
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub node: String,
    /// QEMU VM id.
    #[arg(long)]
    pub vmid: Option<u64>,
    /// LXC container id.
    #[arg(long)]
    pub ctid: Option<u64>,
    /// Config key to change (`rootfs`, `mp0`, `scsi0`, …). Repeatable. Omit to
    /// change every thin disk that lacks discard.
    #[arg(long = "volume")]
    #[serde(default)]
    pub volumes: Vec<String>,
}

/// [MUTATES STATE] Enable discard on a guest's LVM-thin disks
/// (`mountoptions=discard` for an LXC, `discard=on` for a VM disk) so deletes
/// inside the guest return blocks to the pool. On a running guest PVE stages
/// the change until its next start. Run `proxmox.thin.audit` for the exact
/// values this writes.
#[orca_tool(domain = "proxmox", verb = "thin.enable_discard", role = "admin")]
async fn proxmox_thin_enable_discard(
    args: ThinEnableDiscardArgs,
    _ctx: &ToolCtx,
) -> Result<ThinDiscardOutcome> {
    let (vmid, kind) = match (args.vmid, args.ctid) {
        (Some(v), None) => (v, GuestKind::Qemu),
        (None, Some(c)) => (c, GuestKind::Lxc),
        (Some(_), Some(_)) => bail!("set either `vmid` or `ctid`, not both"),
        (None, None) => bail!("`vmid` or `ctid` required"),
    };
    let cfg = resolve_config(&args.endpoint).await?;
    enable_discard(&cfg, &args.endpoint, &args.node, kind, vmid, &args.volumes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::responses::GuestConfigResponse;
    use plugin_toolkit::serde_json::json;
    use std::sync::{Arc, Mutex};

    const GIB: u64 = 1 << 30;

    fn thin(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn lxc_discard_is_mountoptions_not_the_vm_key() {
        let v = "local-lvm:vm-117-disk-0,size=98G";
        assert!(!has_discard(GuestKind::Lxc, v));
        assert_eq!(
            with_discard(GuestKind::Lxc, v),
            "local-lvm:vm-117-disk-0,size=98G,mountoptions=discard"
        );
        // `discard=1` is not an LXC rootfs option; it must not count.
        assert!(!has_discard(
            GuestKind::Lxc,
            "local-lvm:vm-1-disk-0,discard=1"
        ));
    }

    #[test]
    fn lxc_existing_mountoptions_are_extended_not_duplicated() {
        let v = "local-lvm:vm-114-disk-0,mountoptions=noatime;lazytime,size=126G";
        let out = with_discard(GuestKind::Lxc, v);
        assert_eq!(
            out,
            "local-lvm:vm-114-disk-0,mountoptions=noatime;lazytime;discard,size=126G"
        );
        assert!(has_discard(GuestKind::Lxc, &out));
        assert_eq!(with_discard(GuestKind::Lxc, &out), out, "idempotent");
    }

    #[test]
    fn qemu_discard_is_on_and_replaces_ignore() {
        assert_eq!(
            with_discard(
                GuestKind::Qemu,
                "local-lvm:vm-106-disk-0,iothread=1,size=32G"
            ),
            "local-lvm:vm-106-disk-0,iothread=1,size=32G,discard=on"
        );
        assert_eq!(
            with_discard(
                GuestKind::Qemu,
                "local-lvm:vm-106-disk-0,discard=ignore,size=32G"
            ),
            "local-lvm:vm-106-disk-0,discard=on,size=32G"
        );
        assert!(has_discard(
            GuestKind::Qemu,
            "file=local-lvm:vm-1-disk-0,discard=on"
        ));
    }

    #[test]
    fn volume_of_skips_bind_mounts_cdroms_and_empty_drives() {
        assert_eq!(
            volume_of(
                GuestKind::Lxc,
                "volume=local-lvm:vm-113-disk-1,mp=/data,size=8G"
            ),
            Some(("local-lvm:vm-113-disk-1".into(), "local-lvm".into()))
        );
        assert_eq!(
            volume_of(GuestKind::Lxc, "/srv/transcode,mp=/transcode"),
            None
        );
        assert_eq!(
            volume_of(GuestKind::Qemu, "local:iso/debian.iso,media=cdrom"),
            None
        );
        assert_eq!(volume_of(GuestKind::Qemu, "none,media=cdrom"), None);
    }

    #[test]
    fn disk_keys_exclude_unused_efi_and_tpm() {
        assert!(is_disk_key(GuestKind::Lxc, "rootfs"));
        assert!(is_disk_key(GuestKind::Lxc, "mp12"));
        assert!(!is_disk_key(GuestKind::Lxc, "mp"));
        assert!(is_disk_key(GuestKind::Qemu, "scsi0"));
        assert!(is_disk_key(GuestKind::Qemu, "virtio3"));
        assert!(!is_disk_key(GuestKind::Qemu, "scsihw"));
        assert!(!is_disk_key(GuestKind::Qemu, "unused0"));
        assert!(!is_disk_key(GuestKind::Qemu, "efidisk0"));
        assert!(!is_disk_key(GuestKind::Qemu, "tpmstate0"));
    }

    #[test]
    fn full_pool_with_low_fs_usage_is_missing_discard_and_diverged() {
        let pending = parse_pending(&json!([
            {"key": "hostname", "value": "ct"},
            {"key": "rootfs", "value": "local-lvm:vm-117-disk-0,size=98G"},
            {"key": "mp0", "value": "/mnt/share,mp=/share"},
        ]));
        let usage = parse_content(&json!([{
            "volid": "local-lvm:vm-117-disk-0", "format": "raw",
            "size": 98 * GIB, "used": (98.0 * 0.9794 * GIB as f64) as u64,
        }]));
        let v = audit_volumes(
            GuestKind::Lxc,
            &pending,
            &thin(&["local-lvm"]),
            &usage,
            Some(36 * GIB),
        );
        assert_eq!(v.len(), 1, "bind mount is not a thin volume: {v:#?}");
        let r = &v[0];
        assert_eq!(r.key, "rootfs");
        assert_eq!(r.discard, DiscardState::Missing);
        assert_eq!(
            r.proposed.as_deref(),
            Some("local-lvm:vm-117-disk-0,size=98G,mountoptions=discard")
        );
        let d = r.divergence_pct.unwrap();
        assert!((d - 61.2).abs() < 0.5, "got {d}");
        assert!(r.diverged);
    }

    #[test]
    fn healthy_volume_is_not_diverged() {
        let pending = parse_pending(&json!([
            {"key": "rootfs", "value": "local-lvm:vm-113-disk-0,mountoptions=discard,size=16G"},
        ]));
        let usage = parse_content(&json!([{
            "volid": "local-lvm:vm-113-disk-0", "size": 16 * GIB, "used": 13 * GIB,
        }]));
        let v = audit_volumes(
            GuestKind::Lxc,
            &pending,
            &thin(&["local-lvm"]),
            &usage,
            Some(13 * GIB),
        );
        assert_eq!(v[0].discard, DiscardState::Enabled);
        assert_eq!(v[0].proposed, None);
        assert_eq!(v[0].divergence_pct, Some(0.0));
        assert!(!v[0].diverged);
    }

    /// `pct set` on a running CT stages the change; the audit must say so
    /// rather than report it as fixed or as still missing.
    #[test]
    fn staged_discard_is_pending_restart() {
        let pending = parse_pending(&json!([{
            "key": "rootfs",
            "value": "local-lvm:vm-101-disk-0,size=4G",
            "pending": "local-lvm:vm-101-disk-0,size=4G,mountoptions=discard",
        }]));
        let v = audit_volumes(
            GuestKind::Lxc,
            &pending,
            &thin(&["local-lvm"]),
            &HashMap::new(),
            None,
        );
        assert_eq!(v[0].discard, DiscardState::PendingRestart);
        assert_eq!(v[0].proposed, None);
        assert_eq!(v[0].divergence_pct, None, "no usage data, no claim");
    }

    #[test]
    fn non_thin_storage_and_vm_usage_are_not_claimed() {
        let pending = parse_pending(&json!([
            {"key": "scsi0", "value": "local-lvm:vm-102-disk-0,size=64G"},
            {"key": "scsi1", "value": "nfs-share:102/vm-102-disk-1.qcow2,size=8G"},
            {"key": "ide2", "value": "none,media=cdrom"},
            {"key": "scsi2", "value": "local-lvm:vm-102-disk-2,size=8G", "delete": 1},
        ]));
        let usage = parse_content(&json!([{
            "volid": "local-lvm:vm-102-disk-0", "size": 64 * GIB, "used": 40 * GIB,
        }]));
        let v = audit_volumes(
            GuestKind::Qemu,
            &pending,
            &thin(&["local-lvm"]),
            &usage,
            Some(GIB),
        );
        assert_eq!(v.len(), 1, "{v:#?}");
        assert_eq!(v[0].key, "scsi0");
        assert_eq!(v[0].allocated_bytes, Some(40 * GIB));
        assert_eq!(v[0].fs_used_bytes, None, "VM fs usage is not measured");
        assert_eq!(v[0].divergence_pct, None);
        assert_eq!(
            v[0].proposed.as_deref(),
            Some("local-lvm:vm-102-disk-0,size=64G,discard=on")
        );
    }

    fn cfg(json: &str) -> GuestConfigData {
        serde_json::from_str::<GuestConfigResponse>(json)
            .unwrap()
            .data
    }

    #[test]
    fn plan_changes_only_thin_disks_lacking_discard() {
        let c = cfg(r#"{"data":{
            "rootfs":"local-lvm:vm-114-disk-0,size=126G",
            "mp0":"local-lvm:vm-114-disk-1,mp=/cache,mountoptions=discard,size=20G",
            "mp1":"/srv/x,mp=/x",
            "mp2":"tank:subvol-114-disk-0,mp=/zfs,size=10G",
            "digest":"abc"
        }}"#);
        let plan = plan_discard(GuestKind::Lxc, &c, &thin(&["local-lvm"]), &[]).unwrap();
        assert_eq!(plan.len(), 1, "{plan:#?}");
        assert_eq!(plan[0].key, "rootfs");
        assert_eq!(
            plan[0].after,
            "local-lvm:vm-114-disk-0,size=126G,mountoptions=discard"
        );

        let narrowed =
            plan_discard(GuestKind::Lxc, &c, &thin(&["local-lvm"]), &["mp0".into()]).unwrap();
        assert!(narrowed.is_empty(), "mp0 already has discard");

        let err =
            plan_discard(GuestKind::Lxc, &c, &thin(&["local-lvm"]), &["mp2".into()]).unwrap_err();
        assert!(err.to_string().contains("not a disk on lvmthin"));
    }

    fn reply(status: u16, data: Value) -> String {
        let body = serde_json::to_vec(&json!({ "data": data })).unwrap();
        json!({
            "status": status,
            "headers": [["content-type", "application/json"]],
            "body": body,
        })
        .to_string()
    }

    fn test_config() -> Config {
        Config::new(
            "https://10.0.0.5:8006/api2/json",
            "orca@pve!orca",
            "00000000-0000-0000-0000-000000000000",
        )
    }

    /// Answer `http.request` by method + path suffix; record every request.
    fn run_against<T>(
        routes: Vec<(&'static str, &'static str, String)>,
        f: impl AsyncFnOnce() -> T,
    ) -> (T, Vec<Value>) {
        let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
        let log = seen.clone();
        let out = plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, raw: &str| {
                assert_eq!(cap, "http.request");
                let req: Value = serde_json::from_str(raw).unwrap();
                log.lock().unwrap().push(req.clone());
                let method = req["method"].as_str().unwrap();
                let url = req["url"].as_str().unwrap();
                let path = url.split('?').next().unwrap();
                for (m, suffix, body) in &routes {
                    if *m == method && path.ends_with(suffix) {
                        return Ok(body.clone());
                    }
                }
                panic!("unexpected request {method} {url}");
            }),
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(f())
            },
        );
        let seen = seen.lock().unwrap().clone();
        (out, seen)
    }

    #[test]
    fn audit_endpoint_walks_resources_content_and_pending() {
        let routes = vec![
            (
                "GET",
                "/cluster/resources",
                reply(
                    200,
                    json!([
                        {"id": "node/hyp1", "type": "node", "node": "hyp1"},
                        {"id": "storage/hyp1/local-lvm", "type": "storage", "node": "hyp1",
                         "storage": "local-lvm", "plugintype": "lvmthin"},
                        {"id": "storage/hyp1/local", "type": "storage", "node": "hyp1",
                         "storage": "local", "plugintype": "dir"},
                        {"id": "lxc/117", "type": "lxc", "node": "hyp1", "vmid": 117,
                         "name": "ct", "status": "running", "disk": 36 * GIB,
                         "maxdisk": 98 * GIB},
                        {"id": "qemu/900", "type": "qemu", "node": "hyp1", "vmid": 900,
                         "name": "tmpl", "status": "stopped", "template": true},
                    ]),
                ),
            ),
            (
                "GET",
                "/nodes/hyp1/storage/local-lvm/content",
                reply(
                    200,
                    json!([{"volid": "local-lvm:vm-117-disk-0", "format": "raw",
                            "size": 98 * GIB, "used": 96 * GIB}]),
                ),
            ),
            (
                "GET",
                "/nodes/hyp1/lxc/117/pending",
                reply(
                    200,
                    json!([{"key": "rootfs", "value": "local-lvm:vm-117-disk-0,size=98G"}]),
                ),
            ),
        ];
        let (res, seen) = run_against(routes, async || {
            audit_endpoint(&test_config(), "pve", None).await
        });
        let report = res.unwrap();
        assert!(report.errors.is_empty(), "{:#?}", report.errors);
        let audit = report.guests;
        assert_eq!(audit.len(), 1, "template skipped: {audit:#?}");
        let g = &audit[0];
        assert_eq!((g.vmid, g.kind.as_str(), g.running), (117, "lxc", true));
        assert_eq!(g.volumes[0].discard, DiscardState::Missing);
        assert_eq!(g.volumes[0].fs_used_bytes, Some(36 * GIB));
        assert!(g.volumes[0].diverged);
        assert!(
            seen.iter().all(|r| r["method"] == "GET"),
            "an audit must never write"
        );
    }

    #[test]
    fn enable_discard_puts_new_value_with_digest_and_reports_staging() {
        let routes = vec![
            (
                "GET",
                "/nodes/hyp1/storage",
                reply(
                    200,
                    json!([{"storage": "local-lvm", "type": "lvmthin"},
                           {"storage": "local", "type": "dir"}]),
                ),
            ),
            (
                "GET",
                "/nodes/hyp1/lxc/117/config",
                reply(
                    200,
                    json!({"rootfs": "local-lvm:vm-117-disk-0,size=98G", "digest": "d1g"}),
                ),
            ),
            ("PUT", "/nodes/hyp1/lxc/117/config", reply(200, Value::Null)),
            (
                "GET",
                "/nodes/hyp1/lxc/117/pending",
                reply(
                    200,
                    json!([{"key": "rootfs",
                            "value": "local-lvm:vm-117-disk-0,size=98G",
                            "pending": "local-lvm:vm-117-disk-0,size=98G,mountoptions=discard"}]),
                ),
            ),
        ];
        let (res, seen) = run_against(routes, async || {
            enable_discard(&test_config(), "pve", "hyp1", GuestKind::Lxc, 117, &[]).await
        });
        let out = res.unwrap();
        assert_eq!(out.changes.len(), 1);
        assert_eq!(out.changes[0].state, Some(DiscardState::PendingRestart));
        assert!(out.restart_required);

        let put = seen.iter().find(|r| r["method"] == "PUT").unwrap();
        let body: Vec<u8> = serde_json::from_value(put["body"].clone()).unwrap();
        let body = String::from_utf8(body).unwrap();
        assert!(
            body.contains("rootfs=local-lvm%3Avm-117-disk-0%2Csize%3D98G%2Cmountoptions%3Ddiscard"),
            "{body}"
        );
        assert!(body.contains("digest=d1g"), "{body}");
    }

    #[test]
    fn enable_discard_with_nothing_to_change_never_writes() {
        let routes = vec![
            (
                "GET",
                "/nodes/hyp1/storage",
                reply(200, json!([{"storage": "local-lvm", "type": "lvmthin"}])),
            ),
            (
                "GET",
                "/nodes/hyp1/qemu/106/config",
                reply(
                    200,
                    json!({"scsi0": "local-lvm:vm-106-disk-0,discard=on,size=32G"}),
                ),
            ),
        ];
        let (res, seen) = run_against(routes, async || {
            enable_discard(&test_config(), "pve", "hyp1", GuestKind::Qemu, 106, &[]).await
        });
        let out = res.unwrap();
        assert!(out.changes.is_empty());
        assert!(!out.restart_required);
        assert!(seen.iter().all(|r| r["method"] == "GET"));
    }

    #[test]
    fn qemu_discard_ignore_is_missing_and_proposes_on() {
        let pending = parse_pending(&json!([
            {"key": "scsi0", "value": "local-lvm:vm-106-disk-0,discard=ignore,size=32G"},
        ]));
        let v = audit_volumes(
            GuestKind::Qemu,
            &pending,
            &thin(&["local-lvm"]),
            &HashMap::new(),
            None,
        );
        assert_eq!(v[0].discard, DiscardState::Missing);
        assert_eq!(
            v[0].proposed.as_deref(),
            Some("local-lvm:vm-106-disk-0,discard=on,size=32G")
        );
    }

    #[test]
    fn empty_mountoptions_is_missing_and_filled_in_place() {
        let v = "local-lvm:vm-101-disk-0,mountoptions=,size=8G";
        assert!(!has_discard(GuestKind::Lxc, v));
        assert_eq!(
            with_discard(GuestKind::Lxc, v),
            "local-lvm:vm-101-disk-0,mountoptions=discard,size=8G"
        );
    }

    fn two_node_routes(content_hyp2: String) -> Vec<(&'static str, &'static str, String)> {
        vec![
            (
                "GET",
                "/cluster/resources",
                reply(
                    200,
                    json!([
                        {"id": "storage/hyp1/local-lvm", "type": "storage", "node": "hyp1",
                         "storage": "local-lvm", "plugintype": "lvmthin"},
                        {"id": "storage/hyp2/local-lvm", "type": "storage", "node": "hyp2",
                         "storage": "local-lvm", "plugintype": "lvmthin"},
                        {"id": "lxc/100", "type": "lxc", "node": "hyp1", "vmid": 100,
                         "status": "running", "disk": 2 * GIB},
                        {"id": "lxc/200", "type": "lxc", "node": "hyp2", "vmid": 200,
                         "status": "running", "disk": 7 * GIB},
                    ]),
                ),
            ),
            (
                "GET",
                "/nodes/hyp1/storage/local-lvm/content",
                reply(
                    200,
                    json!([{"volid": "local-lvm:vm-100-disk-0", "size": 8 * GIB, "used": 2 * GIB}]),
                ),
            ),
            ("GET", "/nodes/hyp2/storage/local-lvm/content", content_hyp2),
            (
                "GET",
                "/nodes/hyp1/lxc/100/pending",
                reply(
                    200,
                    json!([{"key": "rootfs", "value": "local-lvm:vm-100-disk-0,size=8G"}]),
                ),
            ),
            (
                "GET",
                "/nodes/hyp2/lxc/200/pending",
                reply(
                    200,
                    json!([{"key": "rootfs", "value": "local-lvm:vm-100-disk-0,size=8G"}]),
                ),
            ),
        ]
    }

    /// Node-local `local-lvm` reuses volids across nodes; each guest must read
    /// its own node's allocation.
    #[test]
    fn same_volid_on_two_nodes_is_keyed_per_node() {
        let content = reply(
            200,
            json!([{"volid": "local-lvm:vm-100-disk-0", "size": 8 * GIB, "used": 7 * GIB}]),
        );
        let (res, _) = run_against(two_node_routes(content), async || {
            audit_endpoint(&test_config(), "pve", None).await
        });
        let report = res.unwrap();
        let alloc = |node: &str| {
            report
                .guests
                .iter()
                .find(|g| g.node == node)
                .unwrap()
                .volumes[0]
                .allocated_bytes
        };
        assert_eq!(alloc("hyp1"), Some(2 * GIB));
        assert_eq!(alloc("hyp2"), Some(7 * GIB));
    }

    #[test]
    fn unreadable_content_and_pending_are_reported_not_dropped() {
        let mut routes = two_node_routes(reply(500, Value::Null));
        routes.retain(|(_, path, _)| *path != "/nodes/hyp1/lxc/100/pending");
        routes.push((
            "GET",
            "/nodes/hyp1/lxc/100/pending",
            reply(500, Value::Null),
        ));
        let (res, _) = run_against(routes, async || {
            audit_endpoint(&test_config(), "pve", None).await
        });
        let report = res.unwrap();
        assert_eq!(report.guests.len(), 1, "{report:#?}");
        assert_eq!(report.guests[0].vmid, 200);
        assert_eq!(report.guests[0].volumes[0].allocated_bytes, None);
        assert!(report.errors.iter().any(
            |e| e.node.as_deref() == Some("hyp2") && e.storage.as_deref() == Some("local-lvm")
        ));
        assert!(report.errors.iter().any(|e| e.vmid == Some(100)));
    }

    fn failure(ep: &str) -> EndpointFailure {
        EndpointFailure {
            endpoint: Some(ep.into()),
            error: "unreachable".into(),
        }
    }

    #[test]
    fn every_endpoint_failing_is_an_error_not_an_empty_report() {
        let err = merge_fan_out(vec![], vec![failure("a"), failure("b")], 2).unwrap_err();
        assert!(err.to_string().contains("a: unreachable"), "{err}");
        assert!(merge_fan_out(vec![], vec![], 0).is_err());
    }

    #[test]
    fn a_failed_endpoint_beside_a_good_one_is_listed() {
        let ok = ThinAuditReport::default();
        let out = merge_fan_out(vec![ok], vec![failure("b")], 2).unwrap();
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.errors[0].endpoint.as_deref(), Some("b"));
    }

    fn enable_routes(config: Value, pending: String) -> Vec<(&'static str, &'static str, String)> {
        vec![
            (
                "GET",
                "/nodes/hyp1/storage",
                reply(200, json!([{"storage": "local-lvm", "type": "lvmthin"}])),
            ),
            ("GET", "/nodes/hyp1/lxc/117/config", reply(200, config)),
            ("PUT", "/nodes/hyp1/lxc/117/config", reply(200, Value::Null)),
            ("GET", "/nodes/hyp1/lxc/117/pending", pending),
        ]
    }

    #[test]
    fn enable_discard_without_digest_never_writes() {
        let routes = enable_routes(
            json!({"rootfs": "local-lvm:vm-117-disk-0,size=98G"}),
            reply(200, json!([])),
        );
        let (res, seen) = run_against(routes, async || {
            enable_discard(&test_config(), "pve", "hyp1", GuestKind::Lxc, 117, &[]).await
        });
        assert!(res.unwrap_err().to_string().contains("no digest"));
        assert!(seen.iter().all(|r| r["method"] == "GET"));
    }

    #[test]
    fn enable_discard_refuses_templates() {
        let routes = enable_routes(
            json!({"rootfs": "local-lvm:vm-117-disk-0,size=98G", "template": 1, "digest": "d"}),
            reply(200, json!([])),
        );
        let (res, seen) = run_against(routes, async || {
            enable_discard(&test_config(), "pve", "hyp1", GuestKind::Lxc, 117, &[]).await
        });
        assert!(res.unwrap_err().to_string().contains("template"));
        assert!(seen.iter().all(|r| r["method"] == "GET"));
    }

    #[test]
    fn enable_discard_reread_failure_after_write_is_a_warning() {
        let routes = enable_routes(
            json!({"rootfs": "local-lvm:vm-117-disk-0,size=98G", "digest": "d"}),
            reply(500, Value::Null),
        );
        let (res, seen) = run_against(routes, async || {
            enable_discard(&test_config(), "pve", "hyp1", GuestKind::Lxc, 117, &[]).await
        });
        let out = res.unwrap();
        assert!(seen.iter().any(|r| r["method"] == "PUT"));
        assert_eq!(out.changes.len(), 1);
        assert_eq!(out.changes[0].state, None);
        assert!(!out.restart_required);
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
    }
}
