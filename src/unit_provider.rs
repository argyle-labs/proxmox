//! Proxmox [`UnitProvider`] — exposes cluster guests on the five-verb surface.
//!
//! Every VM (`qemu`) and container (`lxc`) across every registered + enabled
//! Proxmox endpoint is a unit. One `UnitId::manager` per endpoint
//! (`proxmox@<endpoint>`) so a multi-endpoint fleet fans out cleanly; the kind
//! (`vm` / `lxc`) is a first-class declared kind — no kind is owned by orca.
//!
//! Verb map (both kinds):
//! - [`Verb::List`]   → guests across all enabled endpoints (`/cluster/resources`)
//! - [`Verb::Detail`] → one guest's cluster-resource row (state, node, cpu, mem)
//! - [`Verb::Update`] → lifecycle action `start` / `stop` / `shutdown` / `reboot`
//! - [`Verb::Create`] → action `provision` (typed [`ProvisionPayload`] → PVE create)
//! - [`Verb::Delete`] → destroy the guest
//! - [`Verb::Upsert`] → action `set`: ensure-present (provision if absent, else no-op)
//!
//! Endpoint credentials live in the plugin's endpoint registry
//! (`proxmox.{list,create,…}`); this provider reads them through the same
//! `endpoint_db` the tool surface owns, so registering a host once lights up
//! both the tool surface and the unit surface.

use plugin_toolkit::anyhow::{Result, anyhow};
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::unit::{
    ACTION_BACKUP, ACTION_RESTORE, ActionDecl, ActionOutcome, CreateArgs, DeleteArgs, DetailArgs,
    ItemOutcome, ItemsOutcome, KindDeclaration, ListArgs, UnitDescriptor, UnitId, UnitProvider,
    UpdateArgs, UpsertArgs, Verb, VerbArgs, VerbDecl, VerbOutcome,
};
use plugin_toolkit::contract::{
    BackupRef, GuardViolation, RestorePayload, UnitFacts, UnitGuard, partition_violations,
};
use plugin_toolkit::schemars::{JsonSchema, schema_for};
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json::{self, json};

use crate::GuestKind;
use crate::execute::Change;
use crate::generated::{self, types as gtypes};

const KIND_VM: &str = "vm";
const KIND_LXC: &str = "lxc";
/// Unit action that backs an LXC up, then runs its updater.
const ACTION_GUEST_UPDATE: &str = "update";

/// Upper bound orca waits for a vzdump / restore task before giving up. A minimal
/// state backup is small, but a large qemu restore can run long; generous so a
/// legitimately-slow task is not aborted, bounded so a wedged one cannot hang the
/// guarded mutation forever.
const BACKUP_TASK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30 * 60);
const RESTORE_TASK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Stateless — every call re-reads the endpoint registry so newly-registered
/// hosts show up without a reload.
pub struct ProxmoxUnitProvider;

impl ProxmoxUnitProvider {
    pub fn new() -> Self {
        ProxmoxUnitProvider
    }
}

impl Default for ProxmoxUnitProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// One guest row, endpoint-scoped. The typed `payload` for list/detail items.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct GuestSummary {
    /// Registered endpoint name this guest was enumerated from.
    pub endpoint: String,
    /// Cluster name this endpoint belongs to, when clustered. Drives the
    /// canonical id so the same guest seen from every member node collapses to
    /// one unit. `None` for a standalone host (falls back to the endpoint name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// Proxmox node the guest currently runs on.
    pub node: String,
    /// `vm` (qemu) or `lxc`.
    pub kind: String,
    pub vmid: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f64>,
    /// Configured CPU cores (`maxcpu`), used to check the kind's [`UnitGuard`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maxcpu: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem: Option<u64>,
    /// Configured memory in bytes (`maxmem`); the guard floor is compared in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maxmem: Option<i64>,
    /// This guest's config-standard [`UnitGuard`] violations (empty = compliant),
    /// surfaced on every list/detail so the unit surface shows which guests
    /// breach their kind's provisioning floors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_violations: Vec<String>,
    /// Console and update-gate facts, probed by `detail` for a running LXC on
    /// this plugin's node. With them present the guard also requires both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<crate::guest_standard::StandardFacts>,
}

/// Typed payload for `Create { action: "provision" }`. Shared by both kinds;
/// `ostemplate` is required for `lxc`, `iso`/`disk_gb` shape a `vm`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct ProvisionPayload {
    /// Registered endpoint to create the guest on.
    pub endpoint: String,
    /// Target Proxmox node.
    pub node: String,
    /// `vm` (qemu) or `lxc`.
    pub kind: String,
    /// Explicit VMID; omitted → allocated via `/cluster/nextid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmid: Option<u64>,
    /// Guest name (`hostname` for lxc, `name` for vm).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// CPU cores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cores: Option<u64>,
    /// Memory in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<i64>,
    /// Storage pool for the root volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    // ── lxc ──
    /// LXC template volume id (e.g. `local:vztmpl/debian-12-standard_*.tar.zst`). Required for lxc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ostemplate: Option<String>,
    /// Root password / initial credential for the lxc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Root volume size in GiB, allocated on `storage` (`rootfs = <storage>:<gb>`). Requires `storage`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_gb: Option<u64>,
    /// Swap in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub swap: Option<u64>,
    /// Run the container unprivileged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unprivileged: Option<bool>,
    /// Container features (`nesting`/`keyctl` are what Docker needs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub features: Option<LxcFeatures>,
    /// Network interfaces, rendered in order as `net0`, `net1`, ...
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net: Vec<LxcNet>,
    /// Space-separated DNS server IPs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nameserver: Option<String>,
    /// DNS search domains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub searchdomain: Option<String>,
    /// Start the container when the node boots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onboot: Option<bool>,
    /// Boot ordering relative to other guests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<StartupOrder>,
    /// Container timezone (e.g. `America/Denver`, or `host`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// Mount points, rendered in order as `mp0`, `mp1`, ...
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<LxcMount>,
    /// Hookscript volume id (e.g. `local:snippets/hook.sh`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hookscript: Option<String>,
    /// Authorized SSH public keys for root, newline-separated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_public_keys: Option<String>,
    // ── vm ──
    /// Install ISO volume id for a vm (mapped to `cdrom`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso: Option<String>,
    /// RAM held back for the host by the over-allocation guard; default 4096.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_reserve_mib: Option<u64>,
}

/// LXC `features` flags; unset flags are omitted.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct LxcFeatures {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nesting: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyctl: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuse: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mknod: Option<bool>,
    /// Allowed mount fs types, `;`-separated (e.g. `nfs;cifs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount: Option<String>,
}

/// One LXC network interface (`netN`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct LxcNet {
    /// Interface name inside the container; omitted → `eth<N>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub bridge: String,
    /// IPv4 CIDR, `dhcp`, or `manual`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gw: Option<String>,
    /// IPv6 CIDR, `auto`, `dhcp`, or `manual`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gw6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hwaddr: Option<String>,
    /// VLAN tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u64>,
}

/// One LXC mount point (`mpN`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct LxcMount {
    /// Host path (bind mount), existing volume id, or `<storage>:<gb>` to allocate.
    pub volume: String,
    /// Path inside the container.
    pub mp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ro: Option<bool>,
    /// Include in vzdump backups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<bool>,
}

/// PVE `startup` order spec (`order=<n>,up=<s>,down=<s>`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct StartupOrder {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<u64>,
    /// Seconds to wait after starting before the next guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<u64>,
    /// Seconds to wait for shutdown before the next guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<u64>,
}

fn flag(b: bool) -> u8 {
    u8::from(b)
}

fn property_string(parts: Vec<(&str, Option<String>)>) -> String {
    parts
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| format!("{k}={v}")))
        .collect::<Vec<_>>()
        .join(",")
}

impl LxcFeatures {
    fn render(&self) -> String {
        property_string(vec![
            ("nesting", self.nesting.map(|b| flag(b).to_string())),
            ("keyctl", self.keyctl.map(|b| flag(b).to_string())),
            ("fuse", self.fuse.map(|b| flag(b).to_string())),
            ("mknod", self.mknod.map(|b| flag(b).to_string())),
            ("mount", self.mount.clone()),
        ])
    }
}

impl LxcNet {
    fn render(&self, index: usize) -> String {
        property_string(vec![
            (
                "name",
                Some(self.name.clone().unwrap_or_else(|| format!("eth{index}"))),
            ),
            ("bridge", Some(self.bridge.clone())),
            ("ip", self.ip.clone()),
            ("gw", self.gw.clone()),
            ("ip6", self.ip6.clone()),
            ("gw6", self.gw6.clone()),
            ("hwaddr", self.hwaddr.clone()),
            ("tag", self.tag.map(|t| t.to_string())),
            ("firewall", self.firewall.map(|b| flag(b).to_string())),
            ("mtu", self.mtu.map(|m| m.to_string())),
        ])
    }
}

impl LxcMount {
    fn render(&self) -> String {
        let mut s = self.volume.clone();
        let rest = property_string(vec![
            ("mp", Some(self.mp.clone())),
            ("ro", self.ro.map(|b| flag(b).to_string())),
            ("backup", self.backup.map(|b| flag(b).to_string())),
        ]);
        s.push(',');
        s.push_str(&rest);
        s
    }
}

impl StartupOrder {
    fn render(&self) -> String {
        property_string(vec![
            ("order", self.order.map(|n| n.to_string())),
            ("up", self.up.map(|n| n.to_string())),
            ("down", self.down.map(|n| n.to_string())),
        ])
    }
}

/// Typed response for a successful `provision` / `destroy`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct ProvisionResponse {
    pub endpoint: String,
    pub node: String,
    pub kind: String,
    pub vmid: u64,
    /// Proxmox task UPID for the async operation, when returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upid: Option<String>,
}

/// Optional payload for `Update { action: "backup" }`. Every field defaults, so
/// the core pre-mutation guard (which dispatches `backup` with no payload) drives
/// a minimal snapshot vzdump to the node's default backup storage.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
pub struct BackupPayload {
    /// PVE storage to write the archive to. `None` → the first backup-content
    /// storage on the guest's node (a system-owned WHERE, per the storage layer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    /// vzdump mode: `snapshot` (default, no downtime) | `suspend` | `stop`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Optional notes-template recorded on the backup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

// ── helpers ────────────────────────────────────────────────────────────────

fn manager_for(endpoint: &str) -> String {
    UnitId::scoped_manager("proxmox", endpoint)
}

/// Extract the endpoint name from a `proxmox@<endpoint>` manager string, using
/// the core `<base>@<scope>` convention so the split lives in one place.
fn endpoint_of(id: &UnitId) -> Result<String> {
    match id.manager_scope() {
        ("proxmox", Some(endpoint)) => Ok(endpoint.to_string()),
        _ => Err(anyhow!("not a proxmox unit manager: {}", id.manager)),
    }
}

fn kind_from_str(s: &str) -> Result<GuestKind> {
    match s {
        KIND_VM | "qemu" => Ok(GuestKind::Qemu),
        KIND_LXC | "container" => Ok(GuestKind::Lxc),
        other => Err(anyhow!(
            "unknown proxmox kind '{other}' (expected vm | lxc)"
        )),
    }
}

fn kind_str(k: GuestKind) -> &'static str {
    match k {
        GuestKind::Qemu => KIND_VM,
        GuestKind::Lxc => KIND_LXC,
    }
}

// ── config-standard guards (MINIMAL-BACKUP.md §4.4) ──────────────────────────

/// Baseline provisioning invariants per guest kind — conservative, universal
/// floors a well-formed guest must clear. orca refuses to create (or auto-raises)
/// a guest below these, the typed replacement for a guest updater's ad-hoc
/// "under-provisioned / may cause data loss" prompt. Fleet-specific tightening
/// (higher floors, console/update requirements) layers on later via config.
/// A guest's declared minimal state. proxmox's backup is `vzdump`, which images
/// the whole guest — its definition plus its rootfs — so the spec reflects that
/// (both strategies, no explicit include: the whole guest is the archive). Bulk
/// data kept on separate mounts is excluded by keeping it off the guest's disks,
/// not by this spec; narrowing to a paths-only minimal is future work.
fn guest_backup_spec() -> plugin_toolkit::contract::backup::BackupSpec {
    use plugin_toolkit::contract::backup::{BackupSpec, BackupStrategy};
    BackupSpec {
        include: Vec::new(),
        exclude: Vec::new(),
        strategies: vec![BackupStrategy::Definition, BackupStrategy::Rootfs],
    }
}

fn guest_guard(kind: GuestKind) -> UnitGuard {
    match kind {
        GuestKind::Lxc => UnitGuard::min_resources(KIND_LXC, 1, 512),
        GuestKind::Qemu => UnitGuard::min_resources(KIND_VM, 1, 1024),
    }
}

/// Observed facts for a live guest: resources from its cluster-resource row,
/// console and update command from its probe when it has one.
fn facts_of(g: &GuestSummary) -> UnitFacts {
    crate::guest_standard::unit_facts(
        g.maxcpu.map(|c| c.round() as u32),
        g.maxmem.map(|b| (b.max(0) as u64) / (1024 * 1024)),
        g.standard.as_ref(),
    )
}

/// The guard a live guest is held to: the guest standard once probed, the
/// resource floor otherwise.
fn live_guard(kind: GuestKind, g: &GuestSummary) -> UnitGuard {
    match g.standard {
        Some(_) => crate::guest_standard::standard_guard(guest_guard(kind)),
        None => guest_guard(kind),
    }
}

/// Facts a provision request *will* produce, so the guard can auto-raise or
/// refuse an under-provisioned guest before it is created.
fn facts_of_provision(p: &ProvisionPayload) -> UnitFacts {
    UnitFacts {
        cpu: p.cores.map(|c| c as u32),
        mem_mb: p.memory.map(|m| m.max(0) as u64),
        has_root_console: false,
        has_update_command: false,
    }
}

/// Enumerate qemu + lxc guests for one endpoint via `/cluster/resources`.
async fn guests_for_endpoint(
    client: &generated::Client,
    endpoint: &str,
) -> Result<Vec<GuestSummary>> {
    let items = client
        .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
        .await
        .map_err(|e| anyhow!("cluster resources: {e}"))?
        .into_inner();
    let mut out = Vec::new();
    for r in items {
        let kind = match r.type_ {
            gtypes::GetResourcesClusterResourcesResponseItemType::Qemu => GuestKind::Qemu,
            gtypes::GetResourcesClusterResourcesResponseItemType::Lxc => GuestKind::Lxc,
            _ => continue,
        };
        let (Some(node), Some(vmid)) = (r.node, r.vmid) else {
            continue;
        };
        if node.is_empty() || vmid <= 0 {
            continue;
        }
        let vmid = vmid as u64;
        out.push(GuestSummary {
            endpoint: endpoint.to_string(),
            cluster: None,
            node,
            kind: kind_str(kind).to_string(),
            vmid,
            name: r
                .name
                .unwrap_or_else(|| format!("{}-{}", kind_str(kind), vmid)),
            status: r.status,
            cpu: r.cpu,
            maxcpu: r.maxcpu,
            mem: r.mem,
            maxmem: r.maxmem,
            guard_violations: Vec::new(),
            standard: None,
        });
    }
    // Stamp each guest's guard compliance so the unit surface shows breaches.
    for g in &mut out {
        if let Ok(k) = kind_from_str(&g.kind) {
            g.guard_violations = live_guard(k, g)
                .check(&facts_of(g))
                .iter()
                .map(GuardViolation::reason)
                .collect();
        }
    }
    Ok(out)
}

/// All guests across every enabled endpoint. A failing endpoint is logged and
/// skipped so one bad host doesn't blank the whole fleet's units.
async fn all_guests() -> Result<Vec<GuestSummary>> {
    Ok(
        crate::tools::for_each_enabled_endpoint("units", |cfg, ep| async move {
            let client = cfg.build_generated_client()?;
            let mut v = guests_for_endpoint(&client, &ep.name).await?;
            // One cluster-status probe per endpoint stamps the cluster name onto
            // every guest, so the canonical id collapses the same guest seen from
            // all member nodes. A standalone host (or a probe failure) leaves it
            // None → canonical falls back to the endpoint.
            let cluster = match crate::cluster::fetch_cluster_status(&client).await {
                Ok(s) => s.name,
                Err(e) => {
                    tracing::debug!(endpoint = %ep.name, error = %e, "proxmox units: cluster_status probe failed; canonical falls back to endpoint");
                    None
                }
            };
            for g in &mut v {
                g.cluster = cluster.clone();
            }
            Ok(v)
        })
        .await,
    )
}

/// Resolve the node a `(kind, vmid)` currently runs on for one endpoint.
async fn resolve_node(client: &generated::Client, kind: GuestKind, vmid: u64) -> Result<String> {
    let guests = guests_for_endpoint(client, "").await?;
    guests
        .into_iter()
        .find(|g| g.vmid == vmid && g.kind == kind_str(kind))
        .map(|g| g.node)
        .ok_or_else(|| anyhow!("{} vmid {vmid} not found in cluster", kind_str(kind)))
}

/// The storage a `backup` writes to when the payload names none: the first
/// enabled backup-content storage on `node`. Errors (rather than guessing) if the
/// node exposes no backup storage — a clear signal to configure one or pass it.
async fn default_backup_storage(client: &generated::Client, node: &str) -> Result<String> {
    let storages = client
        .get_index_nodes_node_storage(node, Some("backup"), Some(true), None, None, None)
        .await
        .map_err(|e| anyhow!("list backup storages on {node}: {e}"))?
        .into_inner();
    storages
        .into_iter()
        .find(|s| s.content.split(',').any(|c| c.trim() == "backup"))
        .map(|s| s.storage)
        .ok_or_else(|| {
            anyhow!("no backup-content storage on node {node}; pass storage in the backup payload")
        })
}

/// Poll a PVE task (vzdump / restore) to completion. A backup is a prerequisite
/// of the mutation it guards, so orca must *wait* for it and fail loudly on a
/// non-`OK` exit — a silently-running or failed task must never let a mutation
/// proceed. Bounded by `deadline`; returns the terminal exit status text.
async fn wait_for_task(
    client: &generated::Client,
    node: &str,
    upid: &str,
    deadline: plugin_toolkit::time::Deadline,
) -> Result<String> {
    loop {
        let status = client
            .get_read_task_status_nodes_node_tasks_upid_status(node, upid)
            .await
            .map_err(|e| anyhow!("task status {upid} on {node}: {e}"))?
            .into_inner();
        // `status` is Running until the task stops; then `exitstatus` is set.
        use gtypes::GetReadTaskStatusNodesNodeTasksUpidStatusResponseStatus as TaskStatus;
        if !matches!(status.status, TaskStatus::Running) {
            let exit = status.exitstatus.unwrap_or_default();
            if exit == "OK" {
                return Ok(exit);
            }
            return Err(anyhow!("task {upid} on {node} failed: {exit}"));
        }
        if deadline.reached() {
            return Err(anyhow!(
                "task {upid} on {node} did not finish before deadline"
            ));
        }
        plugin_toolkit::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// Resolve a completed vzdump task to the archive it produced by scanning its
/// log for the `creating … archive '<path>'` line PVE emits. This turns the
/// task UPID into a concrete restore locator (an absolute archive path the
/// restore create call accepts as `archive` / `ostemplate`).
async fn archive_from_task_log(
    client: &generated::Client,
    node: &str,
    upid: &str,
) -> Result<String> {
    let lines = client
        .get_read_task_log_nodes_node_tasks_upid_log(node, upid, None, None, None)
        .await
        .map_err(|e| anyhow!("task log {upid} on {node}: {e}"))?
        .into_inner();
    lines
        .iter()
        .find_map(|l| parse_archive_line(&l.t))
        .ok_or_else(|| anyhow!("no archive path in vzdump log for task {upid}"))
}

/// Extract the archive path from a vzdump log line, e.g.
/// `INFO: creating vzdump archive '/mnt/pve/backup/dump/vzdump-lxc-100-….tar.zst'`.
/// Split out from the async fetch so it is unit-testable without a client.
fn parse_archive_line(text: &str) -> Option<String> {
    let rest = text.split_once("archive '")?.1;
    let path = rest.split_once('\'')?.0;
    (!path.is_empty()).then(|| path.to_string())
}

impl ProxmoxUnitProvider {
    fn unit_id(g: &GuestSummary) -> UnitId {
        UnitId {
            manager: manager_for(&g.endpoint),
            kind: g.kind.clone(),
            id: g.vmid.to_string(),
            name: g.name.clone(),
        }
    }

    /// Stable cross-endpoint identity: `cluster:<name>/<kind>/<vmid>` when the
    /// endpoint is clustered (so every member node's sighting of the guest
    /// collapses to one unit), else `endpoint:<name>/<kind>/<vmid>` for a
    /// standalone host. Consumed by core's `merge_by_canonical`.
    fn canonical(g: &GuestSummary) -> String {
        match &g.cluster {
            Some(c) => format!("cluster:{c}/{}/{}", g.kind, g.vmid),
            None => format!("endpoint:{}/{}/{}", g.endpoint, g.kind, g.vmid),
        }
    }

    /// Build the list/detail item for a guest: canonical id (for dedup) plus the
    /// discovered datacenter (the PVE cluster name) when clustered, so
    /// `unit.list` consumers can group guests by datacenter.
    fn list_item(g: &GuestSummary) -> ItemOutcome {
        let item = ItemOutcome::new(
            Self::unit_id(g),
            serde_json::to_string(g).unwrap_or_default(),
        )
        .with_canonical(Self::canonical(g));
        match &g.cluster {
            Some(dc) => item.with_datacenter(dc.clone()),
            None => item,
        }
    }

    async fn do_list(&self, args: ListArgs) -> Result<VerbOutcome> {
        let mut guests = all_guests().await?;
        // Kind filter: query.kind == "vm" | "lxc" narrows the fan-out.
        if let Some(k) = args.query.kind.as_deref() {
            guests.retain(|g| g.kind == k);
        }
        // Free-text search over name.
        if let Some(q) = args.query.search.as_deref() {
            let q = q.to_ascii_lowercase();
            guests.retain(|g| g.name.to_ascii_lowercase().contains(&q));
        }
        let items = guests.iter().map(Self::list_item).collect::<Vec<_>>();
        let total = items.len() as u64;
        Ok(VerbOutcome::Items(ItemsOutcome {
            items,
            total: Some(total),
        }))
    }

    async fn do_detail(&self, args: DetailArgs) -> Result<VerbOutcome> {
        let endpoint = endpoint_of(&args.id)?;
        let kind = kind_from_str(&args.id.kind)?;
        let vmid: u64 = args
            .id
            .id
            .parse()
            .map_err(|_| anyhow!("vmid '{}' is not a u64", args.id.id))?;
        let client = crate::tools::make_client(&endpoint).await?;
        let mut guest = guests_for_endpoint(&client, &endpoint)
            .await?
            .into_iter()
            .find(|g| g.vmid == vmid && g.kind == kind_str(kind))
            .ok_or_else(|| anyhow!("{} vmid {vmid} not found on {endpoint}", kind_str(kind)))?;
        // Match the canonical id List produces (cluster-scoped when clustered).
        guest.cluster = crate::cluster::fetch_cluster_status(&client)
            .await
            .ok()
            .and_then(|s| s.name);
        Ok(VerbOutcome::Item(Self::list_item(&guest)))
    }

    async fn do_update(&self, args: UpdateArgs) -> Result<VerbOutcome> {
        if !Self::is_pre_mutation_guard_backup(&args) {
            crate::execute::require_admin(
                &format!("unit.update action={}", args.action),
                args.caller.as_ref(),
            )?;
        }
        // Backup is a first-class managed-unit action (the pre-mutation guard and
        // scheduler both dispatch it) — route it before lifecycle transitions.
        if args.action == ACTION_BACKUP {
            return self.do_backup(&args.id, args.payload).await;
        }
        if args.action == ACTION_RESTORE {
            return self.do_restore(&args.id, args.payload).await;
        }
        if args.action == ACTION_GUEST_UPDATE {
            return self.do_guest_update(&args).await;
        }
        let endpoint = endpoint_of(&args.id)?;
        let kind = kind_from_str(&args.id.kind)?;
        let vmid: u64 = args
            .id
            .id
            .parse()
            .map_err(|_| anyhow!("vmid '{}' is not a u64", args.id.id))?;
        let client = crate::tools::make_client(&endpoint).await?;
        let node = resolve_node(&client, kind, vmid).await?;
        lifecycle(&client, &node, vmid, kind, &args.action).await?;
        Ok(VerbOutcome::Action(ActionOutcome {
            changed: true,
            message: format!("{} {} {vmid} on {node}", args.action, kind_str(kind)),
        }))
    }

    /// orca's pre-mutation guard sends `backup` with no caller and no payload
    /// (orca#704), so that exact shape is let through without an admin caller.
    fn is_pre_mutation_guard_backup(args: &UpdateArgs) -> bool {
        args.action == ACTION_BACKUP
            && args.caller.is_none()
            && args.payload.as_deref().is_none_or(|p| p.trim().is_empty())
    }

    /// Take the guest's minimal backup via `vzdump` and return a [`BackupRef`].
    /// The unit's manager routes this to the owning endpoint over the mesh, so a
    /// backup runs wherever the guest actually lives. Because a backup gates the
    /// mutation that triggered it, this *waits* for the vzdump task and fails on a
    /// non-`OK` exit; the returned locator is the concrete archive path (resolved
    /// from the task log), so a later `restore` can consume it directly.
    async fn do_backup(&self, id: &UnitId, payload: Option<String>) -> Result<VerbOutcome> {
        let endpoint = endpoint_of(id)?;
        let kind = kind_from_str(&id.kind)?;
        let vmid: u64 = id
            .id
            .parse()
            .map_err(|_| anyhow!("vmid '{}' is not a u64", id.id))?;
        let p: BackupPayload = match payload {
            Some(raw) => serde_json::from_str(&raw).map_err(|e| anyhow!("backup payload: {e}"))?,
            None => BackupPayload::default(),
        };
        let client = crate::tools::make_client(&endpoint).await?;
        let node = resolve_node(&client, kind, vmid).await?;
        let storage = match p.storage {
            Some(s) => s,
            None => default_backup_storage(&client, &node).await?,
        };

        let mut body = serde_json::Map::new();
        // vzdump's `vmid` is a string on the wire (it accepts a list).
        body.insert("vmid".into(), json!(vmid.to_string()));
        body.insert("storage".into(), json!(storage));
        body.insert(
            "mode".into(),
            json!(p.mode.as_deref().unwrap_or("snapshot")),
        );
        if let Some(notes) = &p.notes {
            body.insert("notes-template".into(), json!(notes));
        }
        let typed: gtypes::PostVzdumpNodesNodeVzdumpBody =
            serde_json::from_value(serde_json::Value::Object(body))
                .map_err(|e| anyhow!("vzdump body: {e}"))?;
        let upid = client
            .post_vzdump_nodes_node_vzdump(&node, &typed)
            .await
            .map_err(|e| anyhow!("vzdump {} {vmid} on {node}: {e}", kind_str(kind)))?
            .into_inner();

        // A backup gates a mutation — wait for it and fail loudly if it errors.
        let deadline = plugin_toolkit::time::Deadline::after(BACKUP_TASK_DEADLINE);
        wait_for_task(&client, &node, &upid, deadline).await?;
        let archive = archive_from_task_log(&client, &node, &upid).await?;

        let backup = BackupRef {
            locator: archive,
            manager: manager_for(&endpoint),
            timestamp: plugin_toolkit::time::now().unix_seconds(),
            checksum: None,
        };
        Ok(VerbOutcome::Item(ItemOutcome::new(
            id.clone(),
            serde_json::to_string(&backup).unwrap_or_default(),
        )))
    }

    /// The pre-update backup of one LXC, through the same path as the unit
    /// `backup` action.
    pub(crate) async fn backup_lxc(
        &self,
        endpoint: &str,
        ctid: u64,
        storage: Option<&str>,
    ) -> Result<BackupRef> {
        let id = UnitId {
            manager: manager_for(endpoint),
            kind: KIND_LXC.to_string(),
            id: ctid.to_string(),
            name: String::new(),
        };
        let payload = BackupPayload {
            storage: storage.map(str::to_string),
            ..Default::default()
        };
        match self
            .do_backup(&id, Some(serde_json::to_string(&payload)?))
            .await?
        {
            VerbOutcome::Item(item) => serde_json::from_str(&item.payload)
                .map_err(|e| anyhow!("backup ref from vzdump: {e}")),
            _ => Err(anyhow!("backup of lxc {ctid} returned no backup ref")),
        }
    }

    /// `update` on an LXC: a plan unless the payload sets `execute`; then, for
    /// an admin caller, back up and run the in-container updater. Node-local.
    async fn do_guest_update(&self, args: &UpdateArgs) -> Result<VerbOutcome> {
        const TOOL: &str = "unit.update action=update";
        crate::execute::require_admin(TOOL, args.caller.as_ref())?;
        let id = &args.id;
        let endpoint = endpoint_of(id)?;
        if kind_from_str(&id.kind)? != GuestKind::Lxc {
            return Err(anyhow!("the update action is LXC-only"));
        }
        let ctid: u64 = id
            .id
            .parse()
            .map_err(|_| anyhow!("vmid '{}' is not a u64", id.id))?;
        let p: crate::guest_standard::GuestUpdatePayload = match &args.payload {
            Some(raw) => serde_json::from_str(raw).map_err(|e| anyhow!("update payload: {e}"))?,
            None => Default::default(),
        };
        let out: Change<crate::guest_standard::GuestApplied> = if !p.execute {
            Change::Plan(crate::guest_standard::plan_update(
                TOOL, &p, ctid, &p, None,
            )?)
        } else {
            crate::execute::authorize_execute(TOOL, args.caller.as_ref())?;
            crate::lxc_guest::unsupported(ctid)?;
            Change::Applied(
                crate::guest_standard::run_update(
                    &crate::lxc_guest::SeamIo,
                    &crate::guest_standard::UnitBackup { endpoint },
                    ctid,
                    &p,
                )
                .await?,
            )
        };
        Ok(VerbOutcome::Item(ItemOutcome::new(
            id.clone(),
            serde_json::to_string(&out)?,
        )))
    }

    /// Restore the guest in place from a prior [`BackupRef`]. Recreates the same
    /// vmid on its current node from the backup archive, overwriting the existing
    /// guest (`force`); waits for the restore task and fails loudly on error.
    /// Restore-to-a-new-vmid/node is a follow-up — this is the in-place inverse of
    /// [`do_backup`], which the RFC pairs it with.
    async fn do_restore(&self, id: &UnitId, payload: Option<String>) -> Result<VerbOutcome> {
        let endpoint = endpoint_of(id)?;
        let kind = kind_from_str(&id.kind)?;
        let vmid: u64 = id
            .id
            .parse()
            .map_err(|_| anyhow!("vmid '{}' is not a u64", id.id))?;
        let raw = payload.ok_or_else(|| anyhow!("restore requires a payload"))?;
        let p: RestorePayload =
            serde_json::from_str(&raw).map_err(|e| anyhow!("restore payload: {e}"))?;
        if let Some(component) = &p.component {
            // A guest is a single unit; there is no sub-component to scope to.
            return Err(anyhow!(
                "proxmox restore has no component scope (got '{component}')"
            ));
        }
        let archive = p.from.locator;
        if archive.is_empty() {
            return Err(anyhow!("restore backup ref has an empty locator"));
        }
        let client = crate::tools::make_client(&endpoint).await?;
        let node = resolve_node(&client, kind, vmid).await?;

        let mut body = serde_json::Map::new();
        body.insert("vmid".into(), json!(vmid));
        body.insert("force".into(), json!(1));
        body.insert("restore".into(), json!(1));
        let upid = match kind {
            // LXC restore reuses the create endpoint: the archive rides in
            // `ostemplate` with `restore=1`.
            GuestKind::Lxc => {
                body.insert("ostemplate".into(), json!(archive));
                let typed: gtypes::PostCreateVmNodesNodeLxcBody =
                    serde_json::from_value(serde_json::Value::Object(body))
                        .map_err(|e| anyhow!("lxc restore body: {e}"))?;
                client
                    .post_create_vm_nodes_node_lxc(&node, &typed)
                    .await
                    .map_err(|e| anyhow!("lxc restore {vmid} on {node}: {e}"))?
                    .into_inner()
            }
            // QEMU restore rides in `archive`.
            GuestKind::Qemu => {
                body.insert("archive".into(), json!(archive));
                let typed: gtypes::PostCreateVmNodesNodeQemuBody =
                    serde_json::from_value(serde_json::Value::Object(body))
                        .map_err(|e| anyhow!("qemu restore body: {e}"))?;
                client
                    .post_create_vm_nodes_node_qemu(&node, &typed)
                    .await
                    .map_err(|e| anyhow!("qemu restore {vmid} on {node}: {e}"))?
                    .into_inner()
            }
        };
        if !upid.is_empty() {
            let deadline = plugin_toolkit::time::Deadline::after(RESTORE_TASK_DEADLINE);
            wait_for_task(&client, &node, &upid, deadline).await?;
        }
        Ok(VerbOutcome::Item(ItemOutcome::new(
            id.clone(),
            json!({ "restored": vmid, "node": node }).to_string(),
        )))
    }

    /// Not admin-checked here: `CreateArgs` carries no caller identity yet
    /// (orca#788), so this relies on orca's central role gate.
    async fn do_create(&self, args: CreateArgs) -> Result<VerbOutcome> {
        if args.action != "provision" {
            return Err(anyhow!("unknown proxmox create action: {}", args.action));
        }
        let raw = args
            .payload
            .ok_or_else(|| anyhow!("provision requires a payload"))?;
        let p: ProvisionPayload =
            serde_json::from_str(&raw).map_err(|e| anyhow!("provision payload: {e}"))?;
        let name = p.name.clone();
        let resp = self.provision_guest(p).await?;
        Ok(VerbOutcome::Item(ItemOutcome::new(
            UnitId {
                manager: manager_for(&resp.endpoint),
                kind: resp.kind.clone(),
                id: resp.vmid.to_string(),
                name: name.unwrap_or_else(|| format!("{}-{}", resp.kind, resp.vmid)),
            },
            serde_json::to_string(&resp).unwrap_or_default(),
        )))
    }

    /// Provision one guest from a typed [`ProvisionPayload`], returning the
    /// [`ProvisionResponse`]. This is the shared core of `create`/`upsert` AND
    /// the generic `deploy_target` adapter (`crate::deploy`), so the config-guard
    /// auto-raise, nextid allocation, and PVE create call live in exactly one
    /// place — the deploy front door delegates here rather than duplicating the
    /// create path.
    pub(crate) async fn provision_guest(
        &self,
        mut p: ProvisionPayload,
    ) -> Result<ProvisionResponse> {
        let kind = kind_from_str(&p.kind)?;

        // Config-standard guard (§4.4): auto-raise under-min resources to the
        // kind's floor, refuse on anything that can't be fixed by editing the
        // spec. Prevents provisioning an under-provisioned guest in the first
        // place — the orca-owned version of the guest updater's warning.
        let (fixable, refuse) =
            partition_violations(guest_guard(kind).check(&facts_of_provision(&p)));
        if !refuse.is_empty() {
            let reasons = refuse
                .iter()
                .map(GuardViolation::reason)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(anyhow!(
                "provision of {} refused by guard: {reasons}",
                kind_str(kind)
            ));
        }
        for v in &fixable {
            match v {
                GuardViolation::UnderCpu { min, .. } => {
                    p.cores = Some(p.cores.unwrap_or(0).max(*min as u64));
                }
                GuardViolation::UnderMem { min, .. } => {
                    p.memory = Some(p.memory.unwrap_or(0).max(*min as i64));
                }
                _ => {}
            }
        }

        crate::memory::guard_create(
            &p.endpoint,
            &p.node,
            p.memory
                .map_or(crate::memory::PVE_DEFAULT_MEMORY_MIB, |m| m.max(0) as u64),
            p.host_reserve_mib
                .unwrap_or(crate::memory::MemoryThresholds::default().reserve_mib),
        )
        .await
        .map_err(|e| anyhow!("provision refused: {e}"))?;

        let cfg = crate::tools::resolve_config(&p.endpoint).await?;
        let client = cfg.build_generated_client()?;

        let vmid = match p.vmid {
            Some(v) => v,
            None => client
                .get_nextid_cluster_nextid(None)
                .await
                .map_err(|e| anyhow!("nextid: {e}"))?
                .into_inner() as u64,
        };

        let upid = provision(&cfg, &p, kind, vmid).await?;
        Ok(ProvisionResponse {
            endpoint: p.endpoint.clone(),
            node: p.node.clone(),
            kind: kind_str(kind).to_string(),
            vmid,
            upid,
        })
    }

    /// Run a lifecycle transition against the guest identified by `name` on
    /// `endpoint`. The generic `deploy_target` surface addresses a workload by
    /// its stable name, whereas PVE lifecycle is keyed by `(node, vmid)`; this
    /// resolves the name → the live guest's `(node, vmid)` on that endpoint and
    /// drives [`lifecycle`], returning the resolved `(vmid, node)`. Fails loudly
    /// when no guest of that kind+name exists on the endpoint.
    pub(crate) async fn lifecycle_by_name(
        &self,
        endpoint: &str,
        kind: GuestKind,
        name: &str,
        action: &str,
    ) -> Result<(u64, String)> {
        let client = crate::tools::make_client(endpoint).await?;
        let guest = guests_for_endpoint(&client, endpoint)
            .await?
            .into_iter()
            .find(|g| g.name == name && g.kind == kind_str(kind))
            .ok_or_else(|| anyhow!("{} named '{name}' not found on {endpoint}", kind_str(kind)))?;
        lifecycle(&client, &guest.node, guest.vmid, kind, action).await?;
        Ok((guest.vmid, guest.node))
    }

    /// Resolve the guest named `name` (kind-filtered) on `endpoint` to its full
    /// summary, or `None` when absent. The name→guest resolution the generic
    /// deploy-target `status`/`adopt` paths share: they observe rather than
    /// transition, so they need the whole summary (including its `status`), not
    /// just the `(vmid, node)` [`lifecycle_by_name`](Self::lifecycle_by_name) returns.
    pub(crate) async fn find_guest_by_name(
        &self,
        endpoint: &str,
        kind: GuestKind,
        name: &str,
    ) -> Result<Option<GuestSummary>> {
        let client = crate::tools::make_client(endpoint).await?;
        Ok(guests_for_endpoint(&client, endpoint)
            .await?
            .into_iter()
            .find(|g| g.name == name && g.kind == kind_str(kind)))
    }

    /// Resolve a guest by its native `vmid` (kind-filtered) on `endpoint`. The
    /// vmid-keyed counterpart of [`find_guest_by_name`](Self::find_guest_by_name)
    /// for `adopt`, whose native id is a PVE vmid.
    pub(crate) async fn find_guest_by_vmid(
        &self,
        endpoint: &str,
        kind: GuestKind,
        vmid: u64,
    ) -> Result<Option<GuestSummary>> {
        let client = crate::tools::make_client(endpoint).await?;
        Ok(guests_for_endpoint(&client, endpoint)
            .await?
            .into_iter()
            .find(|g| g.vmid == vmid && g.kind == kind_str(kind)))
    }

    /// Destroy the guest named `name` (kind-filtered) on `endpoint`: resolve
    /// name→`(node, vmid)` then issue the PVE destroy. Fails loudly when absent —
    /// the retire-half of a transfer must never silently no-op. Returns the
    /// resolved `(vmid, node)`. Mirrors [`do_delete`](Self::do_delete)'s destroy
    /// call, keyed by name instead of a `UnitId`.
    pub(crate) async fn destroy_by_name(
        &self,
        endpoint: &str,
        kind: GuestKind,
        name: &str,
    ) -> Result<(u64, String)> {
        let client = crate::tools::make_client(endpoint).await?;
        let guest = guests_for_endpoint(&client, endpoint)
            .await?
            .into_iter()
            .find(|g| g.name == name && g.kind == kind_str(kind))
            .ok_or_else(|| anyhow!("{} named '{name}' not found on {endpoint}", kind_str(kind)))?;
        let v = guest.vmid as i64;
        let res = match kind {
            GuestKind::Qemu => client
                .delete_destroy_vm_nodes_node_qemu_vmid(&guest.node, v, None, None, None)
                .await
                .map(|_| ()),
            GuestKind::Lxc => client
                .delete_destroy_vm_nodes_node_lxc_vmid(&guest.node, v, None, None, None)
                .await
                .map(|_| ()),
        };
        res.map_err(|e| anyhow!("destroy {} {}: {e}", kind_str(kind), guest.vmid))?;
        Ok((guest.vmid, guest.node))
    }

    /// Idempotent create-or-ensure for a guest keyed by vmid. Per the `Upsert`
    /// contract an upsert succeeds whether or not the item already exists. A
    /// running VM/LXC must never be silently destroyed to "replace" it, so the
    /// safe interpretation is *ensure present*: provision when the guest is
    /// absent, no-op (unchanged) when it already exists. The payload is the same
    /// [`ProvisionPayload`] `create`/provision consumes.
    async fn do_upsert(&self, args: UpsertArgs) -> Result<VerbOutcome> {
        crate::execute::require_admin("unit.upsert", args.caller.as_ref())?;
        let raw = args
            .payload
            .ok_or_else(|| anyhow!("upsert requires a payload"))?;
        let p: ProvisionPayload =
            serde_json::from_str(&raw).map_err(|e| anyhow!("upsert payload: {e}"))?;
        let kind = kind_from_str(&p.kind)?;
        let client = crate::tools::make_client(&p.endpoint).await?;

        // Target vmid: explicit in the payload, else the unit key.
        let vmid = p.vmid.or_else(|| args.id.id.parse::<u64>().ok());

        // Already present → ensure-present is a no-op (idempotent success).
        if let Some(v) = vmid
            && resolve_node(&client, kind, v).await.is_ok()
        {
            return Ok(VerbOutcome::Action(ActionOutcome {
                changed: false,
                message: format!("{} {v} already present", kind_str(kind)),
            }));
        }

        // Absent → provision through the same path as `create`.
        self.do_create(CreateArgs {
            action: "provision".to_string(),
            payload: Some(raw),
            caller: args.caller,
        })
        .await
    }

    async fn do_delete(&self, args: DeleteArgs) -> Result<VerbOutcome> {
        crate::execute::require_admin("unit.delete", args.caller.as_ref())?;
        let endpoint = endpoint_of(&args.id)?;
        let kind = kind_from_str(&args.id.kind)?;
        let vmid: u64 = args
            .id
            .id
            .parse()
            .map_err(|_| anyhow!("vmid '{}' is not a u64", args.id.id))?;
        let client = crate::tools::make_client(&endpoint).await?;
        let node = resolve_node(&client, kind, vmid).await?;
        let v = vmid as i64;
        let res = match kind {
            GuestKind::Qemu => client
                .delete_destroy_vm_nodes_node_qemu_vmid(&node, v, None, None, None)
                .await
                .map(|_| ()),
            GuestKind::Lxc => client
                .delete_destroy_vm_nodes_node_lxc_vmid(&node, v, None, None, None)
                .await
                .map(|_| ()),
        };
        res.map_err(|e| anyhow!("destroy {} {vmid}: {e}", kind_str(kind)))?;
        Ok(VerbOutcome::Action(ActionOutcome {
            changed: true,
            message: format!("destroyed {} {vmid} on {node}", kind_str(kind)),
        }))
    }
}

/// One lifecycle transition. The generated method names differ only by kind +
/// action, so this is the single place that fans across the eight combinations.
async fn lifecycle(
    client: &generated::Client,
    node: &str,
    vmid: u64,
    kind: GuestKind,
    action: &str,
) -> Result<()> {
    let v = vmid as i64;
    let res = match (kind, action) {
        (GuestKind::Qemu, "start") => client
            .post_vm_start_nodes_node_qemu_vmid_status_start(node, v, &Default::default())
            .await
            .map(|_| ()),
        (GuestKind::Qemu, "stop") => client
            .post_vm_stop_nodes_node_qemu_vmid_status_stop(node, v, &Default::default())
            .await
            .map(|_| ()),
        (GuestKind::Qemu, "shutdown") => client
            .post_vm_shutdown_nodes_node_qemu_vmid_status_shutdown(node, v, &Default::default())
            .await
            .map(|_| ()),
        (GuestKind::Qemu, "reboot") => client
            .post_vm_reboot_nodes_node_qemu_vmid_status_reboot(node, v, &Default::default())
            .await
            .map(|_| ()),
        (GuestKind::Lxc, "start") => client
            .post_vm_start_nodes_node_lxc_vmid_status_start(node, v, &Default::default())
            .await
            .map(|_| ()),
        (GuestKind::Lxc, "stop") => client
            .post_vm_stop_nodes_node_lxc_vmid_status_stop(node, v, &Default::default())
            .await
            .map(|_| ()),
        (GuestKind::Lxc, "shutdown") => client
            .post_vm_shutdown_nodes_node_lxc_vmid_status_shutdown(node, v, &Default::default())
            .await
            .map(|_| ()),
        (GuestKind::Lxc, "reboot") => client
            .post_vm_reboot_nodes_node_lxc_vmid_status_reboot(node, v, &Default::default())
            .await
            .map(|_| ()),
        (_, other) => {
            return Err(anyhow!(
                "unknown lifecycle action '{other}' (expected start | stop | shutdown | reboot)"
            ));
        }
    };
    res.map_err(|e| anyhow!("{action} {} {vmid}: {e}", kind_str(kind)))
}

/// Every created VM gets the guest agent channel: it cannot be hot-added to a
/// running VM, and without it the guest can't be exec'd into or fstrim its disks.
const QEMU_AGENT_DEFAULT: &str = "enabled=1";

/// The create body as JSON (only set fields); [`provision`] deserializes it into
/// the generated typed body so required-field validation runs against the PVE schema.
fn create_body(
    p: &ProvisionPayload,
    kind: GuestKind,
    vmid: u64,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let mut body = serde_json::Map::new();
    body.insert("vmid".into(), json!(vmid));
    if let Some(cores) = p.cores {
        body.insert("cores".into(), json!(cores));
    }
    if let Some(memory) = p.memory {
        body.insert("memory".into(), json!(memory));
    }
    if let Some(storage) = &p.storage {
        body.insert("storage".into(), json!(storage));
    }
    match kind {
        GuestKind::Lxc => {
            let ostemplate = p
                .ostemplate
                .as_deref()
                .ok_or_else(|| anyhow!("lxc provision requires 'ostemplate'"))?;
            body.insert("ostemplate".into(), json!(ostemplate));
            if let Some(name) = &p.name {
                body.insert("hostname".into(), json!(name));
            }
            if let Some(password) = &p.password {
                body.insert("password".into(), json!(password));
            }
            if let Some(gb) = p.rootfs_gb {
                let storage = p
                    .storage
                    .as_deref()
                    .ok_or_else(|| anyhow!("lxc 'rootfs_gb' requires 'storage'"))?;
                body.insert("rootfs".into(), json!(format!("{storage}:{gb}")));
            }
            if let Some(swap) = p.swap {
                body.insert("swap".into(), json!(swap));
            }
            if let Some(unprivileged) = p.unprivileged {
                body.insert("unprivileged".into(), json!(flag(unprivileged)));
            }
            if let Some(features) = &p.features {
                body.insert("features".into(), json!(features.render()));
            }
            for (i, net) in p.net.iter().enumerate() {
                body.insert(format!("net{i}"), json!(net.render(i)));
            }
            if let Some(nameserver) = &p.nameserver {
                body.insert("nameserver".into(), json!(nameserver));
            }
            if let Some(searchdomain) = &p.searchdomain {
                body.insert("searchdomain".into(), json!(searchdomain));
            }
            if let Some(onboot) = p.onboot {
                body.insert("onboot".into(), json!(flag(onboot)));
            }
            if let Some(startup) = &p.startup {
                body.insert("startup".into(), json!(startup.render()));
            }
            if let Some(timezone) = &p.timezone {
                body.insert("timezone".into(), json!(timezone));
            }
            for (i, mount) in p.mounts.iter().enumerate() {
                body.insert(format!("mp{i}"), json!(mount.render()));
            }
            if let Some(hookscript) = &p.hookscript {
                body.insert("hookscript".into(), json!(hookscript));
            }
            if let Some(keys) = &p.ssh_public_keys {
                body.insert("ssh-public-keys".into(), json!(keys));
            }
        }
        GuestKind::Qemu => {
            if let Some(name) = &p.name {
                body.insert("name".into(), json!(name));
            }
            if let Some(iso) = &p.iso {
                body.insert("cdrom".into(), json!(iso));
            }
            body.insert("agent".into(), json!(QEMU_AGENT_DEFAULT));
        }
    }
    Ok(body)
}

fn needs_root_pam(p: &ProvisionPayload) -> bool {
    let features = p.features.as_ref().is_some_and(|f| {
        f.keyctl.is_some() || f.fuse.is_some() || f.mknod.is_some() || f.mount.is_some()
    });
    features || p.hookscript.is_some() || p.mounts.iter().any(|m| m.volume.starts_with('/'))
}

fn upid_of(data: serde_json::Value) -> Result<String> {
    match data {
        serde_json::Value::String(upid) => Ok(upid),
        other => Err(anyhow!(
            "lxc create: expected task UPID string, got {other}"
        )),
    }
}

/// Build the typed create body from the typed payload and POST it.
async fn provision(
    cfg: &crate::Config,
    p: &ProvisionPayload,
    kind: GuestKind,
    vmid: u64,
) -> Result<Option<String>> {
    let map = create_body(p, kind, vmid)?;
    let body = serde_json::Value::Object(map.clone());
    let upid = match kind {
        GuestKind::Lxc => {
            let _: gtypes::PostCreateVmNodesNodeLxcBody =
                serde_json::from_value(body).map_err(|e| anyhow!("lxc create body: {e}"))?;
            let http = if needs_root_pam(p) {
                crate::guest_mount::root_client(&p.endpoint, cfg)
                    .await
                    .map_err(|e| anyhow!("lxc create: {e}"))?
            } else {
                cfg.build_reqwest_client()?
            };
            let url = format!(
                "{}/nodes/{}/lxc",
                cfg.base_url.trim_end_matches('/'),
                crate::backup::enc(&p.node)
            );
            let data =
                crate::backup::post_form_data(&http, &url, &crate::backup::form_pairs(&map, &[]))
                    .await
                    .map_err(|e| anyhow!("lxc create: {e}"))?;
            upid_of(data)?
        }
        GuestKind::Qemu => {
            let typed: gtypes::PostCreateVmNodesNodeQemuBody =
                serde_json::from_value(body).map_err(|e| anyhow!("qemu create body: {e}"))?;
            cfg.build_generated_client()?
                .post_create_vm_nodes_node_qemu(&p.node, &typed)
                .await
                .map_err(|e| anyhow!("qemu create: {e}"))?
                .into_inner()
        }
    };
    // PVE returns the task UPID as the response body string; empty → None.
    Ok(if upid.is_empty() { None } else { Some(upid) })
}

// ── declarations ─────────────────────────────────────────────────────────────

/// Verbs shared by both guest kinds. `provision` payload/response schemas differ
/// only in which fields matter per kind, so one [`ProvisionPayload`] serves both.
fn guest_verbs(kind: GuestKind) -> Vec<VerbDecl> {
    let mut update_actions: Vec<ActionDecl> = ["start", "stop", "shutdown", "reboot"]
        .into_iter()
        .map(|a| ActionDecl {
            action: a.to_string(),
            payload_schema: None,
            response_schema: None,
        })
        .collect();
    // Minimal backup as a managed-unit action: the pre-mutation guard and the
    // scheduler both reach it via `Update { action: "backup" }`, routed to the
    // owning endpoint over the mesh. Optional typed payload; returns a BackupRef.
    update_actions.push(ActionDecl {
        action: ACTION_BACKUP.to_string(),
        payload_schema: Some(schema_for!(BackupPayload)),
        response_schema: Some(schema_for!(BackupRef)),
    });
    // Restore the guest in place from a prior BackupRef — the inverse of backup,
    // reached via `Update { action: "restore" }` and routed the same way.
    update_actions.push(ActionDecl {
        action: ACTION_RESTORE.to_string(),
        payload_schema: Some(schema_for!(RestorePayload)),
        response_schema: None,
    });
    if kind == GuestKind::Lxc {
        update_actions.push(ActionDecl {
            action: ACTION_GUEST_UPDATE.to_string(),
            payload_schema: Some(schema_for!(crate::guest_standard::GuestUpdatePayload)),
            response_schema: Some(schema_for!(Change<crate::guest_standard::GuestApplied>)),
        });
    }
    vec![
        VerbDecl::list(),
        VerbDecl::detail(),
        VerbDecl {
            verb: Verb::Update,
            query_schema: None,
            actions: update_actions,
        },
        VerbDecl {
            verb: Verb::Create,
            query_schema: None,
            actions: vec![ActionDecl {
                action: "provision".into(),
                payload_schema: Some(schema_for!(ProvisionPayload)),
                response_schema: Some(schema_for!(ProvisionResponse)),
            }],
        },
        VerbDecl {
            verb: Verb::Delete,
            query_schema: None,
            actions: vec![],
        },
        // Idempotent ensure-present: provision the guest if absent, no-op if it
        // already exists. Shares the `provision` payload/response schema.
        VerbDecl {
            verb: Verb::Upsert,
            query_schema: None,
            actions: vec![ActionDecl {
                action: "set".into(),
                payload_schema: Some(schema_for!(ProvisionPayload)),
                response_schema: Some(schema_for!(ProvisionResponse)),
            }],
        },
    ]
}

impl UnitProvider for ProxmoxUnitProvider {
    fn name(&self) -> &str {
        "proxmox"
    }

    fn declarations(&self) -> Vec<KindDeclaration> {
        vec![
            KindDeclaration::new(KIND_VM, guest_verbs(GuestKind::Qemu))
                .with_backup_spec(guest_backup_spec()),
            KindDeclaration::new(KIND_LXC, guest_verbs(GuestKind::Lxc))
                .with_backup_spec(guest_backup_spec()),
        ]
    }

    fn units(&self) -> BoxFuture<'_, Result<Vec<UnitDescriptor>>> {
        Box::pin(async move {
            let guests = all_guests().await?;
            Ok(guests
                .iter()
                .map(|g| UnitDescriptor {
                    id: Self::unit_id(g),
                    verbs: vec![
                        Verb::List,
                        Verb::Detail,
                        Verb::Update,
                        Verb::Create,
                        Verb::Delete,
                    ],
                    parent: None,
                })
                .collect())
        })
    }

    fn invoke(&self, args: VerbArgs) -> BoxFuture<'_, Result<VerbOutcome>> {
        Box::pin(async move {
            match args {
                VerbArgs::List(a) => self.do_list(a).await,
                VerbArgs::Detail(a) => self.do_detail(a).await,
                VerbArgs::Update(a) => self.do_update(a).await,
                VerbArgs::Create(a) => self.do_create(a).await,
                VerbArgs::Delete(a) => self.do_delete(a).await,
                VerbArgs::Upsert(a) => self.do_upsert(a).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::CallerIdentity;

    fn guest(endpoint: &str, cluster: Option<&str>, kind: &str, vmid: u64) -> GuestSummary {
        GuestSummary {
            endpoint: endpoint.into(),
            cluster: cluster.map(Into::into),
            node: "n1".into(),
            kind: kind.into(),
            vmid,
            name: "g".into(),
            status: None,
            cpu: None,
            maxcpu: None,
            mem: None,
            maxmem: None,
            guard_violations: Vec::new(),
            standard: None,
        }
    }

    #[test]
    fn canonical_is_cluster_scoped_when_clustered() {
        // Same guest seen from three member-node endpoints → identical canonical
        // id, so core's merge collapses them to one unit.
        let a = ProxmoxUnitProvider::canonical(&guest("node-a", Some("cluster-a"), "lxc", 100));
        let b = ProxmoxUnitProvider::canonical(&guest("node-b", Some("cluster-a"), "lxc", 100));
        assert_eq!(a, "cluster:cluster-a/lxc/100");
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_falls_back_to_endpoint_for_standalone() {
        let c = ProxmoxUnitProvider::canonical(&guest("pve1", None, "vm", 200));
        assert_eq!(c, "endpoint:pve1/vm/200");
    }

    #[test]
    fn list_item_sets_datacenter_from_cluster() {
        let clustered =
            ProxmoxUnitProvider::list_item(&guest("node-a", Some("cluster-a"), "lxc", 100));
        assert_eq!(clustered.datacenter.as_deref(), Some("cluster-a"));
        // Standalone host → no datacenter grouping.
        let standalone = ProxmoxUnitProvider::list_item(&guest("pve1", None, "vm", 200));
        assert_eq!(standalone.datacenter, None);
    }

    #[test]
    fn manager_roundtrips_endpoint() {
        let id = UnitId {
            manager: manager_for("cluster-a"),
            kind: KIND_LXC.into(),
            id: "100".into(),
            name: "ct".into(),
        };
        assert_eq!(endpoint_of(&id).unwrap(), "cluster-a");
    }

    #[test]
    fn endpoint_of_rejects_foreign_manager() {
        let id = UnitId {
            manager: "docker@host".into(),
            kind: KIND_VM.into(),
            id: "1".into(),
            name: "x".into(),
        };
        assert!(endpoint_of(&id).is_err());
    }

    #[test]
    fn kind_parsing_accepts_aliases() {
        assert_eq!(kind_str(kind_from_str("vm").unwrap()), KIND_VM);
        assert_eq!(kind_str(kind_from_str("qemu").unwrap()), KIND_VM);
        assert_eq!(kind_str(kind_from_str("lxc").unwrap()), KIND_LXC);
        assert_eq!(kind_str(kind_from_str("container").unwrap()), KIND_LXC);
        assert!(kind_from_str("nope").is_err());
    }

    #[test]
    fn declarations_cover_both_kinds_with_five_verbs() {
        let decls = ProxmoxUnitProvider::new().declarations();
        assert_eq!(decls.len(), 2);
        for d in &decls {
            let verbs: Vec<_> = d.verbs.iter().map(|v| v.verb).collect();
            for want in [
                Verb::List,
                Verb::Detail,
                Verb::Update,
                Verb::Create,
                Verb::Delete,
            ] {
                assert!(verbs.contains(&want), "{} missing {want:?}", d.kind);
            }
        }
    }

    #[test]
    fn provision_action_declares_typed_schemas() {
        let decls = ProxmoxUnitProvider::new().declarations();
        let vm = decls.iter().find(|d| d.kind == KIND_VM).unwrap();
        let create = vm.verbs.iter().find(|v| v.verb == Verb::Create).unwrap();
        let provision = create
            .actions
            .iter()
            .find(|a| a.action == "provision")
            .unwrap();
        assert!(provision.payload_schema.is_some());
        assert!(provision.response_schema.is_some());
        let schema = serde_json::to_string(provision.payload_schema.as_ref().unwrap()).unwrap();
        assert!(schema.contains("endpoint"));
        assert!(schema.contains("ostemplate"));
        for field in [
            "rootfs_gb",
            "swap",
            "unprivileged",
            "features",
            "net",
            "nameserver",
            "searchdomain",
            "onboot",
            "startup",
            "timezone",
            "mounts",
            "hookscript",
            "ssh_public_keys",
            "bridge",
            "keyctl",
        ] {
            assert!(schema.contains(field), "schema missing {field}");
        }
    }

    #[test]
    fn guest_guard_flags_underprovisioned_live_guest() {
        // A 1-core / 256 MiB lxc is below the lxc floor (1 core / 512 MiB).
        let mut g = guest("n", None, "lxc", 100);
        g.maxcpu = Some(1.0);
        g.maxmem = Some(256 * 1024 * 1024);
        let violations = guest_guard(GuestKind::Lxc).check(&facts_of(&g));
        assert_eq!(violations.len(), 1, "only memory is under the floor");
        assert!(matches!(
            violations[0],
            GuardViolation::UnderMem { min: 512, .. }
        ));
        // Raise it above the floor → compliant.
        g.maxmem = Some(1024 * 1024 * 1024);
        assert!(guest_guard(GuestKind::Lxc).is_satisfied(&facts_of(&g)));
    }

    #[test]
    fn probed_lxc_is_held_to_the_guest_standard() {
        let mut g = guest("n", None, "lxc", 100);
        g.maxcpu = Some(2.0);
        g.maxmem = Some(1024 * 1024 * 1024);
        assert!(
            live_guard(GuestKind::Lxc, &g)
                .check(&facts_of(&g))
                .is_empty()
        );
        g.standard = Some(crate::guest_standard::StandardFacts {
            os: crate::guest_standard::Os::Debian,
            has_root_console: false,
            has_update_command: true,
            community_updater: false,
            legacy_backup_key: false,
            foreign_gate: false,
            console_drift: Vec::new(),
        });
        assert_eq!(
            live_guard(GuestKind::Lxc, &g).check(&facts_of(&g)),
            vec![GuardViolation::NoRootConsole]
        );
    }

    fn guest_update(
        payload: serde_json::Value,
        caller: Option<CallerIdentity>,
    ) -> Result<VerbOutcome> {
        let args = UpdateArgs {
            id: UnitId {
                manager: manager_for("pve"),
                kind: KIND_LXC.into(),
                id: "116".into(),
                name: String::new(),
            },
            action: ACTION_GUEST_UPDATE.into(),
            payload: Some(payload.to_string()),
            caller,
        };
        // Any capability (config, http, the lxc seams) panics: none may be reached.
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(|cap: &str, raw: &str| panic!("reached capability {cap}: {raw}")),
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(ProxmoxUnitProvider::new().do_guest_update(&args))
            },
        )
    }

    #[test]
    fn update_action_without_execute_is_a_plan_that_touches_nothing() {
        let admin = CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: "admin".into(),
            can_mutate: true,
        };
        let VerbOutcome::Item(item) = guest_update(json!({"updater": "apt"}), Some(admin)).unwrap()
        else {
            panic!()
        };
        let plan: serde_json::Value = serde_json::from_str(&item.payload).unwrap();
        assert_eq!(plan["dryRun"], json!(true), "{plan}");
    }

    #[test]
    fn update_action_dry_run_needs_an_admin_caller() {
        let err = guest_update(json!({"updater": "apt"}), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no caller identity"), "{err}");
        let reader = CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: "read".into(),
            can_mutate: false,
        };
        let err = guest_update(json!({"updater": "apt"}), Some(reader))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires role 'admin'"), "{err}");
    }

    #[test]
    fn update_action_execute_needs_an_admin_caller_before_any_lookup() {
        let err = guest_update(json!({"execute": true}), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no caller identity"), "{err}");
        let reader = CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: "read".into(),
            can_mutate: false,
        };
        let err = guest_update(json!({"execute": true}), Some(reader))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires role 'admin'"), "{err}");
    }

    fn refused<F: std::future::Future<Output = Result<VerbOutcome>>>(fut: F) -> String {
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(|cap: &str, raw: &str| panic!("reached capability {cap}: {raw}")),
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(fut)
            },
        )
        .unwrap_err()
        .to_string()
    }

    fn unit_id() -> UnitId {
        UnitId {
            manager: manager_for("pve"),
            kind: KIND_LXC.into(),
            id: "116".into(),
            name: String::new(),
        }
    }

    fn non_admins() -> [(Option<CallerIdentity>, &'static str); 2] {
        let reader = CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: "read".into(),
            can_mutate: false,
        };
        [
            (None, "no caller identity"),
            (Some(reader), "requires role 'admin'"),
        ]
    }

    #[test]
    fn unit_update_actions_need_an_admin_caller() {
        let p = ProxmoxUnitProvider::new();
        for (action, payload) in [
            ("start", None),
            (ACTION_BACKUP, Some(r#"{"storage":"local"}"#)),
            (ACTION_RESTORE, Some(r#"{"from":{"locator":"x"}}"#)),
        ] {
            for (caller, want) in non_admins() {
                let err = refused(p.do_update(UpdateArgs {
                    id: unit_id(),
                    action: action.into(),
                    payload: payload.map(str::to_string),
                    caller,
                }));
                assert!(err.contains(want), "{action}: {err}");
            }
        }
    }

    #[test]
    fn only_the_callerless_empty_backup_is_the_pre_mutation_guard() {
        let args = |payload: Option<&str>, caller: Option<CallerIdentity>| UpdateArgs {
            id: unit_id(),
            action: ACTION_BACKUP.into(),
            payload: payload.map(str::to_string),
            caller,
        };
        assert!(ProxmoxUnitProvider::is_pre_mutation_guard_backup(&args(
            None, None
        )));
        assert!(ProxmoxUnitProvider::is_pre_mutation_guard_backup(&args(
            Some(""),
            None
        )));
        assert!(!ProxmoxUnitProvider::is_pre_mutation_guard_backup(&args(
            Some("{}"),
            None
        )));
        let [_, (reader, _)] = non_admins();
        assert!(!ProxmoxUnitProvider::is_pre_mutation_guard_backup(&args(
            None, reader
        )));
    }

    #[test]
    fn unit_upsert_and_delete_need_an_admin_caller() {
        let p = ProxmoxUnitProvider::new();
        for (caller, want) in non_admins() {
            let err = refused(p.do_upsert(UpsertArgs {
                id: unit_id(),
                action: "set".into(),
                payload: Some(r#"{"endpoint":"pve","kind":"lxc"}"#.into()),
                caller: caller.clone(),
            }));
            assert!(err.contains(want), "upsert: {err}");
            let err = refused(p.do_delete(DeleteArgs {
                id: unit_id(),
                caller,
            }));
            assert!(err.contains(want), "delete: {err}");
        }
    }

    #[test]
    fn update_action_is_declared_for_lxc_only() {
        let decls = ProxmoxUnitProvider::new().declarations();
        let has = |kind: &str| {
            decls
                .iter()
                .find(|d| d.kind == kind)
                .unwrap()
                .verbs
                .iter()
                .find(|v| v.verb == Verb::Update)
                .unwrap()
                .actions
                .iter()
                .any(|a| a.action == ACTION_GUEST_UPDATE)
        };
        assert!(has(KIND_LXC));
        assert!(!has(KIND_VM));
    }

    const DOCKER_HOST_LXC: &str = r#"{
        "endpoint":"e","node":"thor","kind":"lxc",
        "ostemplate":"local:vztmpl/alpine-3.23-default_20250101_amd64.tar.xz",
        "name":"vidar","cores":4,"memory":4096,"swap":1024,
        "storage":"local-lvm","rootfs_gb":16,"unprivileged":true,
        "features":{"nesting":true,"keyctl":true},
        "net":[{"bridge":"vmbr0","ip":"10.0.0.50/24","gw":"10.0.0.1",
                "hwaddr":"BC:24:11:00:00:01","ip6":"auto"}],
        "nameserver":"10.0.0.201 10.0.0.1","searchdomain":"scottkey.me",
        "onboot":true,"startup":{"order":4,"up":30},
        "timezone":"America/Denver",
        "mounts":[{"volume":"/mnt/data","mp":"/data","backup":false}],
        "hookscript":"local:snippets/hook.sh",
        "ssh_public_keys":"ssh-ed25519 AAAA test"
    }"#;

    #[test]
    fn provision_payload_parses_docker_host_lxc_fields() {
        let p: ProvisionPayload = serde_json::from_str(DOCKER_HOST_LXC).unwrap();
        assert_eq!(p.rootfs_gb, Some(16));
        assert_eq!(p.swap, Some(1024));
        assert_eq!(p.unprivileged, Some(true));
        let f = p.features.as_ref().unwrap();
        assert_eq!(
            (f.nesting, f.keyctl, f.fuse),
            (Some(true), Some(true), None)
        );
        assert_eq!(p.net.len(), 1);
        assert_eq!(p.net[0].bridge, "vmbr0");
        assert_eq!(p.net[0].hwaddr.as_deref(), Some("BC:24:11:00:00:01"));
        assert_eq!(p.nameserver.as_deref(), Some("10.0.0.201 10.0.0.1"));
        assert_eq!(p.searchdomain.as_deref(), Some("scottkey.me"));
        assert_eq!(p.onboot, Some(true));
        let s = p.startup.as_ref().unwrap();
        assert_eq!((s.order, s.up, s.down), (Some(4), Some(30), None));
        assert_eq!(p.timezone.as_deref(), Some("America/Denver"));
        assert_eq!(p.mounts[0].mp, "/data");
        assert_eq!(p.hookscript.as_deref(), Some("local:snippets/hook.sh"));
        assert_eq!(p.ssh_public_keys.as_deref(), Some("ssh-ed25519 AAAA test"));
    }

    #[test]
    fn create_body_renders_docker_host_lxc_property_strings() {
        let p: ProvisionPayload = serde_json::from_str(DOCKER_HOST_LXC).unwrap();
        let body = create_body(&p, GuestKind::Lxc, 120).unwrap();
        let pairs: std::collections::BTreeMap<String, String> =
            crate::backup::form_pairs(&body, &[]).into_iter().collect();
        let want = [
            ("hostname", "vidar"),
            ("rootfs", "local-lvm:16"),
            ("swap", "1024"),
            ("unprivileged", "1"),
            ("features", "nesting=1,keyctl=1"),
            (
                "net0",
                "name=eth0,bridge=vmbr0,ip=10.0.0.50/24,gw=10.0.0.1,ip6=auto,hwaddr=BC:24:11:00:00:01",
            ),
            ("nameserver", "10.0.0.201 10.0.0.1"),
            ("searchdomain", "scottkey.me"),
            ("onboot", "1"),
            ("startup", "order=4,up=30"),
            ("timezone", "America/Denver"),
            ("mp0", "/mnt/data,mp=/data,backup=0"),
            ("hookscript", "local:snippets/hook.sh"),
            ("ssh-public-keys", "ssh-ed25519 AAAA test"),
        ];
        for (k, v) in want {
            assert_eq!(pairs.get(k).map(String::as_str), Some(v), "{k}");
        }
        let _: gtypes::PostCreateVmNodesNodeLxcBody =
            serde_json::from_value(serde_json::Value::Object(body)).unwrap();
    }

    #[test]
    fn root_pam_only_for_privileged_lxc_fields() {
        let base = || -> ProvisionPayload {
            serde_json::from_str(r#"{"endpoint":"e","node":"n","kind":"lxc","ostemplate":"t"}"#)
                .unwrap()
        };
        assert!(!needs_root_pam(&base()));
        let mut p = base();
        p.features = Some(LxcFeatures {
            nesting: Some(true),
            ..Default::default()
        });
        assert!(!needs_root_pam(&p));
        p.features.as_mut().unwrap().keyctl = Some(true);
        assert!(needs_root_pam(&p));
        let mut p = base();
        p.hookscript = Some("local:snippets/h.sh".into());
        assert!(needs_root_pam(&p));
        let mut p = base();
        p.mounts = vec![LxcMount {
            volume: "local-lvm:8".into(),
            mp: "/data".into(),
            ..Default::default()
        }];
        assert!(!needs_root_pam(&p));
        p.mounts[0].volume = "/mnt/data".into();
        assert!(needs_root_pam(&p));
    }

    #[test]
    fn upid_of_rejects_non_string_data() {
        assert_eq!(
            upid_of(json!("UPID:thor:1:2:3:vzcreate:120:root@pam:")).unwrap(),
            "UPID:thor:1:2:3:vzcreate:120:root@pam:"
        );
        assert!(upid_of(json!(null)).is_err());
        assert!(upid_of(json!({})).is_err());
        assert!(upid_of(json!(7)).is_err());
    }

    #[test]
    fn create_body_omits_unset_lxc_fields() {
        let p: ProvisionPayload = serde_json::from_str(
            r#"{"endpoint":"e","node":"n","kind":"lxc","ostemplate":"local:vztmpl/x.tar.zst"}"#,
        )
        .unwrap();
        let body = create_body(&p, GuestKind::Lxc, 120).unwrap();
        let mut keys: Vec<&str> = body.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["ostemplate", "vmid"]);
    }

    #[test]
    fn create_body_rootfs_gb_requires_storage() {
        let p: ProvisionPayload = serde_json::from_str(
            r#"{"endpoint":"e","node":"n","kind":"lxc","ostemplate":"t","rootfs_gb":8}"#,
        )
        .unwrap();
        assert!(create_body(&p, GuestKind::Lxc, 120).is_err());
    }

    #[test]
    fn provision_facts_convert_cores_and_memory() {
        let p: ProvisionPayload = serde_json::from_str(
            r#"{"endpoint":"e","node":"n","kind":"vm","cores":4,"memory":8192}"#,
        )
        .unwrap();
        let f = facts_of_provision(&p);
        assert_eq!(f.cpu, Some(4));
        assert_eq!(f.mem_mb, Some(8192));
        // A 4-core / 8 GiB vm clears the vm floor (1 core / 1 GiB).
        assert!(guest_guard(GuestKind::Qemu).is_satisfied(&f));
    }

    #[test]
    fn backup_action_is_declared_with_typed_schemas() {
        let decls = ProxmoxUnitProvider::new().declarations();
        for kind in [KIND_VM, KIND_LXC] {
            let d = decls.iter().find(|d| d.kind == kind).unwrap();
            let update = d.verbs.iter().find(|v| v.verb == Verb::Update).unwrap();
            let backup = update
                .actions
                .iter()
                .find(|a| a.action == ACTION_BACKUP)
                .unwrap_or_else(|| panic!("{kind} missing backup action"));
            assert!(backup.payload_schema.is_some());
            assert!(backup.response_schema.is_some());
        }
    }

    #[test]
    fn restore_action_is_declared_with_payload_schema() {
        let decls = ProxmoxUnitProvider::new().declarations();
        for kind in [KIND_VM, KIND_LXC] {
            let d = decls.iter().find(|d| d.kind == kind).unwrap();
            let update = d.verbs.iter().find(|v| v.verb == Verb::Update).unwrap();
            let restore = update
                .actions
                .iter()
                .find(|a| a.action == ACTION_RESTORE)
                .unwrap_or_else(|| panic!("{kind} missing restore action"));
            assert!(restore.payload_schema.is_some());
        }
    }

    #[test]
    fn parse_archive_line_extracts_path() {
        let line = "INFO: creating vzdump archive '/mnt/pve/backup/dump/vzdump-lxc-100-2026_07_11.tar.zst'";
        assert_eq!(
            parse_archive_line(line).as_deref(),
            Some("/mnt/pve/backup/dump/vzdump-lxc-100-2026_07_11.tar.zst")
        );
        // Unrelated log lines yield nothing.
        assert!(parse_archive_line("INFO: starting new backup job").is_none());
        // A malformed line with an opening quote but no close yields nothing.
        assert!(parse_archive_line("creating archive 'unterminated").is_none());
    }

    #[test]
    fn restore_payload_round_trips() {
        let raw = r#"{"from":{"locator":"/mnt/pve/backup/dump/vzdump-lxc-100.tar.zst","manager":"proxmox@a","timestamp":1}}"#;
        let p: RestorePayload = serde_json::from_str(raw).unwrap();
        assert_eq!(
            p.from.locator,
            "/mnt/pve/backup/dump/vzdump-lxc-100.tar.zst"
        );
        assert!(p.component.is_none());
    }

    #[test]
    fn backup_payload_defaults_are_all_none() {
        let p = BackupPayload::default();
        assert!(p.storage.is_none() && p.mode.is_none() && p.notes.is_none());
        // Empty JSON (what the guard dispatches) parses to the defaults.
        let p2: BackupPayload = serde_json::from_str("{}").unwrap();
        assert!(p2.storage.is_none());
    }

    #[test]
    fn provision_payload_parses_lxc() {
        let p: ProvisionPayload = serde_json::from_str(
            r#"{"endpoint":"lab","node":"pve1","kind":"lxc","ostemplate":"local:vztmpl/debian.tar.zst","cores":2,"memory":1024}"#,
        )
        .unwrap();
        assert_eq!(p.endpoint, "lab");
        assert_eq!(p.cores, Some(2));
        assert_eq!(p.ostemplate.as_deref(), Some("local:vztmpl/debian.tar.zst"));
    }

    #[test]
    fn qemu_create_body_enables_the_guest_agent() {
        let p: ProvisionPayload = serde_json::from_str(
            r#"{"endpoint":"lab","node":"pve1","kind":"vm","iso":"local:iso/debian.iso"}"#,
        )
        .unwrap();
        let body = create_body(&p, GuestKind::Qemu, 120).unwrap();
        assert_eq!(body["agent"], json!("enabled=1"));
        let typed: gtypes::PostCreateVmNodesNodeQemuBody =
            serde_json::from_value(serde_json::Value::Object(body)).unwrap();
        assert_eq!(typed.agent.as_deref(), Some("enabled=1"));
    }

    #[test]
    fn lxc_create_body_has_no_agent_field() {
        let p: ProvisionPayload = serde_json::from_str(
            r#"{"endpoint":"lab","node":"pve1","kind":"lxc","ostemplate":"local:vztmpl/debian.tar.zst"}"#,
        )
        .unwrap();
        let body = create_body(&p, GuestKind::Lxc, 121).unwrap();
        assert!(!body.contains_key("agent"));
    }
}
