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
use crate::generated::{self, types as gtypes};

const KIND_VM: &str = "vm";
const KIND_LXC: &str = "lxc";

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
}

/// Typed payload for `Create { action: "provision" }`. Shared by both kinds;
/// `ostemplate` is required for `lxc`, `iso`/`disk_gb` shape a `vm`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    // ── vm ──
    /// Install ISO volume id for a vm (mapped to `cdrom`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso: Option<String>,
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
fn guest_guard(kind: GuestKind) -> UnitGuard {
    match kind {
        GuestKind::Lxc => UnitGuard::min_resources(KIND_LXC, 1, 512),
        GuestKind::Qemu => UnitGuard::min_resources(KIND_VM, 1, 1024),
    }
}

/// Observed facts for a live guest, from its cluster-resource row. PVE exposes no
/// console / update-command reachability here, so those stay unchecked (the
/// baseline guard declares no such requirement).
fn facts_of(g: &GuestSummary) -> UnitFacts {
    UnitFacts {
        cpu: g.maxcpu.map(|c| c.round() as u32),
        mem_mb: g.maxmem.map(|b| (b.max(0) as u64) / (1024 * 1024)),
        has_root_console: false,
        has_update_command: false,
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
        });
    }
    // Stamp each guest's guard compliance so the unit surface shows breaches.
    for g in &mut out {
        if let Ok(k) = kind_from_str(&g.kind) {
            g.guard_violations = guest_guard(k)
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
        // Backup is a first-class managed-unit action (the pre-mutation guard and
        // scheduler both dispatch it) — route it before lifecycle transitions.
        if args.action == ACTION_BACKUP {
            return self.do_backup(&args.id, args.payload).await;
        }
        if args.action == ACTION_RESTORE {
            return self.do_restore(&args.id, args.payload).await;
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

    async fn do_create(&self, args: CreateArgs) -> Result<VerbOutcome> {
        if args.action != "provision" {
            return Err(anyhow!("unknown proxmox create action: {}", args.action));
        }
        let raw = args
            .payload
            .ok_or_else(|| anyhow!("provision requires a payload"))?;
        let mut p: ProvisionPayload =
            serde_json::from_str(&raw).map_err(|e| anyhow!("provision payload: {e}"))?;
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

        let client = crate::tools::make_client(&p.endpoint).await?;

        let vmid = match p.vmid {
            Some(v) => v,
            None => client
                .get_nextid_cluster_nextid(None)
                .await
                .map_err(|e| anyhow!("nextid: {e}"))?
                .into_inner() as u64,
        };

        let upid = provision(&client, &p, kind, vmid).await?;
        let resp = ProvisionResponse {
            endpoint: p.endpoint.clone(),
            node: p.node.clone(),
            kind: kind_str(kind).to_string(),
            vmid,
            upid,
        };
        Ok(VerbOutcome::Item(ItemOutcome::new(
            UnitId {
                manager: manager_for(&p.endpoint),
                kind: kind_str(kind).to_string(),
                id: vmid.to_string(),
                name: p
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("{}-{vmid}", kind_str(kind))),
            },
            serde_json::to_string(&resp).unwrap_or_default(),
        )))
    }

    /// Idempotent create-or-ensure for a guest keyed by vmid. Per the `Upsert`
    /// contract an upsert succeeds whether or not the item already exists. A
    /// running VM/LXC must never be silently destroyed to "replace" it, so the
    /// safe interpretation is *ensure present*: provision when the guest is
    /// absent, no-op (unchanged) when it already exists. The payload is the same
    /// [`ProvisionPayload`] `create`/provision consumes.
    async fn do_upsert(&self, args: UpsertArgs) -> Result<VerbOutcome> {
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
        })
        .await
    }

    async fn do_delete(&self, args: DeleteArgs) -> Result<VerbOutcome> {
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

/// Build the typed create body from the typed payload and POST it. The body is
/// assembled as JSON (only set fields) then deserialized into the generated
/// typed body, so required-field validation happens against the real PVE schema.
async fn provision(
    client: &generated::Client,
    p: &ProvisionPayload,
    kind: GuestKind,
    vmid: u64,
) -> Result<Option<String>> {
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

    let upid = match kind {
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
            let typed: gtypes::PostCreateVmNodesNodeLxcBody =
                serde_json::from_value(serde_json::Value::Object(body))
                    .map_err(|e| anyhow!("lxc create body: {e}"))?;
            client
                .post_create_vm_nodes_node_lxc(&p.node, &typed)
                .await
                .map_err(|e| anyhow!("lxc create: {e}"))?
                .into_inner()
        }
        GuestKind::Qemu => {
            if let Some(name) = &p.name {
                body.insert("name".into(), json!(name));
            }
            if let Some(iso) = &p.iso {
                body.insert("cdrom".into(), json!(iso));
            }
            let typed: gtypes::PostCreateVmNodesNodeQemuBody =
                serde_json::from_value(serde_json::Value::Object(body))
                    .map_err(|e| anyhow!("qemu create body: {e}"))?;
            client
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
fn guest_verbs() -> Vec<VerbDecl> {
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
            KindDeclaration {
                kind: KIND_VM.into(),
                verbs: guest_verbs(),
            },
            KindDeclaration {
                kind: KIND_LXC.into(),
                verbs: guest_verbs(),
            },
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
}
