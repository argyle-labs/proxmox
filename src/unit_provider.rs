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
//!
//! Endpoint credentials live in the plugin's endpoint registry
//! (`proxmox.{list,create,…}`); this provider reads them through the same
//! `endpoint_db` the tool surface owns, so registering a host once lights up
//! both the tool surface and the unit surface.

use plugin_toolkit::anyhow::{Result, anyhow};
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::unit::{
    ActionDecl, ActionOutcome, CreateArgs, DeleteArgs, DetailArgs, ItemOutcome, ItemsOutcome,
    KindDeclaration, ListArgs, UnitDescriptor, UnitId, UnitProvider, UpdateArgs, Verb, VerbArgs,
    VerbDecl, VerbOutcome,
};
use plugin_toolkit::db::pool::with_pooled_or_open;
use plugin_toolkit::schemars::{JsonSchema, schema_for};
use plugin_toolkit::serde::{Deserialize, Serialize};
use plugin_toolkit::serde_json::{self, json};

use crate::GuestKind;
use crate::generated::{self, types as gtypes};

const KIND_VM: &str = "vm";
const KIND_LXC: &str = "lxc";

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maxmem: Option<i64>,
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

// ── helpers ────────────────────────────────────────────────────────────────

fn manager_for(endpoint: &str) -> String {
    format!("proxmox@{endpoint}")
}

/// Extract the endpoint name from a `proxmox@<endpoint>` manager string.
fn endpoint_of(id: &UnitId) -> Result<String> {
    id.manager
        .strip_prefix("proxmox@")
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("not a proxmox unit manager: {}", id.manager))
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
            mem: r.mem,
            maxmem: r.maxmem,
        });
    }
    Ok(out)
}

/// All guests across every enabled endpoint. A failing endpoint is logged and
/// skipped so one bad host doesn't blank the whole fleet's units.
async fn all_guests() -> Result<Vec<GuestSummary>> {
    let endpoints = with_pooled_or_open(crate::tools::endpoint_db::list)?;
    let mut out = Vec::new();
    for ep in endpoints.into_iter().filter(|e| e.enabled) {
        // Route through `make_client` so the token secret is resolved
        // secure-first from the abstract secrets domain
        // (`proxmox.<endpoint>.token_secret`). Building `Config` straight off
        // the row would use the now-empty plaintext column post-bootstrap and
        // silently authenticate with no token ([[runtime-least-privilege-not-root]]).
        let client = match crate::tools::make_client(&ep.name) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(endpoint = %ep.name, error = %e, "proxmox units: client build failed");
                continue;
            }
        };
        match guests_for_endpoint(&client, &ep.name).await {
            Ok(mut v) => {
                // One cluster-status probe per endpoint stamps the cluster name
                // onto every guest, so the canonical id collapses the same guest
                // seen from all member nodes. A standalone host (or a probe
                // failure) leaves it None → canonical falls back to the endpoint.
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
                out.append(&mut v);
            }
            Err(e) => {
                tracing::warn!(endpoint = %ep.name, error = %e, "proxmox units: enumeration failed");
            }
        }
    }
    Ok(out)
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
        let client = crate::tools::make_client(&endpoint)?;
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
        let endpoint = endpoint_of(&args.id)?;
        let kind = kind_from_str(&args.id.kind)?;
        let vmid: u64 = args
            .id
            .id
            .parse()
            .map_err(|_| anyhow!("vmid '{}' is not a u64", args.id.id))?;
        let client = crate::tools::make_client(&endpoint)?;
        let node = resolve_node(&client, kind, vmid).await?;
        lifecycle(&client, &node, vmid, kind, &args.action).await?;
        Ok(VerbOutcome::Action(ActionOutcome {
            changed: true,
            message: format!("{} {} {vmid} on {node}", args.action, kind_str(kind)),
        }))
    }

    async fn do_create(&self, args: CreateArgs) -> Result<VerbOutcome> {
        if args.action != "provision" {
            return Err(anyhow!("unknown proxmox create action: {}", args.action));
        }
        let raw = args
            .payload
            .ok_or_else(|| anyhow!("provision requires a payload"))?;
        let p: ProvisionPayload =
            serde_json::from_str(&raw).map_err(|e| anyhow!("provision payload: {e}"))?;
        let kind = kind_from_str(&p.kind)?;
        let client = crate::tools::make_client(&p.endpoint)?;

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

    async fn do_delete(&self, args: DeleteArgs) -> Result<VerbOutcome> {
        let endpoint = endpoint_of(&args.id)?;
        let kind = kind_from_str(&args.id.kind)?;
        let vmid: u64 = args
            .id
            .id
            .parse()
            .map_err(|_| anyhow!("vmid '{}' is not a u64", args.id.id))?;
        let client = crate::tools::make_client(&endpoint)?;
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
    let lifecycle_actions = ["start", "stop", "shutdown", "reboot"]
        .into_iter()
        .map(|a| ActionDecl {
            action: a.to_string(),
            payload_schema: None,
            response_schema: None,
        })
        .collect();
    vec![
        VerbDecl::list(),
        VerbDecl::detail(),
        VerbDecl {
            verb: Verb::Update,
            query_schema: None,
            actions: lifecycle_actions,
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
            mem: None,
            maxmem: None,
        }
    }

    #[test]
    fn canonical_is_cluster_scoped_when_clustered() {
        // Same guest seen from three member-node endpoints → identical canonical
        // id, so core's merge collapses them to one unit.
        let a = ProxmoxUnitProvider::canonical(&guest("thor", Some("yggdrasil"), "lxc", 100));
        let b = ProxmoxUnitProvider::canonical(&guest("loki", Some("yggdrasil"), "lxc", 100));
        assert_eq!(a, "cluster:yggdrasil/lxc/100");
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
            ProxmoxUnitProvider::list_item(&guest("thor", Some("yggdrasil"), "lxc", 100));
        assert_eq!(clustered.datacenter.as_deref(), Some("yggdrasil"));
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
