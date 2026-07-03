//! Proxmox tool surface.
//!
//! Endpoint registry: `proxmox.{list, detail, create, update, delete}` —
//! generated wholesale by `#[endpoint_resource]`. The macro emits the row
//! struct, db helpers (`endpoint_db::*`), schema fragment, args/output
//! types, and the five `#[orca_tool]`-annotated functions in one shot.
//!
//! Hand-written tools for cluster drill-in and lifecycle:
//!   - `proxmox.nodes`            list nodes for an endpoint
//!   - `proxmox.node_detail`      VMs + containers on one node
//!   - `proxmox.action`           VM/container start/stop/shutdown/reboot
//!   - `proxmox.host_logs`        systemd journal lines from one node
//!
//! Imports flow through `plugin_toolkit::prelude::*` only.

use plugin_toolkit::prelude::*;

use crate::Config;
use crate::generated;

// ═══════════════════════════════════════════════════════════════════════════
// proxmox.{list,detail,create,update,delete} — endpoint registry CRUD.
// ═══════════════════════════════════════════════════════════════════════════

#[endpoint_resource(plugin = "proxmox")]
pub struct ProxmoxEndpoint {
    pub name: String,
    pub base_url: String,
    pub token_id: String,
    #[secret]
    pub token_secret: String,
    pub insecure: bool,
    pub enabled: bool,
}

// ── Action result ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxActionResult {
    pub node: String,
    pub vmid: u64,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upid: Option<String>,
    pub status: u16,
}

impl From<crate::ProxmoxActionResult> for ProxmoxActionResult {
    fn from(r: crate::ProxmoxActionResult) -> Self {
        Self {
            node: r.node,
            vmid: r.vmid,
            action: r.action,
            upid: r.upid,
            status: r.status,
        }
    }
}

// ── HTTP client helper ─────────────────────────────────────────────────────

pub(crate) fn make_client(name: &str) -> Result<generated::Client> {
    let conn = runtime::open_db()?;
    let row = endpoint_db::get(&conn, name)?
        .with_context(|| format!("proxmox endpoint '{name}' not registered"))?;
    if !row.enabled {
        bail!("proxmox endpoint '{name}' is disabled");
    }
    let secret = resolve_token_secret(name, &row)?;
    let cfg = Config::new(row.base_url, row.token_id, secret).insecure(row.insecure);
    Ok(cfg.build_generated_client()?)
}

/// Resolve an endpoint's token secret secure-first: prefer the abstract secrets
/// domain (`proxmox.<endpoint>.token_secret`), falling back to a legacy
/// plaintext column value only if the domain has none. Once
/// `proxmox.access_bootstrap` has run, the column is empty and the secret lives
/// only in the secrets domain ([[runtime-least-privilege-not-root]]).
pub(crate) fn token_secret_name(endpoint: &str) -> String {
    plugin_toolkit::secrets::scoped_name("proxmox", endpoint, "token_secret")
}

fn resolve_token_secret(name: &str, row: &ProxmoxEndpoint) -> Result<String> {
    if let Some(v) = plugin_toolkit::secrets::get(&token_secret_name(name))? {
        return Ok(v);
    }
    if !row.token_secret.is_empty() {
        return Ok(row.token_secret.clone());
    }
    bail!("proxmox endpoint '{name}' has no token secret (neither in the secrets domain nor inline)")
}

// ═══════════════════════════════════════════════════════════════════════════
// proxmox.nodes — list cluster nodes for an endpoint
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxNodesArgs {
    #[arg(long)]
    pub endpoint: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxNodeRow {
    pub node: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f64>,
}

/// List Proxmox cluster nodes for a registered endpoint.
#[orca_tool(domain = "proxmox", verb = "nodes")]
async fn proxmox_nodes(args: ProxmoxNodesArgs, _ctx: &ToolCtx) -> Result<Vec<ProxmoxNodeRow>> {
    let client = make_client(&args.endpoint)?;
    let items = client
        .get_index_nodes()
        .await
        .map_err(|e| anyhow::anyhow!("proxmox.nodes: {e}"))?
        .into_inner();
    Ok(items
        .into_iter()
        .map(|n| ProxmoxNodeRow {
            node: n.node,
            status: Some(n.status.to_string()),
            uptime: n.uptime,
            cpu: n.cpu,
        })
        .collect())
}

// ═══════════════════════════════════════════════════════════════════════════
// proxmox.node_detail — VMs + containers on one node
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxNodeDetailArgs {
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub node: String,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxGuestRow {
    pub vmid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<i64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProxmoxNodeDetailOutput {
    pub node: String,
    pub vms: Vec<ProxmoxGuestRow>,
    pub containers: Vec<ProxmoxGuestRow>,
}

/// List VMs + containers on one node of a registered Proxmox endpoint.
#[orca_tool(domain = "proxmox", verb = "node_detail")]
async fn proxmox_node_detail(
    args: ProxmoxNodeDetailArgs,
    _ctx: &ToolCtx,
) -> Result<ProxmoxNodeDetailOutput> {
    let client = make_client(&args.endpoint)?;
    let vms = client
        .get_vmlist_nodes_node_qemu(&args.node, None)
        .await
        .map_err(|e| anyhow::anyhow!("proxmox.node_detail vms: {e}"))?
        .into_inner();
    let containers = client
        .get_vmlist_nodes_node_lxc(&args.node)
        .await
        .map_err(|e| anyhow::anyhow!("proxmox.node_detail containers: {e}"))?
        .into_inner();
    Ok(ProxmoxNodeDetailOutput {
        node: args.node.clone(),
        vms: vms
            .into_iter()
            .map(|v| ProxmoxGuestRow {
                vmid: v.vmid as u64,
                name: v.name,
                status: Some(v.status.to_string()),
                uptime: v.uptime,
            })
            .collect(),
        containers: containers
            .into_iter()
            .map(|c| ProxmoxGuestRow {
                vmid: c.vmid as u64,
                name: c.name,
                status: Some(c.status.to_string()),
                uptime: c.uptime,
            })
            .collect(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// proxmox.action — VM/container lifecycle action
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxActionArgs {
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
    /// `start` | `stop` | `shutdown` | `reboot`.
    #[arg(long)]
    pub action: String,
}

/// [MUTATES STATE] Run a lifecycle action against one VM (`vmid`) or
/// container (`ctid`) on the named node.
#[orca_tool(domain = "proxmox", verb = "action", role = "admin")]
async fn proxmox_action(args: ProxmoxActionArgs, _ctx: &ToolCtx) -> Result<ProxmoxActionResult> {
    if args.vmid.is_some() && args.ctid.is_some() {
        bail!("set either `vmid` or `ctid`, not both");
    }
    let action: crate::ProxmoxAction = args.action.parse()?;
    let client = make_client(&args.endpoint)?;
    let (vmid, is_lxc) = match (args.vmid, args.ctid) {
        (Some(v), None) => (v, false),
        (None, Some(c)) => (c, true),
        _ => bail!("`vmid` or `ctid` required"),
    };
    let upid = run_lifecycle(&client, &args.node, vmid, is_lxc, action).await?;
    Ok(ProxmoxActionResult {
        node: args.node,
        vmid,
        action: action.as_str().to_string(),
        upid: Some(upid),
        status: 200,
    })
}

async fn run_lifecycle(
    client: &generated::Client,
    node: &str,
    vmid: u64,
    is_lxc: bool,
    action: crate::ProxmoxAction,
) -> Result<String> {
    let vmid_i = vmid as i64;
    let upid = match (is_lxc, action) {
        (false, crate::ProxmoxAction::Start) => client
            .post_vm_start_nodes_node_qemu_vmid_status_start(node, vmid_i, &Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("qemu start {vmid}: {e}"))?
            .into_inner(),
        (false, crate::ProxmoxAction::Stop) => client
            .post_vm_stop_nodes_node_qemu_vmid_status_stop(node, vmid_i, &Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("qemu stop {vmid}: {e}"))?
            .into_inner(),
        (false, crate::ProxmoxAction::Shutdown) => client
            .post_vm_shutdown_nodes_node_qemu_vmid_status_shutdown(
                node,
                vmid_i,
                &Default::default(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("qemu shutdown {vmid}: {e}"))?
            .into_inner(),
        (false, crate::ProxmoxAction::Reboot) => client
            .post_vm_reboot_nodes_node_qemu_vmid_status_reboot(node, vmid_i, &Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("qemu reboot {vmid}: {e}"))?
            .into_inner(),
        (true, crate::ProxmoxAction::Start) => client
            .post_vm_start_nodes_node_lxc_vmid_status_start(node, vmid_i, &Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("lxc start {vmid}: {e}"))?
            .into_inner(),
        (true, crate::ProxmoxAction::Stop) => client
            .post_vm_stop_nodes_node_lxc_vmid_status_stop(node, vmid_i, &Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("lxc stop {vmid}: {e}"))?
            .into_inner(),
        (true, crate::ProxmoxAction::Shutdown) => client
            .post_vm_shutdown_nodes_node_lxc_vmid_status_shutdown(node, vmid_i, &Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("lxc shutdown {vmid}: {e}"))?
            .into_inner(),
        (true, crate::ProxmoxAction::Reboot) => client
            .post_vm_reboot_nodes_node_lxc_vmid_status_reboot(node, vmid_i, &Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("lxc reboot {vmid}: {e}"))?
            .into_inner(),
    };
    Ok(upid)
}

// Backwards-compat: the action tool builds a `crate::ProxmoxActionResult`-
// shaped value then converts via `From`. Keep the conversion working by
// providing the obvious identity build path above without forcing the
// caller to import the crate-level type.
impl ProxmoxActionResult {
    // Avoid an unused-impl footgun: the From impl above is the only
    // construction path, so no additional helpers needed here.
}

// ═══════════════════════════════════════════════════════════════════════════
// proxmox.host_logs — view systemd journal lines for one Proxmox node
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxHostLogsArgs {
    #[arg(long)]
    pub endpoint: String,
    /// Proxmox node hostname (cluster member, e.g. the `node` field from
    /// `proxmox.nodes`).
    #[arg(long)]
    pub node: String,
    /// Cap on lines returned from the tail. Recommended for interactive
    /// callers — Proxmox can return a lot.
    #[arg(long)]
    pub lastentries: Option<u32>,
    /// Unix timestamp lower bound.
    #[arg(long)]
    pub since: Option<u64>,
    /// Unix timestamp upper bound.
    #[arg(long)]
    pub until: Option<u64>,
    /// Filter to one systemd unit / service name.
    #[arg(long)]
    pub service: Option<String>,
}

/// Pull the systemd journal for one Proxmox node. Mirrors `journalctl`
/// over the HTTPS API — no SSH, no on-host shell. Used by operators
/// today and by the LXC breaker once the API adapter takes over.
#[orca_tool(domain = "proxmox", verb = "host_logs")]
async fn proxmox_host_logs(
    args: ProxmoxHostLogsArgs,
    _ctx: &ToolCtx,
) -> Result<crate::responses::JournalResponse> {
    let client = make_client(&args.endpoint)?;
    let q = crate::responses::JournalQuery {
        since: args.since,
        until: args.until,
        lastentries: args.lastentries,
        service: args.service,
    };
    Ok(crate::fetch_journal(&client, &args.node, q).await?)
}

// ═══════════════════════════════════════════════════════════════════════════
// proxmox.cluster_status / cluster_list — cluster envelope + node membership
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxClusterNode {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<bool>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxClusterStatusOutput {
    /// Cluster name. `null` when the endpoint is a standalone host
    /// without corosync clustering configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorate: Option<bool>,
    pub nodes: Vec<ProxmoxClusterNode>,
}

impl From<crate::cluster::ClusterStatus> for ProxmoxClusterStatusOutput {
    fn from(s: crate::cluster::ClusterStatus) -> Self {
        Self {
            name: s.name,
            quorate: s.quorate,
            nodes: s
                .nodes
                .into_iter()
                .map(|n| ProxmoxClusterNode {
                    name: n.name,
                    ip: n.ip,
                    online: n.online,
                    node_id: n.node_id,
                    local: n.local,
                })
                .collect(),
        }
    }
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxClusterStatusArgs {
    #[arg(long)]
    pub endpoint: String,
}

/// Report cluster name, quorum, and node membership for one registered
/// Proxmox endpoint. Returns `name: null` for standalone hosts.
#[orca_tool(domain = "proxmox", verb = "cluster_status")]
async fn proxmox_cluster_status(
    args: ProxmoxClusterStatusArgs,
    _ctx: &ToolCtx,
) -> Result<ProxmoxClusterStatusOutput> {
    let client = make_client(&args.endpoint)?;
    let status = crate::cluster::fetch_cluster_status(&client).await?;
    Ok(status.into())
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxClusterListArgs {}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxClusterListEntry {
    pub endpoint: String,
    pub status: ProxmoxClusterStatusOutput,
}

/// Walk every enabled Proxmox endpoint and return its cluster status.
/// Endpoints that fail to fetch are skipped with a `warn!` log, mirroring
/// the resilience pattern used by `topology::collect_claims` — a single
/// flaky endpoint must not blank the fleet view.
#[orca_tool(domain = "proxmox", verb = "cluster_list")]
async fn proxmox_cluster_list(
    _args: ProxmoxClusterListArgs,
    _ctx: &ToolCtx,
) -> Result<Vec<ProxmoxClusterListEntry>> {
    let conn = runtime::open_db()?;
    let endpoints = endpoint_db::list(&conn)?;
    drop(conn);

    let mut out = Vec::new();
    for ep in endpoints.into_iter().filter(|e| e.enabled) {
        let name = ep.name.clone();
        let cfg =
            crate::Config::new(ep.base_url, ep.token_id, ep.token_secret).insecure(ep.insecure);
        let client = match cfg.build_generated_client() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    endpoint = %name,
                    error = %e,
                    "proxmox.cluster_list: client build failed",
                );
                continue;
            }
        };
        match crate::cluster::fetch_cluster_status(&client).await {
            Ok(s) => out.push(ProxmoxClusterListEntry {
                endpoint: name,
                status: s.into(),
            }),
            Err(e) => {
                tracing::warn!(
                    endpoint = %name,
                    error = %e,
                    "proxmox.cluster_list: cluster_status fetch failed",
                );
            }
        }
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-ABI domain backends. These two tools are how the plugin's
// cluster-roster + topology contributions reach orca: the loader registers a
// `cluster_roster` / `topology` backend whose proxy invokes these by name
// (`contract::cluster_roster::ROSTER_OP` / `contract::topology::COLLECT_OP`,
// under the `proxmox` invoke prefix declared in `abi_export::backends`). They
// return the plugin-neutral `contract` shapes the registries deserialize.
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxListClustersArgs {}

/// Cluster-roster backend op. Walks every enabled endpoint and maps each
/// cluster into the plugin-neutral `ClusterEntry` shape `AggregateClusterRoster`
/// concatenates. Reuses `ProxmoxClusterRoster` so the roster logic lives in one
/// place.
#[orca_tool(domain = "proxmox", verb = "list_clusters")]
async fn proxmox_list_clusters(
    _args: ProxmoxListClustersArgs,
    _ctx: &ToolCtx,
) -> Result<Vec<plugin_toolkit::contract::ClusterEntry>> {
    use plugin_toolkit::contract::ClusterRoster;
    crate::cluster_roster_impl::ProxmoxClusterRoster
        .list_clusters()
        .await
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxCollectClaimsArgs {}

/// Topology-collector backend op. Walks every enabled endpoint's guests and
/// emits a `TopologyClaim` per VM/container, which orca's inference layer
/// matches by MAC to nest guests under their host.
#[orca_tool(domain = "proxmox", verb = "collect_claims")]
async fn proxmox_collect_claims(
    _args: ProxmoxCollectClaimsArgs,
    _ctx: &ToolCtx,
) -> Result<Vec<plugin_toolkit::contract::TopologyClaim>> {
    crate::topology::collect_claims().await
}
