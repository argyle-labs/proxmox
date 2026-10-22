use plugin_toolkit::prelude::*;

use crate::Config;
use plugin_toolkit::api;

#[endpoint_resource(plugin = "proxmox")]
pub struct ProxmoxEndpoint {
    pub name: String,
    pub token_id: String,
    #[secret]
    pub token_secret: String,
    pub insecure: bool,
    pub enabled: bool,
}

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

pub(crate) async fn resolve_config(name: &str) -> Result<Config> {
    let row = endpoint_db::require(name)?;
    let secret = resolve_token_secret(name)?;
    let reachable = route::resolve_reachable(name, &row.routes, row.insecure).await?;
    let base_url = api_root(&reachable);
    Ok(Config::new(base_url, row.token_id, secret)
        .insecure(row.insecure)
        .endpoint(name))
}

fn api_root(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    if trimmed.ends_with("/api2/json") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/api2/json")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EndpointFailure {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub error: String,
}

pub(crate) struct FanOut<T> {
    pub items: Vec<T>,
    pub failures: Vec<EndpointFailure>,
    pub attempted: usize,
}

pub(crate) async fn fan_out_enabled_endpoints<T, F, Fut>(op: &str, work: F) -> FanOut<T>
where
    F: Fn(Config, ProxmoxEndpoint) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<T>>>,
{
    let mut out = FanOut {
        items: Vec::new(),
        failures: Vec::new(),
        attempted: 0,
    };
    let endpoints = match endpoint_db::list() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(op, error = %e, "proxmox fan-out: endpoint list failed");
            out.failures.push(EndpointFailure {
                endpoint: None,
                error: format!("endpoint list: {e:#}"),
            });
            return out;
        }
    };
    for ep in endpoints.into_iter().filter(|e| e.enabled) {
        out.attempted += 1;
        let name = ep.name.clone();
        let cfg = match resolve_config(&name).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(op, endpoint = %name, error = %e, "proxmox fan-out: endpoint resolve failed");
                out.failures.push(EndpointFailure {
                    endpoint: Some(name),
                    error: format!("resolve: {e:#}"),
                });
                continue;
            }
        };
        match work(cfg, ep).await {
            Ok(items) => out.items.extend(items),
            Err(e) => {
                tracing::warn!(op, endpoint = %name, error = %e, "proxmox fan-out: op failed");
                out.failures.push(EndpointFailure {
                    endpoint: Some(name),
                    error: format!("{e:#}"),
                });
            }
        }
    }
    out
}

pub(crate) async fn for_each_enabled_endpoint<T, F, Fut>(op: &str, work: F) -> Vec<T>
where
    F: Fn(Config, ProxmoxEndpoint) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<T>>>,
{
    fan_out_enabled_endpoints(op, work).await.items
}

pub(crate) fn token_secret_name(endpoint: &str) -> Result<String> {
    plugin_toolkit::secrets::scoped_name("proxmox", endpoint, "token_secret").map(|r| r.to_string())
}

pub(crate) fn enabled_endpoint_names() -> Vec<String> {
    match endpoint_db::list() {
        Ok(eps) => eps
            .into_iter()
            .filter(|e| e.enabled)
            .map(|e| e.name)
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "proxmox: enabled endpoint list failed");
            Vec::new()
        }
    }
}

fn resolve_token_secret(name: &str) -> Result<String> {
    let secret_name = token_secret_name(name)?;
    match plugin_toolkit::secrets::get(&secret_name)? {
        Some(s) => Ok(s.expose_secret().clone()),
        None => Err(anyhow::anyhow!(
            "proxmox endpoint '{name}' has no token secret '{secret_name}'; set it with \
             `proxmox.update --name {name} --token-secret <secret>`"
        )),
    }
}

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
#[orca_tool(
    domain = "proxmox",
    verb = "nodes",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_nodes(args: ProxmoxNodesArgs, _ctx: &ToolCtx) -> Result<Vec<ProxmoxNodeRow>> {
    let items: Vec<ProxmoxNodeRow> =
        api::call("proxmox.get_index_nodes", &args.endpoint, json!({}))
            .map_err(|e| anyhow::anyhow!("proxmox.nodes: {e}"))?;
    Ok(items)
}

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
#[orca_tool(
    domain = "proxmox",
    verb = "node_detail",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_node_detail(
    args: ProxmoxNodeDetailArgs,
    _ctx: &ToolCtx,
) -> Result<ProxmoxNodeDetailOutput> {
    let node = json!({ "node": args.node });
    let vms: Vec<ProxmoxGuestRow> = api::call(
        "proxmox.get_vmlist_nodes_node_qemu",
        &args.endpoint,
        node.clone(),
    )
    .map_err(|e| anyhow::anyhow!("proxmox.node_detail vms: {e}"))?;
    let containers: Vec<ProxmoxGuestRow> =
        api::call("proxmox.get_vmlist_nodes_node_lxc", &args.endpoint, node)
            .map_err(|e| anyhow::anyhow!("proxmox.node_detail containers: {e}"))?;
    Ok(ProxmoxNodeDetailOutput {
        node: args.node,
        vms,
        containers,
    })
}

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
#[orca_tool(
    domain = "proxmox",
    verb = "action",
    role = "admin",
    reaches = [
        "proxmox.post_vm_start_nodes_node_qemu_vmid_status_start",
        "proxmox.post_vm_stop_nodes_node_qemu_vmid_status_stop",
        "proxmox.post_vm_shutdown_nodes_node_qemu_vmid_status_shutdown",
        "proxmox.post_vm_reboot_nodes_node_qemu_vmid_status_reboot",
        "proxmox.post_vm_start_nodes_node_lxc_vmid_status_start",
        "proxmox.post_vm_stop_nodes_node_lxc_vmid_status_stop",
        "proxmox.post_vm_shutdown_nodes_node_lxc_vmid_status_shutdown",
        "proxmox.post_vm_reboot_nodes_node_lxc_vmid_status_reboot"
    ]
)]
async fn proxmox_action(args: ProxmoxActionArgs, ctx: &ToolCtx) -> Result<ProxmoxActionResult> {
    crate::execute::require_admin("proxmox.action", ctx.caller().as_ref())?;
    if args.vmid.is_some() && args.ctid.is_some() {
        bail!("set either `vmid` or `ctid`, not both");
    }
    let action: crate::ProxmoxAction = args.action.parse()?;
    let (vmid, is_lxc) = match (args.vmid, args.ctid) {
        (Some(v), None) => (v, false),
        (None, Some(c)) => (c, true),
        _ => bail!("`vmid` or `ctid` required"),
    };
    let kind = if is_lxc {
        crate::GuestKind::Lxc
    } else {
        crate::GuestKind::Qemu
    };
    let upid = crate::run_lifecycle(&args.endpoint, &args.node, kind, vmid, action)?;
    Ok(ProxmoxActionResult {
        node: args.node,
        vmid,
        action: action.as_str().to_string(),
        upid: Some(upid),
        status: 200,
    })
}

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
#[orca_tool(
    domain = "proxmox",
    verb = "host_logs",
    execute_gated = false,
    role = "admin"
)]
async fn proxmox_host_logs(
    args: ProxmoxHostLogsArgs,
    _ctx: &ToolCtx,
) -> Result<crate::responses::JournalResponse> {
    let q = crate::responses::JournalQuery {
        since: args.since,
        until: args.until,
        lastentries: args.lastentries,
        service: args.service,
    };
    Ok(crate::fetch_journal(&args.endpoint, &args.node, q)?)
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
#[orca_tool(
    domain = "proxmox",
    verb = "cluster_status",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_cluster_status(
    args: ProxmoxClusterStatusArgs,
    _ctx: &ToolCtx,
) -> Result<ProxmoxClusterStatusOutput> {
    let status = crate::cluster::fetch_cluster_status(&args.endpoint)?;
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
#[orca_tool(
    domain = "proxmox",
    verb = "cluster_list",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_cluster_list(
    _args: ProxmoxClusterListArgs,
    _ctx: &ToolCtx,
) -> Result<Vec<ProxmoxClusterListEntry>> {
    Ok(
        for_each_enabled_endpoint("cluster_list", |cfg, ep| async move {
            let status = crate::cluster::fetch_cluster_status(&cfg.endpoint)?;
            Ok(vec![ProxmoxClusterListEntry {
                endpoint: ep.name,
                status: status.into(),
            }])
        })
        .await,
    )
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
#[orca_tool(
    domain = "proxmox",
    verb = "list_clusters",
    execute_gated = false,
    role = "read"
)]
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
#[orca_tool(
    domain = "proxmox",
    verb = "collect_claims",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_collect_claims(
    _args: ProxmoxCollectClaimsArgs,
    _ctx: &ToolCtx,
) -> Result<Vec<plugin_toolkit::contract::TopologyClaim>> {
    crate::topology::collect_claims().await
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxGetFactsArgs {}

/// Host-facts backend op. Reports facts about THIS host for its mesh-propagated
/// `system` snapshot — currently the corosync cluster name, read from the PVE
/// API (not the on-disk `corosync.conf`, which core must not parse). Lets any
/// vantage group PVE peers by cluster without the proxmox plugin loaded there.
/// Takes the first cluster with a name across enabled endpoints (the fleet runs
/// one cluster); `None` when standalone.
#[orca_tool(
    domain = "proxmox",
    verb = "get_facts",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_get_facts(
    _args: ProxmoxGetFactsArgs,
    _ctx: &ToolCtx,
) -> Result<plugin_toolkit::contract::HostFacts> {
    use plugin_toolkit::contract::ClusterRoster;
    let clusters = crate::cluster_roster_impl::ProxmoxClusterRoster
        .list_clusters()
        .await?;
    let cluster = clusters.into_iter().find_map(|c| c.name);
    Ok(plugin_toolkit::contract::HostFacts { cluster })
}

#[cfg(test)]
mod api_root_tests {
    use super::api_root;

    #[test]
    fn appends_api_root_to_bare_host() {
        assert_eq!(
            api_root("https://10.0.0.7:8006"),
            "https://10.0.0.7:8006/api2/json"
        );
    }

    #[test]
    fn trims_trailing_slash_before_appending() {
        assert_eq!(
            api_root("https://host:8006/"),
            "https://host:8006/api2/json"
        );
    }

    #[test]
    fn idempotent_when_suffix_present() {
        assert_eq!(
            api_root("https://host:8006/api2/json"),
            "https://host:8006/api2/json"
        );
    }
}

#[cfg(test)]
mod token_secret_tests {
    use super::resolve_token_secret;

    fn with_secret(value: Option<&'static str>) -> anyhow::Result<String> {
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, raw: &str| {
                assert_eq!(cap, "secret.op");
                let op: serde_json::Value = serde_json::from_str(raw).unwrap();
                assert_eq!(op["op"], "get");
                assert_eq!(op["name"], "proxmox.pve.token_secret");
                Ok(serde_json::json!({ "value": value }).to_string())
            }),
            || resolve_token_secret("pve"),
        )
    }

    #[test]
    fn resolves_from_the_name_core_auth_reads() {
        assert_eq!(with_secret(Some("s3cret")).unwrap(), "s3cret");
    }

    #[test]
    fn missing_secret_names_the_update_command() {
        let err = with_secret(None).unwrap_err().to_string();
        assert!(
            err.contains("proxmox.update --name pve --token-secret"),
            "{err}"
        );
    }
}
