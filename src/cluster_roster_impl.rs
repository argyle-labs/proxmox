//! `contract::ClusterRoster` adapter for the proxmox plugin.
//!
//! Iterates every enabled endpoint, fetches `/cluster/status`, and maps
//! the typed result into the plugin-neutral `ClusterEntry` shape that
//! domain crates consume via `ToolCtx::service::<Arc<dyn ClusterRoster>>`.
//! Endpoints whose client build or status fetch fails are skipped with a
//! `warn!` — matching the resilience pattern in
//! `tools::proxmox_cluster_list`.

use plugin_toolkit::contract::host_facts::HostFactsProvider;
use plugin_toolkit::contract::{ClusterEntry, ClusterNode, ClusterRoster, HostFacts};
use plugin_toolkit::orca_async;

use crate::tools::for_each_enabled_endpoint;

pub struct ProxmoxClusterRoster;

/// Typed `host_facts` facet for the `Plugin` builder. Reports THIS host's
/// corosync cluster membership (via the PVE API) for its mesh-propagated
/// `system` snapshot. Takes the first named cluster across enabled endpoints
/// (the fleet runs one cluster); `None` when standalone. Mirrors the
/// `proxmox.get_facts` tool, reusing [`ProxmoxClusterRoster`].
pub struct ProxmoxHostFacts;

#[orca_async]
impl HostFactsProvider for ProxmoxHostFacts {
    fn name(&self) -> &str {
        "proxmox"
    }

    async fn get_facts(&self) -> anyhow::Result<HostFacts> {
        let clusters = ProxmoxClusterRoster.list_clusters().await?;
        let cluster = clusters.into_iter().find_map(|c| c.name);
        Ok(HostFacts { cluster })
    }
}

#[orca_async]
impl ClusterRoster for ProxmoxClusterRoster {
    fn name(&self) -> &str {
        "proxmox"
    }

    async fn list_clusters(&self) -> anyhow::Result<Vec<ClusterEntry>> {
        Ok(
            for_each_enabled_endpoint("list_clusters", |cfg, ep| async move {
                let client = cfg.build_generated_client()?;
                let s = crate::cluster::fetch_cluster_status(&client).await?;
                Ok(vec![ClusterEntry {
                    endpoint: ep.name,
                    name: s.name,
                    quorate: s.quorate,
                    nodes: s
                        .nodes
                        .into_iter()
                        .map(|n| ClusterNode {
                            name: n.name,
                            ip: n.ip,
                            online: n.online,
                        })
                        .collect(),
                }])
            })
            .await,
        )
    }
}
