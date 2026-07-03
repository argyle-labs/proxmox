//! `contract::ClusterRoster` adapter for the proxmox plugin.
//!
//! Iterates every enabled endpoint, fetches `/cluster/status`, and maps
//! the typed result into the plugin-neutral `ClusterEntry` shape that
//! domain crates consume via `ToolCtx::service::<Arc<dyn ClusterRoster>>`.
//! Endpoints whose client build or status fetch fails are skipped with a
//! `warn!` — matching the resilience pattern in
//! `tools::proxmox_cluster_list`.

use plugin_toolkit::async_trait::async_trait;
use plugin_toolkit::contract::{ClusterEntry, ClusterNode, ClusterRoster};

use crate::tools::for_each_enabled_endpoint;

pub struct ProxmoxClusterRoster;

#[async_trait]
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
