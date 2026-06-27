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
use plugin_toolkit::prelude::*;

use crate::tools::endpoint_db;
use crate::Config;

pub struct ProxmoxClusterRoster;

#[async_trait]
impl ClusterRoster for ProxmoxClusterRoster {
    fn name(&self) -> &str {
        "proxmox"
    }

    async fn list_clusters(&self) -> anyhow::Result<Vec<ClusterEntry>> {
        let conn = runtime::open_db()?;
        let endpoints = endpoint_db::list(&conn)?;
        drop(conn);

        let mut out = Vec::new();
        for ep in endpoints.into_iter().filter(|e| e.enabled) {
            let name = ep.name.clone();
            let cfg = Config::new(ep.base_url, ep.token_id, ep.token_secret).insecure(ep.insecure);
            let client = match cfg.build_generated_client() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(
                        endpoint = %name,
                        error = %e,
                        "ProxmoxClusterRoster: client build failed",
                    );
                    continue;
                }
            };
            match crate::cluster::fetch_cluster_status(&client).await {
                Ok(s) => out.push(ClusterEntry {
                    endpoint: name,
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
                }),
                Err(e) => {
                    tracing::warn!(
                        endpoint = %name,
                        error = %e,
                        "ProxmoxClusterRoster: cluster_status fetch failed",
                    );
                }
            }
        }
        Ok(out)
    }
}
