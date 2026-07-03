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
            // `make_client` resolves the reachable address + secure-first token
            // secret; building `Config` off the row directly would use the
            // now-removed `base_url` and the empty post-bootstrap plaintext token.
            let client = match crate::tools::make_client(&name).await {
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
