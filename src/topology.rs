//! Proxmox → TopologyClaim collector (API path).
//!
//! Replaces the file-reading collector in `system::topology::proxmox` for
//! every host with a registered Proxmox endpoint. Architectural rationale
//! per [[project-adapter-backends-api-first]]: runtime adapters speak the
//! native API, not host-local CLI / pmxcfs files.
//!
//! Two-step fetch per endpoint:
//!   1. `GET /cluster/resources?type=vm` — every VM + LXC in the cluster
//!      via the typed generated client.
//!   2. `GET /nodes/{node}/{kind}/{vmid}/config` per guest — via
//!      `fetch_guest_config` (raw URL: progenitor can't model the
//!      indexed `netN` keys we depend on). Calls fan out concurrently.
//!
//! Errors are scoped per endpoint and per guest: a broken endpoint blanks
//! that endpoint's contribution but doesn't kill claims from others; a
//! guest whose config 404s is skipped silently (it may have been deleted
//! between the cluster-list and the config fetch).

use crate::generated::{self, types as gtypes};
use crate::tools::for_each_enabled_endpoint;
use crate::{GuestKind, fetch_guest_config};
use plugin_toolkit::contract::TopologyClaim;

/// Walk every registered + enabled Proxmox endpoint and return the union
/// of TopologyClaims. Endpoints that fail are logged and skipped.
pub async fn collect_claims() -> anyhow::Result<Vec<TopologyClaim>> {
    Ok(for_each_enabled_endpoint("topology", |cfg, ep| async move {
        let http = cfg.build_reqwest_client()?;
        let client = generated::Client::new_with_client(&cfg.base_url, http.clone());
        collect_for_endpoint(&client, &http, &cfg.base_url, &ep.name).await
    })
    .await)
}

async fn collect_for_endpoint(
    client: &generated::Client,
    http: &reqwest::Client,
    base_url: &str,
    provider_instance: &str,
) -> anyhow::Result<Vec<TopologyClaim>> {
    let items = client
        .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
        .await
        .map_err(|e| anyhow::anyhow!("proxmox cluster resources: {e}"))?
        .into_inner();

    let guests: Vec<GuestRef> = items
        .into_iter()
        .filter_map(|e| {
            let kind = match e.type_ {
                gtypes::GetResourcesClusterResourcesResponseItemType::Qemu => GuestKind::Qemu,
                gtypes::GetResourcesClusterResourcesResponseItemType::Lxc => GuestKind::Lxc,
                _ => return None,
            };
            let node = e.node?;
            let vmid = e.vmid?;
            if node.is_empty() || vmid <= 0 {
                return None;
            }
            Some(GuestRef {
                node,
                vmid: vmid as u64,
                kind,
                name: e.name,
            })
        })
        .collect();

    // Fan out config fetches. Each guest is one round-trip; sequential
    // would be O(N × RTT). At small fleet sizes (≤200 guests) `join_all`
    // is fine — switch to a bounded semaphore if it ever exceeds that.
    let futs = guests.into_iter().map(|g| async move {
        let cfg = match fetch_guest_config(http, base_url, &g.node, g.kind, g.vmid).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(
                    node = %g.node,
                    vmid = g.vmid,
                    error = %e,
                    "proxmox topology: guest_config failed (guest may have been deleted)",
                );
                return None;
            }
        };
        let macs = cfg.data.macs();
        if macs.is_empty() {
            return None;
        }
        Some(TopologyClaim {
            kind: kind_to_claim_kind(g.kind).to_string(),
            id: g.vmid.to_string(),
            name: g
                .name
                .unwrap_or_else(|| format!("{}-{}", kind_to_claim_kind(g.kind), g.vmid)),
            macs,
            provider: "proxmox".to_string(),
            provider_instance: provider_instance.to_string(),
            // The node this guest actually runs on — lets the inventory layer
            // parent it correctly despite cluster-shared pmxcfs config making
            // every cluster peer report every guest.
            runs_on: Some(g.node),
            // PVE config exposes no listening ports; endpoints/image stay
            // empty. In-guest port + service-role discovery arrives via the
            // runtime service-identity registration path, not the claim.
            ..Default::default()
        })
    });
    let claims = plugin_toolkit::futures_util::future::join_all(futs)
        .await
        .into_iter()
        .flatten()
        .collect();
    Ok(claims)
}

fn kind_to_claim_kind(k: GuestKind) -> &'static str {
    match k {
        GuestKind::Qemu => "vm",
        GuestKind::Lxc => "lxc",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestRef {
    node: String,
    vmid: u64,
    kind: GuestKind,
    name: Option<String>,
}
