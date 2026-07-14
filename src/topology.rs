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
use plugin_toolkit::contract::topology::ClaimAddress;
use plugin_toolkit::reqwest;
use std::net::IpAddr;

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
        // Best-effort live IPs. A guest with no agent (QEMU) or no running
        // interfaces reports nothing — that's an expected gap, not an error,
        // so failures are swallowed and `addresses` is simply left empty.
        let addresses = fetch_guest_addresses(client, g.kind, &g.node, g.vmid).await;
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
            addresses,
            // PVE config exposes no listening ports; endpoints/image stay
            // empty. In-guest port + service-role discovery arrives via the
            // runtime service-identity registration path, not the claim.
            ..Default::default()
        })
    });
    let claims = plugin_toolkit::reactor::join_all(futs)
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

/// Fetch a guest's live IPs and map them to `ClaimAddress`es. Never fails:
/// any transport/agent error (e.g. QEMU guest-agent not installed, LXC not
/// running) is logged at debug and yields an empty vec — a noted gap, not a
/// hard error, so one guest can't break the whole collect.
async fn fetch_guest_addresses(
    client: &generated::Client,
    kind: GuestKind,
    node: &str,
    vmid: u64,
) -> Vec<ClaimAddress> {
    let vmid = vmid as i64;
    match kind {
        GuestKind::Lxc => match client
            .get_ip_nodes_node_lxc_vmid_interfaces(node, vmid)
            .await
        {
            Ok(resp) => {
                // Each interface carries a typed `ip-addresses` list plus the
                // legacy `inet`/`inet6` (CIDR) fields; fold both in and dedupe.
                let raw = resp.into_inner().into_iter().flat_map(|iface| {
                    let typed = iface.ip_addresses.into_iter().filter_map(|a| a.ip_address);
                    typed
                        .chain(iface.inet)
                        .chain(iface.inet6)
                        .collect::<Vec<_>>()
                });
                addresses_from_ips(raw)
            }
            Err(e) => {
                tracing::debug!(node = %node, vmid, error = %e, "proxmox topology: lxc interfaces failed");
                Vec::new()
            }
        },
        GuestKind::Qemu => match client
            .get_network_get_interfaces_nodes_node_qemu_vmid_agent_network_get_interfaces(
                node, vmid,
            )
            .await
        {
            Ok(resp) => addresses_from_qemu_agent(&resp.into_inner()),
            Err(e) => {
                tracing::debug!(node = %node, vmid, error = %e, "proxmox topology: qemu guest-agent network-get-interfaces failed (agent absent?)");
                Vec::new()
            }
        },
    }
}

/// Parse the QEMU guest-agent `network-get-interfaces` payload (an untyped
/// JSON map: `{ "result": [ { "ip-addresses": [ { "ip-address": .. } ] } ] }`)
/// into `ClaimAddress`es.
fn addresses_from_qemu_agent(
    map: &plugin_toolkit::serde_json::Map<String, plugin_toolkit::serde_json::Value>,
) -> Vec<ClaimAddress> {
    let ips = map
        .get("result")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|iface| iface.get("ip-addresses").and_then(|v| v.as_array()))
        .flatten()
        .filter_map(|a| {
            a.get("ip-address")
                .and_then(|v| v.as_str())
                .map(String::from)
        });
    addresses_from_ips(ips)
}

/// Turn raw IP strings (bare or CIDR, v4 or v6) into deduped, routable
/// `ClaimAddress`es — dropping loopback, link-local and unspecified.
fn addresses_from_ips<I: IntoIterator<Item = String>>(ips: I) -> Vec<ClaimAddress> {
    let mut out: Vec<ClaimAddress> = Vec::new();
    for raw in ips {
        if let Some((kind, value)) = classify_ip(&raw)
            && !out.iter().any(|a| a.value == value)
        {
            out.push(ClaimAddress {
                kind: kind.to_string(),
                value,
                source: "proxmox".to_string(),
            });
        }
    }
    out
}

/// Classify one IP literal (accepts a trailing `/prefix`) into its address
/// kind, or `None` if it's loopback / link-local / unspecified / unparseable.
fn classify_ip(raw: &str) -> Option<(&'static str, String)> {
    let bare = raw.split('/').next().unwrap_or(raw).trim();
    let ip: IpAddr = bare.parse().ok()?;
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                return None;
            }
            Some(("lan_v4", v4.to_string()))
        }
        IpAddr::V6(v6) => {
            // fe80::/10 link-local (is_unicast_link_local is unstable on stable).
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            if v6.is_loopback() || v6.is_unspecified() || link_local {
                return None;
            }
            Some(("lan_v6", v6.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    #[test]
    fn classify_filters_loopback_and_link_local() {
        assert_eq!(classify_ip("127.0.0.1"), None);
        assert_eq!(classify_ip("169.254.3.4"), None);
        assert_eq!(classify_ip("0.0.0.0"), None);
        assert_eq!(classify_ip("::1"), None);
        assert_eq!(classify_ip("fe80::1"), None);
        assert_eq!(classify_ip("not-an-ip"), None);
        assert_eq!(
            classify_ip("192.0.2.27/24"),
            Some(("lan_v4", "192.0.2.27".to_string()))
        );
        assert_eq!(
            classify_ip("2607:fb90::1"),
            Some(("lan_v6", "2607:fb90::1".to_string()))
        );
    }

    #[test]
    fn addresses_dedupe_and_tag() {
        let got = addresses_from_ips(
            [
                "10.0.0.5/24",
                "10.0.0.5", // dup of the above once CIDR is stripped
                "127.0.0.1",
                "fd00::5",
            ]
            .into_iter()
            .map(String::from),
        );
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].kind, "lan_v4");
        assert_eq!(got[0].value, "10.0.0.5");
        assert_eq!(got[0].source, "proxmox");
        assert_eq!(got[1].kind, "lan_v6");
        assert_eq!(got[1].value, "fd00::5");
    }

    #[test]
    fn qemu_agent_payload_parsed() {
        let payload = json!({
            "result": [
                { "name": "lo", "ip-addresses": [ { "ip-address": "127.0.0.1", "ip-address-type": "ipv4" } ] },
                { "name": "eth0", "ip-addresses": [
                    { "ip-address": "192.0.2.5", "ip-address-type": "ipv4", "prefix": 24 },
                    { "ip-address": "fe80::abc", "ip-address-type": "ipv6" }
                ] }
            ]
        });
        let map = payload.as_object().unwrap().clone();
        let got = addresses_from_qemu_agent(&map);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, "192.0.2.5");
        assert_eq!(got[0].kind, "lan_v4");
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestRef {
    node: String,
    vmid: u64,
    kind: GuestKind,
    name: Option<String>,
}
