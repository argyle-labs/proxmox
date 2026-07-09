//! Live typed-deserialization sweep against a real Proxmox VE cluster.
//!
//! Env-gated — skipped unless `PVE_URL` is set, so CI stays green:
//!   PVE_URL=https://<pve-host>:8006/api2/json \
//!   PVE_TID='<user>@<realm>!<tokenid>' PVE_SEC=<uuid> PVE_INSECURE=1 \
//!   cargo test --test live_read_sweep -- --nocapture
//!
//! For every readable endpoint family, it calls the *generated client* (the
//! exact typed layer every surface wrapper delegates to) and asserts the body
//! deserializes into the typed model. A `.into_inner()` success means the
//! documented schema matched the wire — the real risk the surface must clear
//! (envelope peel + lenient bool/number coercion). Outcomes are classified:
//!   OK    — 2xx, typed deserialize succeeded
//!   GATED — 401/403, token lacks the ACL (not a surface defect)
//!   HTTP  — other non-2xx (reported, not a hard fail)
//!   DESER — 2xx but typed parse failed  ← the bug class this test exists to catch
//!
//! The test FAILS iff any DESER occurs.

use plugin_toolkit::reqwest;
use proxmox::Config;
use proxmox::generated::Client;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Outcome {
    Ok,
    Gated,
    Http,
    Deser,
}

/// Classify a generated-client result into an [`Outcome`]. `Ok` iff the typed
/// body deserialized; `Deser` iff the transport got a body but the typed parse
/// failed (`InvalidResponsePayload`) — the failure mode a wrong schema produces.
fn classify<T>(r: Result<T, proxmox::generated::Error<()>>) -> (Outcome, String) {
    match r {
        Ok(_) => (Outcome::Ok, String::new()),
        Err(e) => {
            let dbg = format!("{e:?}");
            if let Some(code) = e.status() {
                let c = code.as_u16();
                if c == 401 || c == 403 {
                    (Outcome::Gated, format!("{c}"))
                } else {
                    (Outcome::Http, format!("{c}"))
                }
            } else if dbg.to_lowercase().contains("invalid response payload") {
                (Outcome::Deser, dbg.chars().take(600).collect())
            } else {
                // transport/connection error — environmental, report as HTTP
                (Outcome::Http, dbg.chars().take(120).collect())
            }
        }
    }
}

/// Raw JSON GET on `<base>/<path>` for discovery (nodes, vmids) — decouples
/// test setup from typed structs so discovery can't itself fail deser.
async fn raw(http: &reqwest::Client, base: &str, path: &str) -> serde_json::Value {
    let url = format!("{}/{}", base.trim_end_matches('/'), path);
    let resp = http
        .get(&url)
        .send()
        .await
        .expect("discovery request failed");
    assert!(
        resp.status().is_success(),
        "discovery request failed: {} -> {}",
        url,
        resp.status().as_u16()
    );
    let bytes = resp.bytes().await.expect("discovery body read failed");
    serde_json::from_slice(&bytes).expect("discovery body not json")
}

#[tokio::test(flavor = "multi_thread")]
async fn live_read_sweep() {
    let Ok(base) = std::env::var("PVE_URL") else {
        eprintln!("SKIP live_read_sweep: PVE_URL not set");
        return;
    };
    let tid = std::env::var("PVE_TID").expect("PVE_TID");
    let sec = std::env::var("PVE_SEC").expect("PVE_SEC");
    let insecure = std::env::var("PVE_INSECURE").is_ok();

    let cfg = Config::new(&base, &tid, &sec).insecure(insecure);
    let http = cfg.build_reqwest_client().expect("reqwest client");
    let client = Client::new_with_client(&base, http.clone());

    // ── discover a node + one qemu vmid + one lxc vmid via raw JSON ──────────
    let nodes = raw(&http, &base, "nodes").await;
    let node = nodes["data"][0]["node"]
        .as_str()
        .expect("no nodes returned")
        .to_string();
    // Discover a guest of each kind cluster-wide (with its own node) from
    // /cluster/resources — so guest reads target wherever the VM actually runs,
    // not just nodes[0]. Returns (node, vmid).
    let resources = raw(&http, &base, "cluster/resources").await;
    let find_guest = |kind: &str| -> Option<(String, i64)> {
        resources["data"].as_array().and_then(|a| {
            a.iter()
                .filter(|e| e["type"].as_str() == Some(kind))
                .find_map(|e| {
                    let vmid = e["vmid"]
                        .as_i64()
                        .or_else(|| e["vmid"].as_str().and_then(|s| s.parse().ok()))?;
                    let gnode = e["node"].as_str()?.to_string();
                    Some((gnode, vmid))
                })
        })
    };
    let qguest = find_guest("qemu");
    let lguest = find_guest("lxc");
    eprintln!("discovered node={node} qemu={qguest:?} lxc={lguest:?}");

    let mut results: Vec<(&str, Outcome, String)> = Vec::new();
    macro_rules! chk {
        ($name:expr, $call:expr) => {{
            let (o, d) = classify($call.await.map(|_| ()));
            results.push(($name, o, d));
        }};
    }

    // ── cluster / global reads (all response families) ───────────────────────
    chk!("/version", client.get_version_version());
    chk!("/cluster/status", client.get_get_status_cluster_status());
    chk!(
        "/cluster/resources",
        client.get_resources_cluster_resources(None)
    );
    chk!("/cluster/backup", client.get_index_cluster_backup());
    chk!(
        "/cluster/ha/status/current",
        client.get_status_cluster_ha_status_current()
    );
    chk!("/nodes", client.get_index_nodes());
    chk!("/access/users", client.get_index_access_users(None, None));
    chk!("/access/roles", client.get_index_access_roles());
    chk!("/access/domains", client.get_index_access_domains());
    chk!("/access/acl", client.get_read_acl_access_acl());
    chk!("/pools", client.get_index_pools(None, None));
    chk!("/storage", client.get_index_storage(None));

    // ── node-level reads ─────────────────────────────────────────────────────
    chk!(
        "/nodes/{node}/status",
        client.get_status_nodes_node_status(&node)
    );
    chk!(
        "/nodes/{node}/version",
        client.get_version_nodes_node_version(&node)
    );
    chk!(
        "/nodes/{node}/subscription",
        client.get_get_nodes_node_subscription(&node)
    );
    chk!(
        "/nodes/{node}/qemu",
        client.get_vmlist_nodes_node_qemu(&node, None)
    );
    chk!("/nodes/{node}/lxc", client.get_vmlist_nodes_node_lxc(&node));
    chk!(
        "/nodes/{node}/services",
        client.get_index_nodes_node_services(&node)
    );
    chk!(
        "/nodes/{node}/network",
        client.get_index_nodes_node_network(&node, None)
    );
    chk!(
        "/nodes/{node}/disks/list",
        client.get_list_nodes_node_disks_list(&node, None, None, None)
    );
    chk!(
        "/nodes/{node}/storage",
        client.get_index_nodes_node_storage(&node, None, None, None, None, None)
    );

    // ── extended cluster reads (config / ha / replication / firewall / sdn / ceph) ──
    chk!("/cluster/config", client.get_index_cluster_config());
    chk!("/cluster/tasks", client.get_tasks_cluster_tasks());
    chk!(
        "/cluster/ha/resources",
        client.get_index_cluster_ha_resources(None)
    );
    chk!("/cluster/ha/groups", client.get_index_cluster_ha_groups());
    chk!("/cluster/ha/status", client.get_index_cluster_ha_status());
    chk!(
        "/cluster/ha/status/manager_status",
        client.get_manager_status_cluster_ha_status_manager_status()
    );
    chk!(
        "/cluster/replication",
        client.get_index_cluster_replication()
    );
    chk!("/cluster/firewall", client.get_index_cluster_firewall());
    chk!(
        "/cluster/firewall/options",
        client.get_get_options_cluster_firewall_options()
    );
    chk!(
        "/cluster/firewall/rules",
        client.get_get_rules_cluster_firewall_rules()
    );
    chk!(
        "/cluster/firewall/groups",
        client.get_list_security_groups_cluster_firewall_groups()
    );
    chk!(
        "/cluster/firewall/ipset",
        client.get_ipset_index_cluster_firewall_ipset()
    );
    chk!(
        "/cluster/firewall/macros",
        client.get_get_macros_cluster_firewall_macros()
    );
    chk!(
        "/cluster/firewall/refs",
        client.get_refs_cluster_firewall_refs(None)
    );
    chk!("/cluster/sdn", client.get_index_cluster_sdn());
    chk!(
        "/cluster/sdn/zones",
        client.get_index_cluster_sdn_zones(None, None, None)
    );
    chk!(
        "/cluster/sdn/vnets",
        client.get_index_cluster_sdn_vnets(None, None)
    );
    chk!(
        "/cluster/sdn/controllers",
        client.get_index_cluster_sdn_controllers(None, None, None)
    );
    chk!(
        "/cluster/sdn/ipams",
        client.get_index_cluster_sdn_ipams(None)
    );
    chk!("/cluster/sdn/dns", client.get_index_cluster_sdn_dns(None));
    chk!("/cluster/ceph", client.get_cephindex_cluster_ceph());
    chk!(
        "/cluster/ceph/status",
        client.get_status_cluster_ceph_status()
    );

    // ── extended node reads (config / dns / time / report / hosts / tasks / rrd / apt / caps / fw / repl / sdn) ──
    chk!(
        "/nodes/{node}/config",
        client.get_get_config_nodes_node_config(&node, None)
    );
    chk!("/nodes/{node}/dns", client.get_dns_nodes_node_dns(&node));
    chk!("/nodes/{node}/time", client.get_time_nodes_node_time(&node));
    chk!(
        "/nodes/{node}/report",
        client.get_report_nodes_node_report(&node)
    );
    chk!(
        "/nodes/{node}/hosts",
        client.get_get_etc_hosts_nodes_node_hosts(&node)
    );
    chk!(
        "/nodes/{node}/tasks",
        client.get_node_tasks_nodes_node_tasks(
            &node,
            None,
            Some(50),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None
        )
    );
    chk!(
        "/nodes/{node}/rrddata",
        client.get_rrddata_nodes_node_rrddata(
            &node,
            None,
            proxmox::generated::types::GetRrddataNodesNodeRrddataTimeframe::Day
        )
    );
    chk!("/nodes/{node}/apt", client.get_index_nodes_node_apt(&node));
    chk!(
        "/nodes/{node}/apt/repositories",
        client.get_repositories_nodes_node_apt_repositories(&node)
    );
    chk!(
        "/nodes/{node}/apt/versions",
        client.get_versions_nodes_node_apt_versions(&node)
    );
    chk!(
        "/nodes/{node}/capabilities",
        client.get_index_nodes_node_capabilities(&node)
    );
    chk!(
        "/nodes/{node}/capabilities/qemu",
        client.get_qemu_caps_index_nodes_node_capabilities_qemu(&node)
    );
    chk!(
        "/nodes/{node}/firewall",
        client.get_index_nodes_node_firewall(&node)
    );
    chk!(
        "/nodes/{node}/firewall/options",
        client.get_get_options_nodes_node_firewall_options(&node)
    );
    chk!(
        "/nodes/{node}/replication",
        client.get_status_nodes_node_replication(&node, None)
    );
    chk!(
        "/nodes/{node}/ceph",
        client.get_index_nodes_node_ceph(&node)
    );
    chk!(
        "/nodes/{node}/sdn",
        client.get_sdnindex_nodes_node_sdn(&node)
    );

    // ── guest-level reads (skipped if none discovered) ───────────────────────
    if let Some((gn, v)) = &qguest {
        chk!(
            "/nodes/{node}/qemu/{vmid}/status/current",
            client.get_vm_status_nodes_node_qemu_vmid_status_current(gn, *v)
        );
        chk!(
            "/nodes/{node}/qemu/{vmid}/config",
            client.get_vm_config_nodes_node_qemu_vmid_config(gn, *v, None, None)
        );
    }
    if let Some((gn, v)) = &lguest {
        chk!(
            "/nodes/{node}/lxc/{vmid}/status/current",
            client.get_vm_status_nodes_node_lxc_vmid_status_current(gn, *v)
        );
        chk!(
            "/nodes/{node}/lxc/{vmid}/config",
            client.get_vm_config_nodes_node_lxc_vmid_config(gn, *v, None, None)
        );
    }

    // ── report ───────────────────────────────────────────────────────────────
    let mut ok = 0;
    let mut gated = 0;
    let mut http = 0;
    let deser: Vec<_> = results
        .iter()
        .filter(|(_, o, _)| *o == Outcome::Deser)
        .collect();
    eprintln!("\n── live read sweep ──");
    for (name, o, d) in &results {
        match o {
            Outcome::Ok => ok += 1,
            Outcome::Gated => gated += 1,
            Outcome::Http => http += 1,
            Outcome::Deser => {}
        }
        let tag = match o {
            Outcome::Ok => "OK   ",
            Outcome::Gated => "GATED",
            Outcome::Http => "HTTP ",
            Outcome::Deser => "DESER",
        };
        eprintln!("  {tag} {name} {d}");
    }
    eprintln!(
        "\n{ok} OK · {gated} GATED(ACL) · {http} HTTP/env · {} DESER-FAIL",
        deser.len()
    );

    assert!(
        deser.is_empty(),
        "{} endpoint(s) returned a body the typed model could not deserialize: {:#?}",
        deser.len(),
        deser
    );
}
