//! Proxmox cluster-status wrapper.
//!
//! Wraps the generated `GET /cluster/status` call into a typed shape that
//! splits the single response array into the cluster envelope (name +
//! quorate) and its member nodes. A standalone Proxmox host (no cluster
//! configured) returns an array with only a node-typed item — we surface
//! that as `name: None, quorate: None, nodes: [that single node]` instead
//! of erroring, matching how the systems UI wants to render it.
//!
//! Consumed by `tools::proxmox_cluster_status` / `proxmox_cluster_list`
//! and by the frontend systems map for grouping peers by cluster.

use crate::generated::{self, types as gtypes};

#[derive(Debug, Clone)]
pub struct ClusterStatus {
    /// Cluster name. `None` when the endpoint is standalone (no
    /// corosync cluster configured).
    pub name: Option<String>,
    /// Quorate flag from the cluster envelope. `None` on standalone.
    pub quorate: Option<bool>,
    /// All node entries reported by `/cluster/status`. For standalone
    /// this is the single responding node.
    pub nodes: Vec<ClusterNode>,
}

#[derive(Debug, Clone)]
pub struct ClusterNode {
    pub name: String,
    pub ip: Option<String>,
    pub online: Option<bool>,
    pub node_id: Option<i64>,
    pub local: Option<bool>,
}

/// Hit `/cluster/status` on the supplied client and partition the
/// response into cluster envelope + node list.
pub async fn fetch_cluster_status(client: &generated::Client) -> anyhow::Result<ClusterStatus> {
    let items = client
        .get_get_status_cluster_status()
        .await
        .map_err(|e| anyhow::anyhow!("proxmox cluster_status: {e}"))?
        .into_inner();

    let mut cluster_name: Option<String> = None;
    let mut quorate: Option<bool> = None;
    let mut nodes: Vec<ClusterNode> = Vec::new();

    for item in items {
        match item.type_ {
            gtypes::GetGetStatusClusterStatusResponseItemType::Cluster => {
                cluster_name = Some(item.name);
                quorate = item.quorate;
            }
            gtypes::GetGetStatusClusterStatusResponseItemType::Node => {
                nodes.push(ClusterNode {
                    name: item.name,
                    ip: item.ip,
                    online: item.online,
                    node_id: item.nodeid,
                    local: item.local,
                });
            }
        }
    }

    Ok(ClusterStatus {
        name: cluster_name,
        quorate,
        nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    /// Build a generated client whose HTTP rides orca's `http.request`
    /// capability sink instead of a real socket. Base URL is arbitrary —
    /// the sink intercepts every request regardless of host.
    fn client() -> generated::Client {
        Config::new(
            "https://pve.test",
            "user@pve!auto",
            "deadbeef-1111-2222-3333-444444444444",
        )
        .build_generated_client()
        .unwrap()
    }

    /// Encode an `HttpResponse`-shaped reply JSON: `{status, headers, body}`
    /// where `body` is the byte array of `data`, serialized envelope-wrapped
    /// exactly as the Proxmox wire returns it (`{"data": <payload>}`).
    fn envelope_reply(status: u16, data: serde_json::Value) -> String {
        // PVE wraps every body as `{"data": <payload>}`; the JSON content-type
        // is what triggers the transport-layer envelope unwrapper.
        let body = serde_json::to_vec(&serde_json::json!({ "data": data })).unwrap();
        serde_json::json!({
            "status": status,
            "headers": [["content-type", "application/json"]],
            "body": body,
        })
        .to_string()
    }

    /// Install a cap sink that answers every `http.request` with `reply`,
    /// then run `fetch_cluster_status` on a current-thread runtime (the shim
    /// calls the thread-local sink synchronously from inside async code).
    fn run_with_reply<T>(
        reply: String,
        f: impl FnOnce(ClusterStatus) -> T,
    ) -> Result<T, anyhow::Error> {
        let mut out = None;
        let captured = std::cell::RefCell::new(&mut out);
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, _json: &str| {
                assert_eq!(cap, "http.request");
                Ok(reply.clone())
            }),
            || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let status = fetch_cluster_status(&client()).await?;
                    **captured.borrow_mut() = Some(f(status));
                    Ok::<(), anyhow::Error>(())
                })
            },
        )?;
        Ok(out.unwrap())
    }

    #[test]
    fn three_node_cluster_partitions_envelope_and_members() {
        let reply = envelope_reply(
            200,
            serde_json::json!([
                { "id": "cluster", "type": "cluster", "name": "lab", "quorate": true, "nodes": 3, "version": 7 },
                { "id": "node/a", "type": "node", "name": "a", "ip": "192.0.2.1", "online": true,  "nodeid": 1, "local": true },
                { "id": "node/b", "type": "node", "name": "b", "ip": "192.0.2.2", "online": true,  "nodeid": 2 },
                { "id": "node/c", "type": "node", "name": "c", "ip": "192.0.2.3", "online": false, "nodeid": 3 },
            ]),
        );
        run_with_reply(reply, |status| {
            assert_eq!(status.name.as_deref(), Some("lab"));
            assert_eq!(status.quorate, Some(true));
            assert_eq!(status.nodes.len(), 3);
            let c = status.nodes.iter().find(|n| n.name == "c").unwrap();
            assert_eq!(c.ip.as_deref(), Some("192.0.2.3"));
            assert_eq!(c.online, Some(false));
            assert_eq!(c.node_id, Some(3));
            let a = status.nodes.iter().find(|n| n.name == "a").unwrap();
            assert_eq!(a.local, Some(true));
        })
        .unwrap();
    }

    #[test]
    fn standalone_host_has_no_cluster_envelope() {
        let reply = envelope_reply(
            200,
            serde_json::json!([
                { "id": "node/solo", "type": "node", "name": "solo", "ip": "192.0.2.10", "online": true, "local": true },
            ]),
        );
        run_with_reply(reply, |status| {
            assert_eq!(status.name, None);
            assert_eq!(status.quorate, None);
            assert_eq!(status.nodes.len(), 1);
            assert_eq!(status.nodes[0].name, "solo");
        })
        .unwrap();
    }

    #[test]
    fn empty_array_yields_empty_status_not_error() {
        let reply = envelope_reply(200, serde_json::json!([]));
        run_with_reply(reply, |status| {
            assert_eq!(status.name, None);
            assert_eq!(status.quorate, None);
            assert!(status.nodes.is_empty());
        })
        .unwrap();
    }

    #[test]
    fn upstream_5xx_surfaces_as_error() {
        // A 503 with an empty body — the generated client surfaces the
        // non-success status as an error carrying the call context.
        let reply = serde_json::json!({ "status": 503, "headers": [], "body": [] }).to_string();
        let err = run_with_reply(reply, |_| ()).unwrap_err();
        assert!(err.to_string().contains("cluster_status"));
    }
}
