use serde::Deserialize;

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

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum StatusItemType {
    Cluster,
    Node,
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct StatusItem {
    #[serde(rename = "type")]
    type_: StatusItemType,
    name: String,
    ip: Option<String>,
    online: Option<bool>,
    nodeid: Option<i64>,
    local: Option<bool>,
    quorate: Option<bool>,
}

pub fn fetch_cluster_status(endpoint: &str) -> anyhow::Result<ClusterStatus> {
    let items: Vec<StatusItem> = plugin_toolkit::api::call(
        "proxmox.get_get_status_cluster_status",
        endpoint,
        serde_json::json!({}),
    )
    .map_err(|e| anyhow::anyhow!("proxmox cluster_status: {e}"))?;

    let mut cluster_name: Option<String> = None;
    let mut quorate: Option<bool> = None;
    let mut nodes: Vec<ClusterNode> = Vec::new();

    for item in items {
        match item.type_ {
            StatusItemType::Cluster => {
                cluster_name = Some(item.name);
                quorate = item.quorate;
            }
            StatusItemType::Node => {
                nodes.push(ClusterNode {
                    name: item.name,
                    ip: item.ip,
                    online: item.online,
                    node_id: item.nodeid,
                    local: item.local,
                });
            }
            StatusItemType::Other => {}
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

    fn run_with_reply<T>(
        reply: Result<serde_json::Value, String>,
        f: impl FnOnce(ClusterStatus) -> T,
    ) -> Result<T, anyhow::Error> {
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, json: &str| {
                assert_eq!(cap, "api.call");
                assert!(json.contains("proxmox.get_get_status_cluster_status"));
                reply.clone().map(|v| v.to_string())
            }),
            || fetch_cluster_status("lab").map(f),
        )
    }

    #[test]
    fn three_node_cluster_partitions_envelope_and_members() {
        let reply = serde_json::json!([
            { "id": "cluster", "type": "cluster", "name": "lab", "quorate": true, "nodes": 3, "version": 7 },
            { "id": "node/a", "type": "node", "name": "a", "ip": "192.0.2.1", "online": true,  "nodeid": 1, "local": true },
            { "id": "node/b", "type": "node", "name": "b", "ip": "192.0.2.2", "online": true,  "nodeid": 2 },
            { "id": "node/c", "type": "node", "name": "c", "ip": "192.0.2.3", "online": false, "nodeid": 3 },
        ]);
        run_with_reply(Ok(reply), |status| {
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
        let reply = serde_json::json!([
            { "id": "node/solo", "type": "node", "name": "solo", "ip": "192.0.2.10", "online": true, "local": true },
        ]);
        run_with_reply(Ok(reply), |status| {
            assert_eq!(status.name, None);
            assert_eq!(status.quorate, None);
            assert_eq!(status.nodes.len(), 1);
            assert_eq!(status.nodes[0].name, "solo");
        })
        .unwrap();
    }

    #[test]
    fn empty_array_yields_empty_status_not_error() {
        run_with_reply(Ok(serde_json::json!([])), |status| {
            assert_eq!(status.name, None);
            assert_eq!(status.quorate, None);
            assert!(status.nodes.is_empty());
        })
        .unwrap();
    }

    #[test]
    fn upstream_error_surfaces_with_context() {
        let err = run_with_reply(Err("upstream 503".into()), |_| ()).unwrap_err();
        assert!(err.to_string().contains("cluster_status"));
    }
}
