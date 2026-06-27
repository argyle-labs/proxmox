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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn install_crypto() {
        _ = rustls::crypto::ring::default_provider().install_default();
    }

    async fn client_against(server: &MockServer) -> generated::Client {
        install_crypto();
        let http = reqwest::Client::builder().build().unwrap();
        generated::Client::new_with_client(&server.uri(), http)
    }

    #[tokio::test]
    async fn three_node_cluster_partitions_envelope_and_members() {
        let server = MockServer::start().await;
        let body = serde_json::json!([
            { "id": "cluster", "type": "cluster", "name": "lab", "quorate": true, "nodes": 3, "version": 7 },
            { "id": "node/a", "type": "node", "name": "a", "ip": "192.0.2.1", "online": true,  "nodeid": 1, "local": true },
            { "id": "node/b", "type": "node", "name": "b", "ip": "192.0.2.2", "online": true,  "nodeid": 2 },
            { "id": "node/c", "type": "node", "name": "c", "ip": "192.0.2.3", "online": false, "nodeid": 3 },
        ]);
        Mock::given(method("GET"))
            .and(path("/cluster/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let client = client_against(&server).await;
        let status = fetch_cluster_status(&client).await.unwrap();

        assert_eq!(status.name.as_deref(), Some("lab"));
        assert_eq!(status.quorate, Some(true));
        assert_eq!(status.nodes.len(), 3);
        let c = status.nodes.iter().find(|n| n.name == "c").unwrap();
        assert_eq!(c.ip.as_deref(), Some("192.0.2.3"));
        assert_eq!(c.online, Some(false));
        assert_eq!(c.node_id, Some(3));
        let a = status.nodes.iter().find(|n| n.name == "a").unwrap();
        assert_eq!(a.local, Some(true));
    }

    #[tokio::test]
    async fn standalone_host_has_no_cluster_envelope() {
        let server = MockServer::start().await;
        let body = serde_json::json!([
            { "id": "node/solo", "type": "node", "name": "solo", "ip": "192.0.2.10", "online": true, "local": true },
        ]);
        Mock::given(method("GET"))
            .and(path("/cluster/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let status = fetch_cluster_status(&client_against(&server).await)
            .await
            .unwrap();
        assert_eq!(status.name, None);
        assert_eq!(status.quorate, None);
        assert_eq!(status.nodes.len(), 1);
        assert_eq!(status.nodes[0].name, "solo");
    }

    #[tokio::test]
    async fn empty_array_yields_empty_status_not_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cluster/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let status = fetch_cluster_status(&client_against(&server).await)
            .await
            .unwrap();
        assert_eq!(status.name, None);
        assert_eq!(status.quorate, None);
        assert!(status.nodes.is_empty());
    }

    #[tokio::test]
    async fn upstream_5xx_surfaces_as_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/cluster/status"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let err = fetch_cluster_status(&client_against(&server).await)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cluster_status"));
    }
}
