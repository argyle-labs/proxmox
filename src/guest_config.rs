use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::backup::config_op;
use crate::guest_label::guests;

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GuestConfigArgs {
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub vmid: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GuestConfig {
    pub endpoint: String,
    pub node: String,
    pub kind: String,
    pub vmid: u64,
    pub config: Value,
}

pub fn guest_config(endpoint: &str, vmid: u64) -> Result<GuestConfig> {
    let (node, kind, ..) = guests(endpoint, None)?
        .into_iter()
        .find(|(_, _, id, _)| *id == vmid)
        .ok_or_else(|| anyhow!("guest {vmid} not found on {endpoint}"))?;
    let config: Value = plugin_toolkit::api::call(
        config_op(kind, "get"),
        endpoint,
        json!({ "node": node, "vmid": vmid }),
    )
    .map_err(|e| e.context(format!("{} {vmid} config", kind.as_str())))?;
    Ok(GuestConfig {
        endpoint: endpoint.to_string(),
        node,
        kind: kind.as_str().to_string(),
        vmid,
        config,
    })
}

/// Read a VM or LXC's PVE config by vmid; the node is resolved from cluster
/// resources.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.config",
    execute_gated = false,
    role = "read",
    tool_callable = true,
    reaches = [
        "proxmox.get_resources_cluster_resources",
        "proxmox.get_vm_config_nodes_node_qemu_vmid_config",
        "proxmox.get_vm_config_nodes_node_lxc_vmid_config"
    ]
)]
async fn proxmox_guest_config(args: GuestConfigArgs, _ctx: &ToolCtx) -> Result<GuestConfig> {
    guest_config(&args.endpoint, args.vmid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::record_api_calls;

    fn routes(method: &str, path: &str) -> String {
        match (method, path) {
            (_, "/cluster/resources") => r#"[
                {"type":"lxc","node":"thor","vmid":112,"name":"sonarr"},
                {"type":"qemu","node":"odin","vmid":200,"name":"win"}
            ]"#
            .into(),
            ("GET", "/nodes/thor/lxc/112/config") => {
                r#"{"hostname":"sonarr","unprivileged":1,"features":"nesting=1"}"#.into()
            }
            ("GET", "/nodes/odin/qemu/200/config") => r#"{"name":"win","cores":4}"#.into(),
            _ => "null".into(),
        }
    }

    #[test]
    fn lxc_config_is_read_from_the_resolved_node() {
        let (out, calls) = record_api_calls(routes, || guest_config("pve", 112));
        let out = out.unwrap();
        assert_eq!((out.node.as_str(), out.kind.as_str()), ("thor", "lxc"));
        assert_eq!(out.config["unprivileged"], 1);
        assert_eq!(out.config["features"], "nesting=1");
        assert!(calls.iter().all(|c| c.0 == "GET"));
    }

    #[test]
    fn vm_config_uses_the_qemu_path() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 200));
        let out = out.unwrap();
        assert_eq!((out.node.as_str(), out.kind.as_str()), ("odin", "qemu"));
        assert_eq!(out.config["cores"], 4);
    }

    #[test]
    fn unknown_vmid_is_an_error() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 999));
        assert!(out.unwrap_err().to_string().contains("guest 999 not found"));
    }
}
