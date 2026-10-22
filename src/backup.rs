use std::path::Path;

use anyhow::{Context, Result, anyhow};
use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::backend_def::backup_kind_backend_def;
use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json::{self, Value, json};

use crate::GuestKind;

pub const PVECONFIG_PREFIX: &str = "proxmox.__backup_pveconfig";
pub const VM_PREFIX: &str = "proxmox.__backup_vm";
pub const LXC_PREFIX: &str = "proxmox.__backup_lxc";
pub const LXC_BIND_PREFIX: &str = "proxmox.__backup_lxcbind";
pub const NODE_STATE_PREFIX: &str = "proxmox.__backup_pvenodestate";

pub const PUT_CLUSTER_OPTIONS_OP: &str = "proxmox.put_set_options_cluster_options";

fn reaching(def: BackendDef, ops: &[&str]) -> BackendDef {
    BackendDef {
        reaches: ops.iter().map(|o| o.to_string()).collect(),
        ..def
    }
}

pub fn backend_defs() -> Vec<BackendDef> {
    vec![
        reaching(
            backup_kind_backend_def("pve-config", PVECONFIG_PREFIX),
            &[PUT_CLUSTER_OPTIONS_OP],
        ),
        reaching(
            backup_kind_backend_def("vm", VM_PREFIX),
            &[config_op(GuestKind::Qemu, "put")],
        ),
        reaching(
            backup_kind_backend_def("lxc", LXC_PREFIX),
            &[config_op(GuestKind::Lxc, "put")],
        ),
        backup_kind_backend_def("lxc-bind", LXC_BIND_PREFIX),
        reaching(
            backup_kind_backend_def("pve-node-state", NODE_STATE_PREFIX),
            &crate::node_state::REACHES,
        ),
    ]
}

pub fn dispatch(
    name: &str,
    args: plugin_toolkit::serde_json::Value,
) -> Option<Result<plugin_toolkit::serde_json::Value, plugin_toolkit::serde_json::Value>> {
    let (kind, op) = match_prefix(name)?;
    let args_json = args.to_string();
    Some(plugin_toolkit::reactor::block_on(async move {
        run(kind, op, &args_json)
            .await
            .map(|s| {
                plugin_toolkit::serde_json::from_str(&s)
                    .unwrap_or(plugin_toolkit::serde_json::Value::String(s))
            })
            .map_err(|e| plugin_toolkit::serde_json::Value::String(e.to_string()))
    }))
}

#[derive(Clone, Copy)]
enum Kind {
    PveConfig,
    Vm,
    Lxc,
    LxcBind,
    NodeState,
}

fn match_prefix(name: &str) -> Option<(Kind, &str)> {
    for (prefix, kind) in [
        (PVECONFIG_PREFIX, Kind::PveConfig),
        (VM_PREFIX, Kind::Vm),
        (LXC_PREFIX, Kind::Lxc),
        (LXC_BIND_PREFIX, Kind::LxcBind),
        (NODE_STATE_PREFIX, Kind::NodeState),
    ] {
        if let Some(op) = name.strip_prefix(prefix).and_then(|s| s.strip_prefix('.')) {
            return Some((kind, op));
        }
    }
    None
}

async fn run(kind: Kind, op: &str, args_json: &str) -> Result<String> {
    match (kind, op) {
        (Kind::PveConfig, "instances") => Ok(json!(["default"]).to_string()),
        (Kind::PveConfig, "layout") => Ok(json!(["cluster", "proxmox", "pve-config"]).to_string()),
        (Kind::PveConfig, "backup") => {
            let (dir, _instance) = decode_backup(args_json)?;
            pveconfig_backup(&dir).await
        }
        (Kind::PveConfig, "restore") => {
            let (dir, _instance) = decode_backup(args_json)?;
            pveconfig_restore(&dir).await
        }

        (Kind::Vm | Kind::Lxc, "instances") => guest_instances(guest_kind(kind)).await,
        (Kind::Vm | Kind::Lxc, "layout") => {
            let instance = decode_instance(args_json)?;
            let class = match kind {
                Kind::Vm => "proxmox-vm",
                _ => "proxmox-lxc",
            };
            Ok(json!(["guests", class, instance]).to_string())
        }
        (Kind::Vm | Kind::Lxc, "backup") => {
            let (dir, instance) = decode_backup(args_json)?;
            guest_backup(guest_kind(kind), &instance, &dir).await
        }
        (Kind::Vm | Kind::Lxc, "restore") => {
            let (dir, instance) = decode_backup(args_json)?;
            guest_restore(guest_kind(kind), &instance, &dir).await
        }

        (Kind::LxcBind, "instances") => Ok(serde_json::to_string(
            &crate::bind_mounts::kind_instances(&crate::bind_mounts::local_plans()),
        )?),
        (Kind::LxcBind, "layout") => {
            let instance = decode_instance(args_json)?;
            Ok(json!(["guests", "proxmox-lxc-bind", instance]).to_string())
        }
        (Kind::LxcBind, "backup") => {
            let (dir, instance) = decode_backup(args_json)?;
            let plan = crate::bind_mounts::local_plan(&instance)?;
            let n = crate::bind_mounts::capture(
                &crate::bind_mounts::UnprivilegedTree,
                &plan,
                Path::new(&dir),
            )?;
            Ok(json!({
                "checksum": Value::Null,
                "note": format!("copied {n} file(s) of bind-mount app state for {instance}"),
            })
            .to_string())
        }
        (Kind::LxcBind, "restore") => {
            let (dir, instance) = decode_backup(args_json)?;
            let plan = crate::bind_mounts::local_plan(&instance)?;
            crate::bind_mounts::restore(
                &crate::bind_mounts::UnprivilegedTree,
                &plan,
                Path::new(&dir),
            )?;
            Ok(Value::Null.to_string())
        }

        (Kind::NodeState, "instances") => Ok(serde_json::to_string(
            &crate::node_state::instances().await,
        )?),
        (Kind::NodeState, "layout") => {
            let instance = decode_instance(args_json)?;
            Ok(json!(["hosts", "proxmox-node-state", instance]).to_string())
        }
        (Kind::NodeState, "backup") => {
            let (dir, instance) = decode_backup(args_json)?;
            Ok(crate::node_state::backup(&dir, &instance)
                .await?
                .to_string())
        }
        (Kind::NodeState, "restore") => {
            let (dir, _instance) = decode_backup(args_json)?;
            Ok(crate::node_state::restore(&dir)?.to_string())
        }

        (_, other) => Err(anyhow!("proxmox backup: unknown op '{other}'")),
    }
}

fn guest_kind(kind: Kind) -> GuestKind {
    match kind {
        Kind::Lxc => GuestKind::Lxc,
        _ => GuestKind::Qemu,
    }
}

fn decode_instance(args_json: &str) -> Result<String> {
    let v: Value = serde_json::from_str(args_json).context("backup: parse instance args")?;
    Ok(v.get("instance")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string())
}

fn decode_backup(args_json: &str) -> Result<(String, String)> {
    let v: Value = serde_json::from_str(args_json).context("backup: parse backup args")?;
    let dir = v
        .get("payload_dir")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("backup: missing payload_dir"))?
        .to_string();
    let instance = v
        .get("instance")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();
    Ok((dir, instance))
}

async fn guest_instances(kind: GuestKind) -> Result<String> {
    use crate::responses::ResourceType;
    let want = match kind {
        GuestKind::Qemu => ResourceType::Qemu,
        GuestKind::Lxc => ResourceType::Lxc,
    };
    let mut ids = Vec::new();
    for name in crate::tools::enabled_endpoint_names() {
        let items = match crate::responses::cluster_resources(&name, Some("vm")) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(endpoint = %name, error = %e, "backup instances: cluster resources failed");
                continue;
            }
        };
        for r in items {
            if r.type_ != want {
                continue;
            }
            let (Some(node), Some(vmid)) = (r.node, r.vmid) else {
                continue;
            };
            if node.is_empty() || vmid <= 0 {
                continue;
            }
            ids.push(format!("{node}/{vmid}"));
        }
    }
    ids.sort();
    ids.dedup();
    Ok(serde_json::to_string(&ids)?)
}

async fn guest_backup(kind: GuestKind, instance: &str, dir: &str) -> Result<String> {
    let (node, vmid) = parse_instance(instance)?;
    let endpoint = resolve_endpoint_for_node(&node).await?;
    let data = plugin_toolkit::api::call::<Value>(
        config_op(kind, "get"),
        &endpoint,
        json!({ "node": node, "vmid": vmid }),
    )
    .with_context(|| format!("backup: fetch config for {instance}"))?;
    let keys = data.as_object().map(|m| m.len()).unwrap_or(0);
    write_json(dir, "config.json", &data)?;
    Ok(json!({
        "checksum": Value::Null,
        "note": format!("captured {} config keys for {}/{}/{}", keys, node, kind.as_str(), vmid),
    })
    .to_string())
}

async fn guest_restore(kind: GuestKind, instance: &str, dir: &str) -> Result<String> {
    let (node, vmid) = parse_instance(instance)?;
    let data = read_json(dir, "config.json")?;
    let obj = data
        .as_object()
        .ok_or_else(|| anyhow!("restore: config.json is not an object"))?;

    const SKIP: &[&str] = &["digest", "meta", "lock"];
    let args = json!({ "node": node, "vmid": vmid, "body": body_args(obj, SKIP) });

    let endpoint = resolve_endpoint_for_node(&node).await?;
    plugin_toolkit::api::call::<Value>(config_op(kind, "put"), &endpoint, args)
        .with_context(|| format!("restore: put config for {instance}"))?;
    Ok(Value::Null.to_string())
}

const PVECONFIG_CAPTURES: &[(&str, &str)] = &[
    ("storage", "storage.json"),
    ("access/users", "users.json"),
    ("access/acl", "acl.json"),
    ("cluster/options", "datacenter.json"),
];

async fn pveconfig_backup(dir: &str) -> Result<String> {
    let endpoint = first_enabled_endpoint()
        .await
        .context("pve-config backup: no reachable endpoint")?;
    let mut captured = Vec::new();
    for (path, file) in PVECONFIG_CAPTURES {
        match crate::api_path::get(&endpoint, path) {
            Ok(data) => {
                write_json(dir, file, &data)?;
                captured.push(*file);
            }
            Err(e) => {
                tracing::warn!(path, error = %e, "pve-config backup: capture failed; skipping");
            }
        }
    }
    Ok(json!({
        "checksum": Value::Null,
        "note": format!("captured cluster config: {}", captured.join(", ")),
    })
    .to_string())
}

async fn pveconfig_restore(dir: &str) -> Result<String> {
    let datacenter = read_json(dir, "datacenter.json").ok();
    let args = datacenter
        .as_ref()
        .and_then(Value::as_object)
        .map(|obj| body_args(obj, &["digest"]))
        .unwrap_or_default();
    if !args.is_empty() {
        let endpoint = first_enabled_endpoint()
            .await
            .context("pve-config restore: no reachable endpoint")?;
        plugin_toolkit::api::call::<Value>(
            PUT_CLUSTER_OPTIONS_OP,
            &endpoint,
            json!({ "body": args }),
        )
        .context("pve-config restore: put cluster options")?;
    }
    Ok(Value::Null.to_string())
}

pub(crate) fn enc(s: &str) -> String {
    plugin_toolkit::progenitor_client::encode_path(s)
}

pub(crate) fn form_pairs(
    obj: &serde_json::Map<String, Value>,
    skip: &[&str],
) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for (k, v) in obj {
        if skip.contains(&k.as_str()) {
            continue;
        }
        let s = match v {
            Value::String(s) => s.clone(),
            Value::Null => continue,
            other => other.to_string(),
        };
        pairs.push((k.clone(), s));
    }
    pairs
}

pub(crate) async fn put_form(
    http: &reqwest::Client,
    url: &str,
    pairs: &[(String, String)],
) -> Result<()> {
    send_form(http.put(url), "PUT", url, pairs)
        .await
        .map(|_| ())
}

pub(crate) async fn post_form_data(
    http: &reqwest::Client,
    url: &str,
    pairs: &[(String, String)],
) -> Result<Value> {
    let body = send_form(http.post(url), "POST", url, pairs).await?;
    let mut v: Value =
        serde_json::from_str(&body).map_err(|e| anyhow!("POST {url}: parse: {e}"))?;
    match v.as_object_mut().and_then(|m| m.remove("data")) {
        Some(data) => Ok(data),
        None => Err(anyhow!("POST {url}: response missing 'data' envelope")),
    }
}

async fn send_form(
    req: reqwest::RequestBuilder,
    method: &str,
    url: &str,
    pairs: &[(String, String)],
) -> Result<String> {
    use plugin_toolkit::delegated_http::header::HeaderValue;
    use plugin_toolkit::delegated_http::serialize::ToQuery;
    use plugin_toolkit::progenitor_client::QueryParam;
    let params: Vec<QueryParam> = pairs
        .iter()
        .map(|(k, v)| QueryParam::new(k.as_str(), v))
        .collect();
    let body = params
        .as_slice()
        .to_query_string()
        .map_err(|e| anyhow!("form encode: {e}"))?;
    let resp = req
        .header(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .body(body.into_bytes())
        .send()
        .await
        .map_err(|e| anyhow!("{method} {url}: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("{method} {url}: HTTP {}: {body}", status.as_u16()));
    }
    Ok(body)
}

fn parse_instance(instance: &str) -> Result<(String, u64)> {
    let (node, vmid) = instance
        .split_once('/')
        .ok_or_else(|| anyhow!("backup: malformed instance '{instance}' (want <node>/<vmid>)"))?;
    let vmid: u64 = vmid
        .parse()
        .map_err(|_| anyhow!("backup: non-numeric vmid in '{instance}'"))?;
    Ok((node.to_string(), vmid))
}

pub(crate) async fn resolve_endpoint_for_node(node: &str) -> Result<String> {
    for name in crate::tools::enabled_endpoint_names() {
        match crate::api_path::get(&name, "nodes") {
            Ok(nodes) => {
                let hit = nodes.as_array().is_some_and(|arr| {
                    arr.iter()
                        .any(|n| n.get("node").and_then(Value::as_str) == Some(node))
                });
                if hit {
                    return Ok(name);
                }
            }
            Err(e) => {
                tracing::warn!(endpoint = %name, error = %e, "backup: list nodes failed");
            }
        }
    }
    Err(anyhow!("backup: no enabled endpoint hosts node '{node}'"))
}

async fn first_enabled_endpoint() -> Result<String> {
    for name in crate::tools::enabled_endpoint_names() {
        match crate::api_path::get(&name, "nodes") {
            Ok(_) => return Ok(name),
            Err(e) => {
                tracing::warn!(endpoint = %name, error = %e, "backup: endpoint unreachable");
            }
        }
    }
    Err(anyhow!("backup: no enabled endpoint resolved"))
}

pub(crate) fn config_op(kind: GuestKind, method: &str) -> &'static str {
    match (kind, method) {
        (GuestKind::Qemu, "get") => "proxmox.get_vm_config_nodes_node_qemu_vmid_config",
        (GuestKind::Lxc, "get") => "proxmox.get_vm_config_nodes_node_lxc_vmid_config",
        (GuestKind::Qemu, _) => "proxmox.put_update_vm_nodes_node_qemu_vmid_config",
        (GuestKind::Lxc, _) => "proxmox.put_update_vm_nodes_node_lxc_vmid_config",
    }
}

pub(crate) fn body_args(
    obj: &serde_json::Map<String, Value>,
    skip: &[&str],
) -> serde_json::Map<String, Value> {
    obj.iter()
        .filter(|(k, v)| !skip.contains(&k.as_str()) && !v.is_null())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

pub(crate) async fn raw_get_data(
    http: &reqwest::Client,
    base_url: &str,
    path: &str,
) -> Result<Value> {
    let url = format!("{}/{}", base_url.trim_end_matches('/'), path);
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("GET {path}: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| anyhow!("GET {path}: read body: {e}"))?;
    if !status.is_success() {
        return Err(anyhow!("GET {path}: HTTP {}: {body}", status.as_u16()));
    }
    let mut v: Value =
        serde_json::from_str(&body).map_err(|e| anyhow!("GET {path}: parse: {e}"))?;
    match v.as_object_mut().and_then(|m| m.remove("data")) {
        Some(data) => Ok(data),
        None => Err(anyhow!("GET {path}: response missing 'data' envelope")),
    }
}

fn write_json(dir: &str, file: &str, value: &Value) -> Result<()> {
    let path = Path::new(dir).join(file);
    let bytes = serde_json::to_vec_pretty(value).context("backup: serialize json")?;
    std::fs::write(&path, bytes).with_context(|| format!("backup: write {}", path.display()))?;
    Ok(())
}

fn read_json(dir: &str, file: &str) -> Result<Value> {
    let path = Path::new(dir).join(file);
    let bytes =
        std::fs::read(&path).with_context(|| format!("restore: read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("restore: parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lxc_bind_prefix_is_not_taken_by_the_lxc_kind() {
        assert!(matches!(
            match_prefix("proxmox.__backup_lxcbind.instances"),
            Some((Kind::LxcBind, "instances"))
        ));
        assert!(matches!(
            match_prefix("proxmox.__backup_lxc.backup"),
            Some((Kind::Lxc, "backup"))
        ));
        let names: Vec<String> = backend_defs().into_iter().map(|d| d.name).collect();
        assert!(names.contains(&"lxc-bind".to_string()), "{names:?}");
    }
}
