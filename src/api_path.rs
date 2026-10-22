use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use plugin_toolkit::serde_json::{Map, Value};

struct Op {
    tool: String,
    method: String,
    segments: Vec<String>,
    types: Vec<(String, String)>,
}

fn ops() -> &'static [Op] {
    static OPS: OnceLock<Vec<Op>> = OnceLock::new();
    OPS.get_or_init(|| {
        let surface: Value =
            plugin_toolkit::serde_json::from_slice(crate::API_SURFACE).unwrap_or_default();
        surface["ops"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|o| {
                Some(Op {
                    tool: o["tool"].as_str()?.to_string(),
                    method: o["method"].as_str()?.to_ascii_uppercase(),
                    segments: split(o["path"].as_str()?),
                    types: o["params"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|p| {
                            Some((
                                p["name"].as_str()?.to_string(),
                                p["schema"]["type"].as_str()?.to_string(),
                            ))
                        })
                        .collect(),
                })
            })
            .collect()
    })
}

fn split(path: &str) -> Vec<String> {
    path.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn typed(op: &Op, name: &str, raw: &str) -> Value {
    let ty = op
        .types
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, t)| t.as_str());
    match ty {
        Some("integer") => raw.parse::<i64>().map_or_else(|_| raw.into(), Value::from),
        Some("number") => raw.parse::<f64>().map_or_else(|_| raw.into(), Value::from),
        Some("boolean") => match raw {
            "1" | "true" => Value::Bool(true),
            "0" | "false" => Value::Bool(false),
            _ => raw.into(),
        },
        _ => raw.into(),
    }
}

fn decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find(method: &str, path: &str) -> Result<(&'static Op, Map<String, Value>)> {
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    let segments = split(route);
    let op = ops()
        .iter()
        .filter(|o| o.method == method && o.segments.len() == segments.len())
        .filter_map(|o| {
            let mut literal = 0;
            for (t, s) in o.segments.iter().zip(&segments) {
                if t.starts_with('{') {
                    continue;
                }
                if t != s {
                    return None;
                }
                literal += 1;
            }
            Some((literal, o))
        })
        .max_by_key(|(literal, _)| *literal)
        .map(|(_, o)| o)
        .ok_or_else(|| anyhow!("no proxmox api op for {method} {route}"))?;
    let mut args = Map::new();
    for (t, s) in op.segments.iter().zip(&segments) {
        if let Some(name) = t.strip_prefix('{').and_then(|t| t.strip_suffix('}')) {
            args.insert(name.to_string(), typed(op, name, &decode(s)));
        }
    }
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = decode(k);
        let v = decode(v);
        args.insert(k.clone(), typed(op, &k, &v));
    }
    Ok((op, args))
}

#[cfg(test)]
pub(crate) fn resolve(method: &str, path: &str) -> Result<(String, Value)> {
    let (op, args) = find(method, path)?;
    Ok((op.tool.clone(), Value::Object(args)))
}

pub(crate) fn get(endpoint: &str, path: &str) -> Result<Value> {
    send("GET", endpoint, path, &[])
}

pub(crate) fn send(
    method: &str,
    endpoint: &str,
    path: &str,
    body: &[(String, String)],
) -> Result<Value> {
    let (op, mut args) = find(method, path)?;
    if !body.is_empty() {
        let body: Map<String, Value> = body
            .iter()
            .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
            .collect();
        args.insert("body".into(), Value::Object(body));
    }
    plugin_toolkit::api::call(&op.tool, endpoint, Value::Object(args))
        .with_context(|| format!("{method} {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    #[test]
    fn resolves_path_params_and_typed_query() {
        let (op, args) = resolve("GET", "nodes/thor/tasks?typefilter=vzdump&limit=100").unwrap();
        assert_eq!(op, "proxmox.get_node_tasks_nodes_node_tasks");
        assert_eq!(
            args,
            json!({"node": "thor", "typefilter": "vzdump", "limit": 100})
        );
    }

    #[test]
    fn literal_segments_win_over_placeholders() {
        let (op, args) = resolve("GET", "nodes/thor/lxc/110/config").unwrap();
        assert_eq!(op, "proxmox.get_vm_config_nodes_node_lxc_vmid_config");
        assert_eq!(args, json!({"node": "thor", "vmid": 110}));
        let (op, _) = resolve("GET", "cluster/resources?type=vm").unwrap();
        assert_eq!(op, "proxmox.get_resources_cluster_resources");
    }

    #[test]
    fn body_pairs_ride_the_body_param_and_path_segments_decode() {
        let (_, calls) = crate::test_support::record_api_calls(
            |_, _| "null".to_string(),
            || {
                send(
                    "PUT",
                    "pve",
                    "cluster/backup/job%2Da",
                    &[
                        ("enabled".into(), "1".into()),
                        ("schedule".into(), "sun 01:00".into()),
                    ],
                )
            },
        );
        assert_eq!(calls[0].0, "PUT");
        assert_eq!(calls[0].1, "/cluster/backup/job-a");
        assert_eq!(
            calls[0].2,
            json!({"body": {"enabled": "1", "schedule": "sun 01:00"}})
        );
    }

    #[test]
    fn unknown_paths_are_an_error() {
        assert!(resolve("GET", "nope/at/all").is_err());
    }
}
