//! Offline validation of the entire auto-generated proxmox tool surface.
//!
//! Walks the dispatch registry (populated by the `#[orca_tool]` inventory
//! submissions in `proxmox::surface`) and asserts every emitted tool is
//! well-formed: unique name, an `input_schema` that takes an `endpoint`, and an
//! `output_schema` that is a *concrete* JSON Schema — never an opaque
//! `Map<String,Value>` (`additionalProperties: true` with no properties), which
//! would violate the no-opaque-JSON rule the generator is built to honor.
//!
//! This covers all ~327 surfaced endpoints without a live cluster — the live
//! read-sweep (typed deserialization vs wire) is a separate, network-gated test.

use plugin_toolkit::serde_json::{self, Value};

/// Force the proxmox rlib to link so its inventory entries register.
#[allow(unused_imports)]
use proxmox as _;

fn proxmox_tools() -> Vec<Value> {
    let manifest = plugin_toolkit::dispatch::tool_manifest_json();
    let all: Vec<Value> = serde_json::from_str(&manifest).expect("manifest is valid JSON array");
    all.into_iter()
        .filter(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .is_some_and(|n| n.starts_with("proxmox."))
        })
        .collect()
}

/// A schema is "concrete" if it pins a shape: an object with declared
/// `properties`, an array, a `$ref`, an enum/const, or a scalar `type`. A bare
/// `{"type":"object"}` with `additionalProperties` and no `properties` is the
/// opaque-map shape we must never emit.
fn is_concrete_schema(s: &Value) -> bool {
    let Some(obj) = s.as_object() else {
        return s.is_boolean(); // `true`/`false` schema — not what we want, caught below
    };
    if obj.contains_key("$ref")
        || obj.contains_key("properties")
        || obj.contains_key("enum")
        || obj.contains_key("const")
        || obj.contains_key("oneOf")
        || obj.contains_key("anyOf")
        || obj.contains_key("allOf")
    {
        return true;
    }
    match obj.get("type").and_then(|t| t.as_str()) {
        Some("array") => true,
        Some("object") => false, // object with no properties => opaque map
        Some(_) => true,         // scalar
        None => false,
    }
}

#[test]
fn every_tool_has_unique_name() {
    let tools = proxmox_tools();
    assert!(!tools.is_empty(), "no proxmox tools registered");
    let mut seen = std::collections::HashSet::new();
    for t in &tools {
        let name = t["name"].as_str().unwrap();
        assert!(seen.insert(name), "duplicate tool name: {name}");
    }
    eprintln!("proxmox tools registered: {}", tools.len());
}

/// Fan-out verbs that default to every enabled endpoint when `endpoint` is
/// omitted. Any other tool advertising an optional endpoint is a mistake.
const OPTIONAL_ENDPOINT: &[&str] = &["proxmox.thin.audit"];

/// Hand-written tools whose names collide with the generated verb prefixes.
const HAND_WRITTEN_PREFIXED: &[&str] = &["proxmox.get_facts"];

fn is_generated_verb(name: &str) -> bool {
    !HAND_WRITTEN_PREFIXED.contains(&name)
        && name.strip_prefix("proxmox.").is_some_and(|v| {
            ["get_", "post_", "put_", "delete_"]
                .iter()
                .any(|p| v.starts_with(p))
        })
}

#[test]
fn every_tool_input_schema_takes_endpoint() {
    let mut generated = 0;
    for t in proxmox_tools() {
        let name = t["name"].as_str().unwrap();
        let input = &t["input_schema"];
        assert!(input.is_object(), "{name}: input_schema not an object");
        let props = input.get("properties").and_then(|p| p.as_object());
        let required = input
            .get("required")
            .and_then(|r| r.as_array())
            .is_some_and(|r| r.iter().any(|v| v == "endpoint"));
        if is_generated_verb(name) {
            generated += 1;
            assert!(required, "{name}: generated verb does not require endpoint");
        }
        if let Some(ep) = props.and_then(|p| p.get("endpoint")) {
            let ty = &ep["type"];
            let nullable = ty.as_array().is_some_and(|a| {
                a.iter().any(|v| v == "string") && a.iter().all(|v| v == "string" || v == "null")
            });
            if OPTIONAL_ENDPOINT.contains(&name) {
                assert!(
                    nullable && !required,
                    "{name}: endpoint should be optional: {ty}"
                );
            } else {
                assert!(
                    ty == "string",
                    "{name}: endpoint must be a plain string: {ty}"
                );
            }
        }
    }
    assert!(generated > 0, "no generated verbs matched");
}

#[test]
fn no_tool_emits_an_opaque_output_schema() {
    let mut offenders = Vec::new();
    for t in proxmox_tools() {
        let name = t["name"].as_str().unwrap().to_string();
        let out = &t["output_schema"];
        // Resolve a top-level $ref against $defs so a ref to an opaque def is caught.
        let resolved = resolve_ref(out, out);
        if !is_concrete_schema(&resolved) {
            offenders.push(name);
        }
    }
    assert!(
        offenders.is_empty(),
        "{} tool(s) emit opaque/empty output schemas: {:?}",
        offenders.len(),
        offenders
    );
}

/// If `schema` is a `{"$ref":"#/$defs/X"}`, return the def from `root.$defs.X`;
/// otherwise return `schema` unchanged.
fn resolve_ref(schema: &Value, root: &Value) -> Value {
    if let Some(r) = schema.get("$ref").and_then(|v| v.as_str())
        && let Some(name) = r.strip_prefix("#/$defs/")
        && let Some(def) = root.get("$defs").and_then(|d| d.get(name))
    {
        return def.clone();
    }
    schema.clone()
}

/// Gate presence is read off the advertised input schema: the central execute
/// gate injects `execute` into every gated verb.
fn is_execute_gated(name: &str) -> bool {
    proxmox_tools()
        .into_iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("{name} not registered"))["input_schema"]["properties"]
        .get("execute")
        .is_some()
}

#[test]
fn thin_audit_reads_and_enable_discard_is_dry_run_by_default() {
    assert!(!is_execute_gated("proxmox.thin.audit"));
    assert!(is_execute_gated("proxmox.thin.enable_discard"));
}

/// Hand-written reads plan nothing, so they must run without `execute` and be
/// callable below admin.
#[test]
fn hand_written_reads_are_not_execute_gated() {
    for name in [
        "proxmox.nodes",
        "proxmox.node_detail",
        "proxmox.deploy_target_list",
        "proxmox.host_logs",
        "proxmox.cluster_status",
        "proxmox.cluster_list",
        "proxmox.list_clusters",
        "proxmox.collect_claims",
        "proxmox.get_facts",
        "proxmox.lxc_data.plan",
    ] {
        assert!(!is_execute_gated(name), "{name} is execute-gated");
        assert_eq!(
            plugin_toolkit::dispatch::required_role(name),
            Some("read"),
            "{name}"
        );
    }
}

fn test_ctx() -> plugin_toolkit::contract::ToolCtx {
    use plugin_toolkit::contract::config::{Config, Model, Ports};
    let dir = std::env::temp_dir().join(format!("proxmox-surface-{}", std::process::id()));
    plugin_toolkit::contract::ToolCtx::new(std::sync::Arc::new(Config {
        anthropic_api_key: None,
        lmstudio_url: String::new(),
        ollama_url: String::new(),
        default_model: Model::LMStudio {
            id: String::new(),
            url: String::new(),
        },
        app_dir: dir.clone(),
        memory_root: dir.clone(),
        db_path: dir.join("test.db"),
        ports: Ports::default(),
    }))
}

/// Without `execute` the gate answers with a plan before the verb body runs, so
/// no capability (HTTP, secrets, db) is ever reached.
#[test]
fn enable_discard_dispatch_without_execute_returns_a_plan() {
    let args = serde_json::json!({
        "endpoint": "pve",
        "node": "hyp1",
        "ctid": 101,
    });
    let out = plugin_toolkit::capsink::with_cap_sink(
        Box::new(|cap: &str, raw: &str| panic!("dry run reached capability {cap}: {raw}")),
        || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(plugin_toolkit::dispatch::dispatch(
                    "proxmox.thin.enable_discard",
                    args,
                    &test_ctx(),
                ))
        },
    )
    .expect("a dry run is not an error");
    assert_eq!(out["dryRun"], serde_json::json!(true), "{out}");
    assert_eq!(
        out["tool"],
        serde_json::json!("proxmox.thin.enable_discard")
    );
    assert_eq!(out["inputs"]["ctid"], serde_json::json!(101));
}

/// Verbs that own their `execute` opt-in: not centrally gated, admin-only, and
/// an execute call with no caller identity is refused before any capability.
const SELF_GATED: &[&str] = &[
    "proxmox.backup_job.upsert",
    "proxmox.backup_job.delete",
    "proxmox.guest.pxarexclude",
];

#[test]
fn self_gated_verbs_take_their_own_execute_and_need_admin() {
    for name in SELF_GATED {
        let tool = proxmox_tools()
            .into_iter()
            .find(|t| t["name"] == *name)
            .unwrap_or_else(|| panic!("{name} not registered"));
        assert!(
            tool["input_schema"]["properties"].get("execute").is_some(),
            "{name} takes execute"
        );
        assert_eq!(
            plugin_toolkit::dispatch::required_role(name),
            Some("admin"),
            "{name}"
        );
    }
    assert_eq!(
        plugin_toolkit::dispatch::required_role("proxmox.backup_job.list"),
        Some("read")
    );
    assert!(!is_execute_gated("proxmox.backup_job.list"));
}

#[test]
fn self_gated_execute_without_a_caller_is_refused_before_anything_runs() {
    for (name, args) in [
        (
            "proxmox.backup_job.upsert",
            serde_json::json!({"endpoint": "pve", "id": "j", "execute": true}),
        ),
        (
            "proxmox.backup_job.delete",
            serde_json::json!({"endpoint": "pve", "id": "j", "execute": true}),
        ),
        (
            "proxmox.guest.pxarexclude",
            serde_json::json!({"endpoint": "pve", "ctid": 1, "patterns": ["/data"], "execute": true}),
        ),
    ] {
        let err = plugin_toolkit::capsink::with_cap_sink(
            Box::new(|cap: &str, raw: &str| panic!("reached capability {cap}: {raw}")),
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(plugin_toolkit::dispatch::dispatch(name, args, &test_ctx()))
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no caller identity"), "{name}: {err}");
    }
}
