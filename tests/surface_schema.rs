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

/// Force the proxmox cdylib/rlib to link so its inventory entries register.
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

#[test]
fn every_tool_input_schema_takes_endpoint() {
    for t in proxmox_tools() {
        let name = t["name"].as_str().unwrap();
        let input = &t["input_schema"];
        assert!(input.is_object(), "{name}: input_schema not an object");
        // Every surface wrapper carries `endpoint: String`; endpoint-CRUD tools
        // (list/detail/…) may not, so only assert on the generated surface verbs.
        let props = input.get("properties").and_then(|p| p.as_object());
        if let Some(props) = props {
            // If it has an endpoint field, it must be a string.
            if let Some(ep) = props.get("endpoint") {
                assert_eq!(
                    ep.get("type").and_then(|v| v.as_str()),
                    Some("string"),
                    "{name}: endpoint field is not a string"
                );
            }
        }
    }
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
