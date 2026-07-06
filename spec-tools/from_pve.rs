//! Parser for Proxmox VE's `apidoc.js` schema dialect.
//!
//! Proxmox does not publish OpenAPI 3.x. They ship `pve-docs/api-viewer/apidoc.js`
//! as a JavaScript file containing a tree of `{ path, info, children, ... }`
//! nodes — structurally compatible with OpenAPI (paths, methods, JSON-Schema-ish
//! params/returns) but in a different dialect.
//!
//! This parser walks that tree and emits an `openapiv3::OpenAPI` spec
//! pointing-equivalent to what a hand-written conversion would produce. The
//! output feeds the same downstream pipeline as `parse_str` for OpenAPI 3.x:
//! `normalize::for_progenitor` → `progenitor::Generator`.
//!
//! Usage (in a plugin build.rs):
//!
//! ```ignore
//! let raw = std::fs::read_to_string("specs/apidoc.json")?;
//! let mut spec = openapi::from_pve::parse_str(&raw)?;
//! openapi::normalize::for_progenitor(&mut spec);
//! // ...feed to progenitor
//! ```
//!
//! The Proxmox dialect's quirks vs. JSON Schema Draft 4:
//!   - `optional: 1` means NOT required (inverted from OpenAPI's `required[]`).
//!   - `properties` is a map at the root for `parameters`, but the root
//!     itself isn't always marked `type: "object"` — we infer.
//!   - PVE-specific `format` strings (`pve-vmid`, `pve-node`, …) are
//!     preserved verbatim; progenitor maps unknown formats to `String`.
//!   - `typetext` is a human label, not a type. Dropped.
//!   - `default` values are dropped (PVE-side default propagation is not
//!     load-bearing for codegen; progenitor never reads them).
//!   - `description` may be missing on intermediate path nodes; we walk
//!     past those and only emit operations under nodes that have `info`.

use anyhow::{Context, Result};
use indexmap::IndexMap;
use openapiv3::{
    ArrayType, BooleanType, IntegerType, MediaType, NumberType, ObjectType, OpenAPI, Operation,
    Parameter, ParameterData, ParameterSchemaOrContent, PathItem, Paths, QueryStyle, ReferenceOr,
    RequestBody, Response, Responses, Schema, SchemaData, SchemaKind, StatusCode, StringType, Type,
    VariantOrUnknownOrEmpty,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Top-level parser. Accepts either:
///   - the raw `apidoc.js` body (`var apiSchema = [...];`), or
///   - the JSON array on its own.
///
/// Returns a fully-populated `openapiv3::OpenAPI` ready for
/// `normalize::for_progenitor` + progenitor codegen.
pub fn parse_str(raw: &str) -> Result<OpenAPI> {
    let json = strip_apidoc_prefix(raw);
    let tree: Vec<PveNode> =
        serde_json::from_str(json).context("pve apidoc: parse top-level array")?;
    let mut spec = OpenAPI {
        openapi: "3.0.3".to_string(),
        info: openapiv3::Info {
            title: "Proxmox VE API".to_string(),
            version: "8".to_string(),
            description: Some("Generated from Proxmox apidoc.js by openapi::from_pve.".to_string()),
            ..Default::default()
        },
        paths: Paths::default(),
        ..Default::default()
    };
    let mut flat: BTreeMap<String, BTreeMap<String, PveMethod>> = BTreeMap::new();
    for node in &tree {
        flatten(node, "", &mut flat);
    }
    for (path, methods) in flat {
        let mut item = PathItem::default();
        for (method_upper, m) in methods {
            let op = build_operation(&path, &method_upper, &m);
            assign_op(&mut item, &method_upper, op);
        }
        spec.paths.paths.insert(path, ReferenceOr::Item(item));
    }
    Ok(spec)
}

/// Find the JSON array literal inside a raw `apidoc.js` body and return
/// just that span. Handles:
///   - `var apiSchema = [...];` (older Proxmox)
///   - `const apiSchema = [...];` (Proxmox 8.x)
///   - bare JSON array `[...]`
///   - a JS trailer after the array (Proxmox ships UI code in the same file)
///
/// Bracket-balances from the first `[` to its matching `]`, respecting
/// string literals and escape sequences, then returns that slice.
pub fn strip_apidoc_prefix(raw: &str) -> &str {
    let bytes = raw.as_bytes();
    let Some(start) = bytes.iter().position(|&b| b == b'[') else {
        return raw;
    };
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut end = start;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    &raw[start..end]
}

// ── PVE schema dialect (deserialize) ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct PveNode {
    path: String,
    #[serde(default)]
    info: BTreeMap<String, PveMethod>,
    #[serde(default)]
    children: Vec<PveNode>,
}

#[derive(Debug, Deserialize, Clone)]
struct PveMethod {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Option<PveSchema>,
    #[serde(default)]
    returns: Option<PveSchema>,
}

#[derive(Debug, Default, Deserialize, Clone)]
struct PveSchema {
    #[serde(default, rename = "type")]
    ty: Option<PveType>,
    #[serde(default)]
    description: Option<String>,
    /// `1` = NOT required (opposite of OpenAPI's `required[]`). Proxmox
    /// inconsistently emits `1` (int) or `"1"` (string) across endpoints.
    #[serde(default)]
    optional: Option<PveFlag>,
    /// Proxmox `format` is overloaded: usually a string like `pve-vmid`,
    /// but for compound parameters it's a nested schema describing
    /// sub-fields (e.g. corosync `link[n]` where the format object
    /// describes `address`, `priority`, etc.). We preserve the string
    /// case and drop the compound case — OpenAPI has no equivalent.
    #[serde(default)]
    format: Option<PveFormat>,
    #[serde(default)]
    items: Option<Box<PveSchema>>,
    #[serde(default)]
    properties: Option<BTreeMap<String, PveSchema>>,
    /// PVE enums can be strings (`"applet"|"vv"|…`) or integers
    /// (`0|1|2`). Strings map straight into OpenAPI; integer enums
    /// would need a separate `IntegerType { enumeration }` path that
    /// progenitor doesn't currently exploit, so we accept them but
    /// don't propagate.
    #[serde(default, rename = "enum")]
    enum_values: Option<PveEnumValues>,
    #[serde(default)]
    minimum: Option<PveNumber>,
    #[serde(default)]
    maximum: Option<PveNumber>,
    #[serde(default, rename = "minLength")]
    min_length: Option<PveNumber>,
    #[serde(default, rename = "maxLength")]
    max_length: Option<PveNumber>,
    #[serde(default)]
    pattern: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum PveType {
    Single(String),
    Multi(Vec<String>),
}

/// PVE boolean-ish flag. Proxmox inconsistently emits `1` (int) or `"1"`
/// (string) for fields like `optional`, `protected`, `allowtoken`.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum PveFlag {
    Int(u8),
    Str(String),
}

impl PveFlag {
    fn is_set(&self) -> bool {
        match self {
            PveFlag::Int(n) => *n != 0,
            PveFlag::Str(s) => s != "0" && !s.is_empty(),
        }
    }
}

/// PVE numeric bound. Proxmox sometimes stringifies `minimum`/`maximum`
/// (e.g. `"minimum": "0"`); accept both shapes and normalize to f64.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum PveNumber {
    Int(i64),
    Float(f64),
    Str(String),
}

impl PveNumber {
    fn as_f64(&self) -> Option<f64> {
        match self {
            PveNumber::Int(n) => Some(*n as f64),
            PveNumber::Float(f) => Some(*f),
            PveNumber::Str(s) => s.parse().ok(),
        }
    }
    fn as_i64(&self) -> Option<i64> {
        self.as_f64().map(|f| f as i64)
    }
    fn as_usize(&self) -> Option<usize> {
        self.as_i64().and_then(|n| usize::try_from(n).ok())
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum PveFormat {
    /// A simple format name like `"pve-vmid"` or `"ipv4"`.
    Str(String),
    /// A nested format object — Proxmox uses this for compound
    /// `link[n]`-style parameters. We can't represent it in OpenAPI;
    /// the IgnoredAny consumes the tree without allocating.
    Compound(serde::de::IgnoredAny),
}

impl PveSchema {
    fn format_str(&self) -> Option<&str> {
        match &self.format {
            Some(PveFormat::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    fn string_enum(&self) -> Vec<String> {
        match &self.enum_values {
            Some(PveEnumValues::Strings(v)) => v.clone(),
            _ => Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum PveEnumValues {
    Strings(Vec<String>),
    /// Numeric (or mixed) enum — dropped on the OpenAPI side.
    Other(serde::de::IgnoredAny),
}

impl PveType {
    fn primary(&self) -> &str {
        match self {
            PveType::Single(s) => s,
            PveType::Multi(v) => v.first().map(|s| s.as_str()).unwrap_or(""),
        }
    }
}

// ── Tree flatten ───────────────────────────────────────────────────────────

fn flatten(node: &PveNode, parent: &str, out: &mut BTreeMap<String, BTreeMap<String, PveMethod>>) {
    let path = join_path(parent, &node.path);
    if !node.info.is_empty() {
        out.entry(path.clone()).or_default().extend(
            node.info
                .iter()
                .map(|(k, v)| (k.to_ascii_uppercase(), v.clone())),
        );
    }
    for child in &node.children {
        flatten(child, &path, out);
    }
}

/// Join `parent` and `node.path`. Proxmox apidoc nodes carry either an
/// absolute path (`/access/users`) or a leaf segment (`/{userid}`); we
/// normalize so the result is always absolute.
fn join_path(parent: &str, node_path: &str) -> String {
    if node_path.starts_with('/') && (parent.is_empty() || node_path.starts_with(parent)) {
        node_path.to_string()
    } else if node_path.starts_with('/') {
        format!("{parent}{node_path}")
    } else {
        format!("{parent}/{node_path}")
    }
}

// ── Operation build ────────────────────────────────────────────────────────

fn build_operation(path: &str, method_upper: &str, m: &PveMethod) -> Operation {
    let path_param_names = extract_path_params(path);
    let mut parameters: Vec<ReferenceOr<Parameter>> = Vec::new();
    let mut body_props: BTreeMap<String, PveSchema> = BTreeMap::new();
    let mut body_required: BTreeSet<String> = BTreeSet::new();

    if let Some(params) = &m.parameters
        && let Some(props) = &params.properties
    {
        for (name, schema) in props {
            let required = !schema.optional.as_ref().is_some_and(PveFlag::is_set);
            if path_param_names.contains(name.as_str()) {
                parameters.push(ReferenceOr::Item(Parameter::Path {
                    parameter_data: pve_to_parameter_data(name, schema, true),
                    style: openapiv3::PathStyle::Simple,
                }));
            } else if is_body_method(method_upper) {
                if required {
                    body_required.insert(name.clone());
                }
                body_props.insert(name.clone(), schema.clone());
            } else {
                parameters.push(ReferenceOr::Item(Parameter::Query {
                    parameter_data: pve_to_parameter_data(name, schema, required),
                    allow_reserved: false,
                    style: QueryStyle::Form,
                    allow_empty_value: None,
                }));
            }
        }
    }

    let request_body = if body_props.is_empty() {
        None
    } else {
        let schema = build_object_schema(&body_props, &body_required);
        let mut content = IndexMap::new();
        content.insert(
            "application/json".to_string(),
            MediaType {
                schema: Some(ReferenceOr::Item(schema)),
                ..Default::default()
            },
        );
        Some(ReferenceOr::Item(RequestBody {
            content,
            required: !body_required.is_empty(),
            ..Default::default()
        }))
    };

    // Narrow, growable list of endpoints whose documented response string
    // enums are incomplete on the wire (verified live). `/cluster/ha/status/current`
    // documents `type` as [quorum,master,lrm,service] but also emits `fencing`.
    // Only these have their response enums relaxed to plain strings; every other
    // endpoint keeps its (complete, roster-consumed) enums intact.
    let relax_response_enums = matches!(path, "/cluster/ha/status/current");
    // Narrow, growable list of response fields PVE documents as `string` but
    // sends as a JSON integer on the wire (verified live). `/nodes/{node}/apt/
    // repositories` documents `infos[].index` as string but emits `0`, `1`, …
    // Responses are descriptive (not validated), so widening the documented
    // type to the observed wire type is always safe and fixes the parse.
    let coerce_int_fields: &[&str] = match path {
        "/nodes/{node}/apt/repositories" => &["index"],
        _ => &[],
    };
    let responses = build_responses(m.returns.as_ref(), relax_response_enums, coerce_int_fields);

    Operation {
        operation_id: Some(synth_operation_id(method_upper, path, m.name.as_deref())),
        summary: m.description.clone(),
        description: m.description.clone(),
        parameters,
        request_body,
        responses,
        ..Default::default()
    }
}

/// Rewrite Perl-style inline regex flag groups (`(?^:X)`, `(?^i:X)`) to
/// plain non-capturing groups (`(?:X)`). PVE patterns frequently use the
/// Perl-only `^` "default flags" form which Rust's `regex` / progenitor's
/// `regress` rejects. Drop the `^` and any flags between it and the `:`.
fn sanitize_pattern(pat: &str) -> String {
    let mut out = String::with_capacity(pat.len());
    let bytes = pat.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 < bytes.len() && &bytes[i..i + 3] == b"(?^" {
            out.push_str("(?");
            i += 3;
            while i < bytes.len() && bytes[i] != b':' && bytes[i] != b')' {
                i += 1;
            }
        } else if i + 2 < bytes.len() && &bytes[i..i + 3] == b"(?>" {
            out.push_str("(?:");
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn is_body_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH")
}

fn extract_path_params(path: &str) -> BTreeSet<&str> {
    let mut out = BTreeSet::new();
    let mut s = path;
    while let Some(open) = s.find('{') {
        let rest = &s[open + 1..];
        if let Some(close) = rest.find('}') {
            out.insert(&rest[..close]);
            s = &rest[close + 1..];
        } else {
            break;
        }
    }
    out
}

fn synth_operation_id(method: &str, path: &str, name: Option<&str>) -> String {
    let base = name.unwrap_or("op");
    let path_slug: String = path
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => c,
            _ => '_',
        })
        .collect();
    let slug = path_slug.trim_matches('_').to_string();
    format!("{}_{}_{}", method.to_ascii_lowercase(), base, slug)
}

fn assign_op(item: &mut PathItem, method_upper: &str, op: Operation) {
    match method_upper {
        "GET" => item.get = Some(op),
        "POST" => item.post = Some(op),
        "PUT" => item.put = Some(op),
        "DELETE" => item.delete = Some(op),
        "PATCH" => item.patch = Some(op),
        "OPTIONS" => item.options = Some(op),
        "HEAD" => item.head = Some(op),
        _ => {} // unknown, drop
    }
}

// ── Schema translation ─────────────────────────────────────────────────────

fn pve_to_parameter_data(name: &str, schema: &PveSchema, required: bool) -> ParameterData {
    ParameterData {
        name: name.to_string(),
        description: schema.description.clone(),
        required,
        deprecated: None,
        format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(pve_to_schema(schema))),
        example: None,
        examples: Default::default(),
        explode: None,
        extensions: Default::default(),
    }
}

fn pve_to_schema(s: &PveSchema) -> Schema {
    let data = SchemaData {
        description: s.description.clone(),
        ..Default::default()
    };
    // Effective type: PVE often omits `type` on documented fields. Infer it
    // rather than falling back to an opaque `Map<String,Value>` (which both
    // violates the no-opaque-JSON rule and mis-deserializes — e.g. the HA
    // status `type` field is an untyped string on the wire, not an object):
    //   properties present → object · items present → array · else → string
    // (PVE's convention for an untyped scalar field). An explicit `type` always
    // wins.
    let effective_ty = match s.ty.as_ref().map(PveType::primary).unwrap_or("") {
        "" if s.properties.is_some() => "object",
        "" if s.items.is_some() => "array",
        "" => "string",
        other => other,
    };
    let kind = match effective_ty {
        "string" => SchemaKind::Type(Type::String(StringType {
            format: match s.format_str() {
                Some(f) => VariantOrUnknownOrEmpty::Unknown(f.to_string()),
                None => VariantOrUnknownOrEmpty::Empty,
            },
            pattern: s.pattern.as_deref().map(sanitize_pattern),
            enumeration: s.string_enum().into_iter().map(Some).collect(),
            min_length: s.min_length.as_ref().and_then(PveNumber::as_usize),
            max_length: s.max_length.as_ref().and_then(PveNumber::as_usize),
        })),
        "integer" => SchemaKind::Type(Type::Integer(IntegerType {
            minimum: s.minimum.as_ref().and_then(PveNumber::as_i64),
            maximum: s.maximum.as_ref().and_then(PveNumber::as_i64),
            ..Default::default()
        })),
        "number" => SchemaKind::Type(Type::Number(NumberType {
            minimum: s.minimum.as_ref().and_then(PveNumber::as_f64),
            maximum: s.maximum.as_ref().and_then(PveNumber::as_f64),
            ..Default::default()
        })),
        "boolean" => SchemaKind::Type(Type::Boolean(BooleanType::default())),
        "array" => SchemaKind::Type(Type::Array(ArrayType {
            items: s
                .items
                .as_ref()
                .map(|inner| ReferenceOr::Item(Box::new(pve_to_schema(inner)))),
            min_items: None,
            max_items: None,
            unique_items: false,
        })),
        "object" => {
            let mut properties: IndexMap<String, ReferenceOr<Box<Schema>>> = IndexMap::new();
            let mut required: Vec<String> = Vec::new();
            if let Some(props) = &s.properties {
                for (name, schema) in props {
                    // Narrow, growable override: PVE documents these response
                    // fields as required but omits or `null`s them on the wire
                    // (verified live via tests/live_read_sweep.rs). Mark them
                    // optional AND nullable so progenitor emits `Option<T>` —
                    // which absorbs both absence and an explicit `null` (a plain
                    // non-required array otherwise becomes `Vec<T>` + default,
                    // and `default` does not coerce an explicit `null`). Add a
                    // field here only after the sweep proves it broken; keep
                    // required-ness everywhere PVE actually honors it.
                    let observed_optional = matches!(name.as_str(), "mounted" | "osdid-list");
                    let mut prop = pve_to_schema(schema);
                    if observed_optional {
                        prop.schema_data.nullable = true;
                    }
                    properties.insert(name.clone(), ReferenceOr::Item(Box::new(prop)));
                    if !observed_optional && !schema.optional.as_ref().is_some_and(PveFlag::is_set)
                    {
                        required.push(name.clone());
                    }
                }
            }
            SchemaKind::Type(Type::Object(ObjectType {
                properties,
                required,
                additional_properties: None,
                min_properties: None,
                max_properties: None,
            }))
        }
        // Any other unrecognized PVE type (e.g. `null`): treat as a string
        // scalar rather than an opaque object — never emit `Map<String,Value>`.
        _ => SchemaKind::Type(Type::String(StringType::default())),
    };
    Schema {
        schema_data: data,
        schema_kind: kind,
    }
}

fn build_object_schema(props: &BTreeMap<String, PveSchema>, required: &BTreeSet<String>) -> Schema {
    let mut properties: IndexMap<String, ReferenceOr<Box<Schema>>> = IndexMap::new();
    for (name, schema) in props {
        properties.insert(
            name.clone(),
            ReferenceOr::Item(Box::new(pve_to_schema(schema))),
        );
    }
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::Object(ObjectType {
            properties,
            required: required.iter().cloned().collect(),
            additional_properties: None,
            min_properties: None,
            max_properties: None,
        })),
    }
}

/// Recursively strip `enum` constraints from string schemas in a *response*
/// body. PVE documents string enums that its wire does not honor — the HA
/// status `type` field is documented `[quorum,master,lrm,service]` but also
/// emits `fencing`. A closed Rust enum then fails to deserialize the live body.
/// Responses are descriptive, not validated, so dropping the enum (the field
/// stays `String`) is always safe and fixes the incomplete-enum class at once.
/// Request/parameter enums are untouched — those *are* validated on input.
fn strip_response_enums(schema: &mut Schema) {
    match &mut schema.schema_kind {
        SchemaKind::Type(Type::String(s)) => s.enumeration.clear(),
        SchemaKind::Type(Type::Object(o)) => {
            for prop in o.properties.values_mut() {
                if let ReferenceOr::Item(inner) = prop {
                    strip_response_enums(inner);
                }
            }
        }
        SchemaKind::Type(Type::Array(a)) => {
            if let Some(ReferenceOr::Item(items)) = a.items.as_mut() {
                strip_response_enums(items);
            }
        }
        _ => {}
    }
}

/// Retype every response property named in `fields` from `string` to `integer`,
/// recursing through objects and arrays. Narrow companion to
/// [`strip_response_enums`] for the documented-string / wire-integer class.
fn coerce_response_int_fields(schema: &mut Schema, fields: &[&str]) {
    match &mut schema.schema_kind {
        SchemaKind::Type(Type::Object(o)) => {
            for (name, prop) in o.properties.iter_mut() {
                if let ReferenceOr::Item(inner) = prop {
                    if fields.contains(&name.as_str())
                        && matches!(inner.schema_kind, SchemaKind::Type(Type::String(_)))
                    {
                        inner.schema_kind = SchemaKind::Type(Type::Integer(IntegerType::default()));
                    } else {
                        coerce_response_int_fields(inner, fields);
                    }
                }
            }
        }
        SchemaKind::Type(Type::Array(a)) => {
            if let Some(ReferenceOr::Item(items)) = a.items.as_mut() {
                coerce_response_int_fields(items, fields);
            }
        }
        _ => {}
    }
}

fn build_responses(
    returns: Option<&PveSchema>,
    relax_enums: bool,
    coerce_int_fields: &[&str],
) -> Responses {
    let mut responses = Responses::default();
    let mut schema = returns.map(pve_to_schema).unwrap_or_else(|| Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::Object(ObjectType::default())),
    });
    if relax_enums {
        strip_response_enums(&mut schema);
    }
    if !coerce_int_fields.is_empty() {
        coerce_response_int_fields(&mut schema, coerce_int_fields);
    }
    let mut content = IndexMap::new();
    content.insert(
        "application/json".to_string(),
        MediaType {
            schema: Some(ReferenceOr::Item(schema)),
            ..Default::default()
        },
    );
    responses.responses.insert(
        StatusCode::Code(200),
        ReferenceOr::Item(Response {
            description: "OK".to_string(),
            content,
            ..Default::default()
        }),
    );
    responses
}
