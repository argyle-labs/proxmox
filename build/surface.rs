//! Prototype: generate the orca tool surface from the OpenAPI-derived client.
//!
//! Runs in `build.rs` *after* `plugin_toolkit_build::openapi::generate_all_*`
//! has written `<OUT_DIR>/<flavor>_codegen.rs`. Rather than hand-write one
//! `#[orca_tool]` per capability, this pairs every generated `impl Client`
//! method back to its spec operation via progenitor's doc comment
//! (`Sends a `GET` request to `/nodes/{node}/tasks/{upid}/status``), applies a
//! declarative ruleset, and emits:
//!
//!   1. `<flavor>_surface.rs` — an `#[orca_tool]` wrapper per matched method,
//!      with an args struct carrying the method's params **including the full
//!      typed request body**, and a body that calls the generated method through
//!      `crate::tools::make_client`.
//!   2. JsonSchema derives anchored onto the transitive closure of every type
//!      the surfaced tools reference — request bodies, query enums, and response
//!      bodies — so the complete request/response shape is known at runtime via
//!      the tool's `args_schema` / `output_schema`.
//!
//! `OrcaToolDef::Args` requires only `DeserializeOwned + Serialize + JsonSchema`
//! (NOT `clap::Args`) — the CLI surface is generated from the JSON Schema — so a
//! nested typed body field is a first-class arg, not a JSON blob.
//!
//! This is the proxmox-local prototype of what will become a reusable
//! `plugin-toolkit-build` pass. Keep the ruleset (`rules()`) the single place
//! that decides what becomes surface.

#![allow(clippy::disallowed_types)]

use std::collections::{BTreeSet, HashMap};

use anyhow::{Context, Result};
use quote::ToTokens;
use regex::Regex;

/// A generated `impl Client` method paired to its spec operation.
struct Method {
    ident: String,
    http: String,
    path: String,
    params: Vec<Param>,
    /// The `T` inside `ResponseValue<T>`, as source text with `types::` paths
    /// rewritten to `crate::generated::types::`. `None` for `()` / unit.
    ret: Option<String>,
    /// Bare `types::*` idents referenced by params + return — closure seeds.
    type_seeds: Vec<String>,
}

/// A single surfaceable method argument, with its emitted parts precomputed.
struct Param {
    /// Field declaration line inside the args struct (no trailing comma).
    field_decl: String,
    /// Expression passed at the call site, in the method's positional order.
    call_expr: String,
}

/// One surface rule: match on `"<METHOD> <path>"`, name a verb prefix.
struct Rule {
    re: Regex,
    /// Verb naming: `Auto` derives a unique verb from the method ident; a
    /// literal pins one verb (only safe for single-match rules).
    verb: VerbNaming,
    role_admin: bool,
}

enum VerbNaming {
    Auto,
    /// Reserved for single-match rules that pin a fixed verb name. Not yet
    /// constructed — every current rule derives its verb via `Auto`.
    #[allow(dead_code)]
    Literal(&'static str),
}

/// The single place that decides what becomes orca surface.
///
/// Prototype ambition (per directive): surface **everything emittable** with
/// full typed request + response bodies. Mutating methods (POST/PUT/DELETE) get
/// `role = "admin"`. Verb = the generated method ident (unique, deterministic;
/// prettified later).
fn rules() -> Vec<Rule> {
    vec![
        Rule {
            re: Regex::new(r"^(POST|PUT|DELETE) ").unwrap(),
            verb: VerbNaming::Auto,
            role_admin: true,
        },
        Rule {
            re: Regex::new(r"^GET ").unwrap(),
            verb: VerbNaming::Auto,
            role_admin: false,
        },
    ]
}

pub fn generate(flavor: &str) -> Result<()> {
    let out_dir = std::env::var("OUT_DIR").context("OUT_DIR not set")?;
    let gen_path = format!("{out_dir}/{flavor}_codegen.rs");
    let src = std::fs::read_to_string(&gen_path).with_context(|| format!("read {gen_path}"))?;
    let mut file: syn::File = syn::parse_file(&src).context("parse generated codegen")?;

    let type_idents = collect_type_idents(&file);
    let methods = collect_methods(&file, &type_idents);
    let rules = rules();

    let mut matched: Vec<(&Method, bool)> = Vec::new();
    let mut skipped = 0usize;
    for m in &methods {
        let key = format!("{} {}", m.http, m.path);
        let Some(r) = rules.iter().find(|r| r.re.is_match(&key)) else {
            continue;
        };
        if m.ret.is_none() {
            skipped += 1;
            continue;
        }
        // `Literal` verbs must match exactly one method; `Auto` is always safe.
        let _ = &r.verb;
        matched.push((m, r.role_admin));
    }

    // Transitive closure of every type the surfaced tools touch, then anchor
    // JsonSchema so the full request/response shape is runtime-introspectable.
    let field_refs = collect_type_field_refs(&file, &type_idents);
    let mut needed: BTreeSet<String> = BTreeSet::new();
    for (m, _) in &matched {
        for seed in &m.type_seeds {
            close_over(seed, &field_refs, &mut needed);
        }
    }
    let anchored = anchor_jsonschema(&mut file, &needed);
    std::fs::write(&gen_path, prettyplease::unparse(&file))
        .with_context(|| format!("rewrite {gen_path}"))?;
    println!(
        "cargo:warning=surface: {} tool(s) emitted, {skipped} skipped (unit return), \
         JsonSchema on {anchored}/{} type(s)",
        matched.len(),
        needed.len()
    );

    let surface = emit_surface(&matched);
    let surface_path = format!("{out_dir}/{flavor}_surface.rs");
    std::fs::write(&surface_path, surface).with_context(|| format!("write {surface_path}"))?;
    Ok(())
}

/// Walk every `impl Client` block and turn each surfaceable `pub async fn` into
/// a [`Method`]. A method using an arg/return shape the emitter can't render is
/// dropped (returns `None` from [`method_from_fn`]).
fn collect_methods(file: &syn::File, locals: &BTreeSet<String>) -> Vec<Method> {
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut drops: std::collections::BTreeMap<String, usize> = Default::default();
    for item in &file.items {
        let syn::Item::Impl(imp) = item else { continue };
        let is_client = matches!(&*imp.self_ty, syn::Type::Path(p)
            if p.path.segments.last().is_some_and(|s| s.ident == "Client"));
        if !is_client {
            continue;
        }
        for ii in &imp.items {
            let syn::ImplItem::Fn(f) = ii else { continue };
            total += 1;
            match method_from_fn(f, locals) {
                Ok(m) => out.push(m),
                Err(reason) => *drops.entry(reason.into()).or_default() += 1,
            }
        }
    }
    let dropped: usize = drops.values().sum();
    println!(
        "cargo:warning=surface: paired {}/{total} client methods ({dropped} dropped: {})",
        out.len(),
        drops
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    out
}

fn method_from_fn(f: &syn::ImplItemFn, locals: &BTreeSet<String>) -> Result<Method, &'static str> {
    let doc = collect_doc(&f.attrs);
    let re = Regex::new(r"Sends a `(GET|POST|PUT|DELETE|PATCH)` request to `([^`]+)`").unwrap();
    let caps = re.captures(&doc).ok_or("no-doc-path")?;
    let http = caps[1].to_string();
    let path = caps[2].to_string();

    let mut params = Vec::new();
    let mut seeds = Vec::new();
    for arg in &f.sig.inputs {
        let syn::FnArg::Typed(pt) = arg else { continue };
        let syn::Pat::Ident(pi) = &*pt.pat else {
            return Err("non-ident-param");
        };
        let name = pi.ident.to_string();
        let (param, mut param_seeds) = classify(&name, &pt.ty, locals).ok_or("param-type")?;
        params.push(param);
        seeds.append(&mut param_seeds);
    }

    let (ret, mut ret_seeds) = return_inner(&f.sig.output, locals).ok_or("return-type")?;
    seeds.append(&mut ret_seeds);
    Ok(Method {
        ident: f.sig.ident.to_string(),
        http,
        path,
        params,
        ret,
        type_seeds: seeds,
    })
}

/// Classify one method param into an emitted [`Param`] + the `types::*` idents
/// it seeds into the JsonSchema closure. `None` if the shape isn't emittable.
fn classify(name: &str, ty: &syn::Type, locals: &BTreeSet<String>) -> Option<(Param, Vec<String>)> {
    // `&str` / `&'a str` path param → `String`, passed by ref.
    if let syn::Type::Reference(r) = ty
        && is_ident(&r.elem, "str")
    {
        return Some((field(name, "String", &format!("&args.{name}")), vec![]));
    }
    // `&Body` typed request body → nested typed field, passed by ref.
    if let syn::Type::Reference(r) = ty
        && let Some(rendered) = rendered_local_type(&r.elem, locals)
    {
        let mut seeds = Vec::new();
        collect_types_idents_in_ty(&r.elem, &mut seeds);
        return Some((field(name, &rendered, &format!("&args.{name}")), seeds));
    }
    // bare scalar path param (e.g. `vmid: i64`) → same type, by value.
    for scalar in SCALARS {
        if is_ident(ty, scalar) {
            return Some((field(name, scalar, &format!("args.{name}")), vec![]));
        }
    }
    // `Option<...>` query params.
    if let Some(inner) = option_inner(ty) {
        // `Option<&str>` → `Option<String>`, `.as_deref()`.
        if let syn::Type::Reference(r) = inner
            && is_ident(&r.elem, "str")
        {
            return Some((
                field(name, "Option<String>", &format!("args.{name}.as_deref()")),
                vec![],
            ));
        }
        // `Option<&[String]>` / `Option<Vec<String>>` array query.
        if let Some(elem) = slice_or_vec_inner(inner)
            && is_ident(elem, "String")
        {
            let by_ref = matches!(inner, syn::Type::Reference(_));
            let call = if by_ref {
                format!("args.{name}.as_deref()")
            } else {
                format!("args.{name}")
            };
            return Some((field(name, "Option<Vec<String>>", &call), vec![]));
        }
        // `Option<scalar>` → same, by value.
        for scalar in SCALARS {
            if is_ident(inner, scalar) {
                return Some((
                    field(name, &format!("Option<{scalar}>"), &format!("args.{name}")),
                    vec![],
                ));
            }
        }
        // `Option<types::Enum>` query enum → keep the typed enum, by value.
        if let Some(rendered) = rendered_local_type(inner, locals) {
            let mut seeds = Vec::new();
            collect_types_idents_in_ty(inner, &mut seeds);
            return Some((
                field(
                    name,
                    &format!("Option<{rendered}>"),
                    &format!("args.{name}"),
                ),
                seeds,
            ));
        }
    }
    None
}

const SCALARS: &[&str] = &["u64", "i64", "u32", "i32", "u16", "f64", "bool"];

fn field(name: &str, ty: &str, call_expr: &str) -> Param {
    Param {
        field_decl: format!("    pub {name}: {ty},"),
        call_expr: call_expr.to_string(),
    }
}

/// If `ty` is a `types::Foo` path (a locally-defined generated type), render it
/// as `crate::generated::types::Foo`. Rejects non-local / primitive paths.
fn rendered_local_type(ty: &syn::Type, locals: &BTreeSet<String>) -> Option<String> {
    let syn::Type::Path(p) = ty else { return None };
    let last = p.path.segments.last()?;
    let starts_types = p.path.segments.first().is_some_and(|s| s.ident == "types");
    if !(starts_types || locals.contains(&last.ident.to_string())) {
        return None;
    }
    Some(rewrite_types_path(&ty.to_token_stream().to_string()))
}

/// Extract `T` from `Result<ResponseValue<T>, Error<...>>`, rewrite `types::`
/// paths, and collect its `types::*` seeds. `None` return means an unsurfaceable
/// output (byte streams, opaque JSON) → skip the method entirely (`Err` sentinel
/// would abort the build). `Some(None)` return means unit `()`.
fn return_inner(
    output: &syn::ReturnType,
    locals: &BTreeSet<String>,
) -> Option<(Option<String>, Vec<String>)> {
    let syn::ReturnType::Type(_, ty) = output else {
        return Some((None, vec![]));
    };
    let result_ok = first_generic(ty, "Result")?;
    let inner = first_generic(result_ok, "ResponseValue")?;
    // Unit response.
    if let syn::Type::Tuple(t) = inner
        && t.elems.is_empty()
    {
        return Some((None, vec![]));
    }
    if !return_is_surfaceable(inner, locals) {
        return None;
    }
    let mut seeds = Vec::new();
    collect_types_idents_in_ty(inner, &mut seeds);
    let rendered = rewrite_types_path(&inner.to_token_stream().to_string());
    Some((Some(rendered), seeds))
}

/// True if the return type is something we can hand to schemars: a local
/// `types::*`, a `Vec`/`Option` thereof, `String`, or a scalar. Byte streams and
/// opaque `serde_json::Value` are rejected.
fn return_is_surfaceable(ty: &syn::Type, locals: &BTreeSet<String>) -> bool {
    match ty {
        syn::Type::Path(p) => {
            let Some(last) = p.path.segments.last() else {
                return false;
            };
            let id = last.ident.to_string();
            let ok_leaf = id == "String"
                || id == "Vec"
                || id == "Option"
                || SCALARS.contains(&id.as_str())
                || p.path.segments.first().is_some_and(|s| s.ident == "types")
                || locals.contains(&id);
            if !ok_leaf {
                return false;
            }
            if let syn::PathArguments::AngleBracketed(a) = &last.arguments {
                for arg in &a.args {
                    if let syn::GenericArgument::Type(t) = arg
                        && !return_is_surfaceable(t, locals)
                    {
                        return false;
                    }
                }
            }
            true
        }
        _ => false,
    }
}

/// Emit the surface source: header + one `#[orca_tool]` block per matched method.
fn emit_surface(matched: &[(&Method, bool)]) -> String {
    let mut s = String::new();
    s.push_str(
        "// @generated by build/surface.rs — do not edit. Regenerated every build.\n\
         use plugin_toolkit::prelude::*;\n\n",
    );
    for (m, role_admin) in matched {
        s.push_str(&emit_one(m, *role_admin));
        s.push('\n');
    }
    s
}

fn emit_one(m: &Method, role_admin: bool) -> String {
    let verb = &m.ident; // unique, deterministic; prettified later.
    let struct_ident = format!("SurfaceArgs_{verb}");
    let mut fields = String::from("    pub endpoint: String,\n");
    let mut call_args = String::new();
    for p in &m.params {
        fields.push_str(&p.field_decl);
        fields.push('\n');
        call_args.push_str(&p.call_expr);
        call_args.push_str(", ");
    }
    let ret = m.ret.as_deref().unwrap_or("()");
    let role = if role_admin { ", role = \"admin\"" } else { "" };
    format!(
        "#[derive(Serialize, Deserialize, JsonSchema)]\n\
         #[allow(non_camel_case_types)]\n\
         pub struct {struct_ident} {{\n{fields}}}\n\n\
         /// Auto-generated from `{http} {path}`.\n\
         #[orca_tool(domain = \"proxmox\", verb = \"{verb}\", cli = \"skip\"{role})]\n\
         async fn surface_{verb}(args: {struct_ident}, _ctx: &ToolCtx) -> anyhow::Result<{ret}> {{\n    \
         let client = crate::tools::make_client(&args.endpoint).await?;\n    \
         let out = client.{ident}({call_args}).await.map_err(|e| anyhow::anyhow!(\"proxmox.{verb}: {{e}}\"))?.into_inner();\n    \
         Ok(out)\n}}\n",
        http = m.http,
        path = m.path,
        ident = m.ident,
    )
}

// ── JsonSchema anchoring ────────────────────────────────────────────────────

/// All type idents defined under `pub mod types { ... }`.
fn collect_type_idents(file: &syn::File) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    if let Some(items) = types_mod_items(file) {
        for it in items {
            match it {
                syn::Item::Struct(s) => {
                    set.insert(s.ident.to_string());
                }
                syn::Item::Enum(e) => {
                    set.insert(e.ident.to_string());
                }
                _ => {}
            }
        }
    }
    set
}

/// For each type ident, the local type idents it references — the adjacency for
/// the closure.
fn collect_type_field_refs(
    file: &syn::File,
    locals: &BTreeSet<String>,
) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(items) = types_mod_items(file) {
        for it in items {
            match it {
                syn::Item::Struct(s) => {
                    let mut refs = Vec::new();
                    for f in &s.fields {
                        collect_local_idents(&f.ty, locals, &mut refs);
                    }
                    map.insert(s.ident.to_string(), refs);
                }
                syn::Item::Enum(e) => {
                    let mut refs = Vec::new();
                    for v in &e.variants {
                        for f in &v.fields {
                            collect_local_idents(&f.ty, locals, &mut refs);
                        }
                    }
                    map.insert(e.ident.to_string(), refs);
                }
                _ => {}
            }
        }
    }
    map
}

fn close_over(seed: &str, refs: &HashMap<String, Vec<String>>, out: &mut BTreeSet<String>) {
    if !out.insert(seed.to_string()) {
        return;
    }
    if let Some(children) = refs.get(seed) {
        for c in children {
            close_over(c, refs, out);
        }
    }
}

/// Add `#[derive(JsonSchema)] #[schemars(crate=...)]` to every type in `needed`.
fn anchor_jsonschema(file: &mut syn::File, needed: &BTreeSet<String>) -> usize {
    let mut n = 0;
    if let Some(items) = types_mod_items_mut(file) {
        for it in items {
            let (ident, attrs) = match it {
                syn::Item::Struct(s) => (s.ident.to_string(), &mut s.attrs),
                syn::Item::Enum(e) => (e.ident.to_string(), &mut e.attrs),
                _ => continue,
            };
            if !needed.contains(&ident) {
                continue;
            }
            attrs.push(syn::parse_quote!(
                #[derive(::plugin_toolkit::schemars::JsonSchema)]
            ));
            attrs.push(syn::parse_quote!(
                #[schemars(crate = "::plugin_toolkit::schemars")]
            ));
            n += 1;
        }
    }
    n
}

// ── syn helpers ─────────────────────────────────────────────────────────────

fn types_mod_items(file: &syn::File) -> Option<&Vec<syn::Item>> {
    file.items.iter().find_map(|it| match it {
        syn::Item::Mod(m) if m.ident == "types" => m.content.as_ref().map(|(_, items)| items),
        _ => None,
    })
}

fn types_mod_items_mut(file: &mut syn::File) -> Option<&mut Vec<syn::Item>> {
    file.items.iter_mut().find_map(|it| match it {
        syn::Item::Mod(m) if m.ident == "types" => m.content.as_mut().map(|(_, items)| items),
        _ => None,
    })
}

fn collect_doc(attrs: &[syn::Attribute]) -> String {
    let mut s = String::new();
    for a in attrs {
        if a.path().is_ident("doc")
            && let syn::Meta::NameValue(nv) = &a.meta
            && let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(ls),
                ..
            }) = &nv.value
        {
            s.push_str(&ls.value());
            s.push('\n');
        }
    }
    s
}

fn is_ident(ty: &syn::Type, ident: &str) -> bool {
    matches!(ty, syn::Type::Path(p)
        if p.path.segments.last().is_some_and(|s| s.ident == ident
            && matches!(s.arguments, syn::PathArguments::None)))
}

fn option_inner(ty: &syn::Type) -> Option<&syn::Type> {
    first_generic(ty, "Option")
}

/// If `ty` is `&[T]` or `Vec<T>`, return `T`.
fn slice_or_vec_inner(ty: &syn::Type) -> Option<&syn::Type> {
    match ty {
        syn::Type::Reference(r) => match &*r.elem {
            syn::Type::Slice(s) => Some(&s.elem),
            other => slice_or_vec_inner(other),
        },
        _ => first_generic(ty, "Vec"),
    }
}

/// If `ty`'s last path segment is `name<...>`, return its first type generic.
fn first_generic<'a>(ty: &'a syn::Type, name: &str) -> Option<&'a syn::Type> {
    let syn::Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != name {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    args.args.iter().find_map(|a| match a {
        syn::GenericArgument::Type(t) => Some(t),
        _ => None,
    })
}

/// Collect bare `types::Ident` leaf idents referenced anywhere in `ty`.
fn collect_types_idents_in_ty(ty: &syn::Type, out: &mut Vec<String>) {
    match ty {
        syn::Type::Path(p) => {
            if p.path.segments.first().is_some_and(|s| s.ident == "types")
                && let Some(last) = p.path.segments.last()
            {
                out.push(last.ident.to_string());
            }
            for seg in &p.path.segments {
                if let syn::PathArguments::AngleBracketed(a) = &seg.arguments {
                    for arg in &a.args {
                        if let syn::GenericArgument::Type(t) = arg {
                            collect_types_idents_in_ty(t, out);
                        }
                    }
                }
            }
        }
        syn::Type::Reference(r) => collect_types_idents_in_ty(&r.elem, out),
        syn::Type::Slice(s) => collect_types_idents_in_ty(&s.elem, out),
        syn::Type::Tuple(t) => t
            .elems
            .iter()
            .for_each(|e| collect_types_idents_in_ty(e, out)),
        _ => {}
    }
}

/// Collect local (defined-in-`types`) idents referenced in `ty` for adjacency.
fn collect_local_idents(ty: &syn::Type, locals: &BTreeSet<String>, out: &mut Vec<String>) {
    match ty {
        syn::Type::Path(p) => {
            if let Some(last) = p.path.segments.last() {
                let id = last.ident.to_string();
                if locals.contains(&id) {
                    out.push(id);
                }
                if let syn::PathArguments::AngleBracketed(a) = &last.arguments {
                    for arg in &a.args {
                        if let syn::GenericArgument::Type(t) = arg {
                            collect_local_idents(t, locals, out);
                        }
                    }
                }
            }
        }
        syn::Type::Reference(r) => collect_local_idents(&r.elem, locals, out),
        syn::Type::Slice(s) => collect_local_idents(&s.elem, locals, out),
        syn::Type::Tuple(t) => t
            .elems
            .iter()
            .for_each(|e| collect_local_idents(e, locals, out)),
        _ => {}
    }
}

/// Rewrite `types :: ...` occurrences (as `to_token_stream` renders them) to
/// `crate :: generated :: types :: ...` for use in emitted source.
fn rewrite_types_path(s: &str) -> String {
    s.replace("types ::", "crate :: generated :: types ::")
}
