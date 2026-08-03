//! Backup KINDs contributed by the proxmox plugin (the WHAT axis that
//! `orca backup --kind <kind>` fans out over).
//!
//! proxmox is an **API-remote** plugin — there is no local `/etc/pve` to read.
//! Every KIND here captures *configuration* (not disk images) by pulling it from
//! the PVE REST API and writing plain files into the host-local `payload_dir`
//! that the generic backup engine hands us (a shared filesystem — the plugin
//! runs on the same host as the engine, so we write bytes directly rather than
//! streaming them over the socket).
//!
//! Three KINDs are registered, each with a distinct bridge invoke-prefix:
//!
//! - `pve-config` (`proxmox.__backup_pveconfig`) — one logical instance
//!   (`default`). Captures cluster/host config the API exposes: storage config
//!   (`/storage`), access users + ACL (`/access/users`, `/access/acl`), and
//!   datacenter options (`/cluster/options`), each written as a JSON file.
//!   Restore best-effort re-applies datacenter options (safe + idempotent) and
//!   is **capture-only** for users/ACL/storage (re-applying those blind is
//!   destructive), which the restore path documents inline.
//! - `vm` (`proxmox.__backup_vm`) — every cluster VM as `"<node>/<vmid>"`.
//!   Captures the guest's raw config object (preserving indexed keys like
//!   `net0`/`mp0`); restore PUTs it back to
//!   `/nodes/{node}/qemu/{vmid}/config`.
//! - `lxc` (`proxmox.__backup_lxc`) — every cluster container as
//!   `"<node>/<vmid>"`; same as `vm` against `/nodes/{node}/lxc/{vmid}/config`.
//!
//! The host calls, per kind, `{prefix}.{op}` for op in
//! instances|layout|backup|restore over the subprocess socket with BARE JSON
//! requests/responses (no envelope). [`dispatch`] matches all three prefixes and
//! their four ops, decodes the arg shapes, and drives the async work to
//! completion on the subprocess reactor.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::backend_def::backup_kind_backend_def;
use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json::{self, Value, json};

use crate::{Config, GuestKind};

pub const PVECONFIG_PREFIX: &str = "proxmox.__backup_pveconfig";
pub const VM_PREFIX: &str = "proxmox.__backup_vm";
pub const LXC_PREFIX: &str = "proxmox.__backup_lxc";

/// The three `backup_kind` backend descriptors this plugin advertises, one per
/// KIND with its own invoke-prefix. `backup_kind_backend_def` enforces
/// `name == kind`, so the host records and (on unload) deregisters each by the
/// KIND name that the provider registry keys on.
pub fn backend_defs() -> Vec<BackendDef> {
    vec![
        backup_kind_backend_def("pve-config", PVECONFIG_PREFIX),
        backup_kind_backend_def("vm", VM_PREFIX),
        backup_kind_backend_def("lxc", LXC_PREFIX),
    ]
}

/// Handle a `proxmox.__backup_*` bridge call. Returns `None` for anything that
/// isn't one of the three backup prefixes so [`crate::registration::backend_dispatch`]
/// falls through to the next handler (and ultimately the `#[orca_tool]` surface).
pub fn dispatch(name: &str, args_json: &str) -> Option<Result<String, String>> {
    let (kind, op) = match_prefix(name)?;
    Some(plugin_toolkit::reactor::block_on(async move {
        run(kind, op, args_json).await.map_err(|e| e.to_string())
    }))
}

/// Which KIND a `vm`/`lxc` prefix maps onto for the API path.
#[derive(Clone, Copy)]
enum Kind {
    PveConfig,
    Vm,
    Lxc,
}

/// Split a bridge tool name into `(kind, op)` if it targets one of our backup
/// prefixes; `None` otherwise.
fn match_prefix(name: &str) -> Option<(Kind, &str)> {
    for (prefix, kind) in [
        (PVECONFIG_PREFIX, Kind::PveConfig),
        (VM_PREFIX, Kind::Vm),
        (LXC_PREFIX, Kind::Lxc),
    ] {
        if let Some(op) = name.strip_prefix(prefix).and_then(|s| s.strip_prefix('.')) {
            return Some((kind, op));
        }
    }
    None
}

async fn run(kind: Kind, op: &str, args_json: &str) -> Result<String> {
    match (kind, op) {
        // ── pve-config ──────────────────────────────────────────────────────
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

        // ── vm / lxc ────────────────────────────────────────────────────────
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

        (_, other) => Err(anyhow!("proxmox backup: unknown op '{other}'")),
    }
}

fn guest_kind(kind: Kind) -> GuestKind {
    match kind {
        Kind::Lxc => GuestKind::Lxc,
        _ => GuestKind::Qemu,
    }
}

// ── request decoders ────────────────────────────────────────────────────────

/// `{"instance":"<id>"}` → `<id>`.
fn decode_instance(args_json: &str) -> Result<String> {
    let v: Value = serde_json::from_str(args_json).context("backup: parse instance args")?;
    Ok(v.get("instance")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string())
}

/// `{"payload_dir":"<path>","instance":"<id>"}` → `(dir, instance)`.
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

// ── guest (vm / lxc) KIND ───────────────────────────────────────────────────

/// Every cluster guest of `kind`, as `"<node>/<vmid>"`, across every enabled
/// endpoint. One `/cluster/resources` call per endpoint keeps this cheap enough
/// for the bridge's synchronous `instances` call.
async fn guest_instances(kind: GuestKind) -> Result<String> {
    use crate::generated::types as gtypes;
    let want = match kind {
        GuestKind::Qemu => gtypes::GetResourcesClusterResourcesResponseItemType::Qemu,
        GuestKind::Lxc => gtypes::GetResourcesClusterResourcesResponseItemType::Lxc,
    };
    let mut ids = Vec::new();
    for name in crate::tools::enabled_endpoint_names() {
        let cfg = match crate::tools::resolve_config(&name).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(endpoint = %name, error = %e, "backup instances: resolve failed");
                continue;
            }
        };
        let client = cfg.build_generated_client()?;
        let items = match client
            .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
            .await
        {
            Ok(r) => r.into_inner(),
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

/// Capture one guest's raw config object to `payload_dir/config.json`. The raw
/// endpoint (vs the generated client) preserves indexed keys — `net0`, `mp0`,
/// … — that progenitor collapses.
async fn guest_backup(kind: GuestKind, instance: &str, dir: &str) -> Result<String> {
    let (node, vmid) = parse_instance(instance)?;
    let (cfg, _) = resolve_endpoint_for_node(&node).await?;
    let http = cfg.build_reqwest_client()?;
    let path = format!("nodes/{}/{}/{}/config", enc(&node), kind.as_str(), vmid);
    let data = raw_get_data(&http, &cfg.base_url, &path)
        .await
        .with_context(|| format!("backup: fetch config for {instance}"))?;
    let keys = data.as_object().map(|m| m.len()).unwrap_or(0);
    write_json(dir, "config.json", &data)?;
    Ok(json!({
        "checksum": Value::Null,
        "note": format!("captured {} config keys for {}/{}/{}", keys, node, kind.as_str(), vmid),
    })
    .to_string())
}

/// Restore a guest config by PUTting the captured keys back to
/// `/nodes/{node}/{kind}/{vmid}/config`. Server-managed / read-only keys are
/// dropped (`digest`, `meta`, `lock`) so the PUT does not reject the batch.
async fn guest_restore(kind: GuestKind, instance: &str, dir: &str) -> Result<String> {
    let (node, vmid) = parse_instance(instance)?;
    let data = read_json(dir, "config.json")?;
    let obj = data
        .as_object()
        .ok_or_else(|| anyhow!("restore: config.json is not an object"))?;

    // Read-only / server-managed keys the config PUT rejects or ignores.
    const SKIP: &[&str] = &["digest", "meta", "lock"];
    let pairs = form_pairs(obj, SKIP);

    let (cfg, _) = resolve_endpoint_for_node(&node).await?;
    let http = cfg.build_reqwest_client()?;
    let url = format!(
        "{}/nodes/{}/{}/{}/config",
        cfg.base_url.trim_end_matches('/'),
        enc(&node),
        kind.as_str(),
        vmid
    );
    put_form(&http, &url, &pairs).await?;
    Ok(Value::Null.to_string())
}

// ── pve-config KIND ─────────────────────────────────────────────────────────

/// One (path, filename) capture spec for the cluster/host config pull. Each is a
/// GET whose `data` payload is written verbatim as a JSON file.
const PVECONFIG_CAPTURES: &[(&str, &str)] = &[
    ("storage", "storage.json"),
    ("access/users", "users.json"),
    ("access/acl", "acl.json"),
    ("cluster/options", "datacenter.json"),
];

/// Capture cluster/host config from the first reachable enabled endpoint —
/// cluster-scoped config is identical across member nodes, so one endpoint
/// suffices. A capture that the API refuses (e.g. token lacks the privilege) is
/// logged and skipped rather than failing the whole run.
async fn pveconfig_backup(dir: &str) -> Result<String> {
    let cfg = first_enabled_config()
        .await
        .context("pve-config backup: no reachable endpoint")?;
    let http = cfg.build_reqwest_client()?;
    let mut captured = Vec::new();
    for (path, file) in PVECONFIG_CAPTURES {
        match raw_get_data(&http, &cfg.base_url, path).await {
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

/// Best-effort re-apply of captured cluster config.
///
/// Only datacenter options (`PUT /cluster/options`) are re-applied — that write
/// is safe and idempotent. Users, ACL and storage are **capture-only**: blindly
/// PUT/POSTing them back could delete live grants or clobber storage definitions
/// other nodes depend on, so this path intentionally does not re-apply them. The
/// captured JSON files remain in `payload_dir` for an operator to reconcile by
/// hand.
async fn pveconfig_restore(dir: &str) -> Result<String> {
    // datacenter options: the one safe, idempotent re-apply. `digest` guards
    // against concurrent edits — omit it so a stale digest can't reject the PUT.
    let datacenter = read_json(dir, "datacenter.json").ok();
    let pairs = datacenter
        .as_ref()
        .and_then(Value::as_object)
        .map(|obj| form_pairs(obj, &["digest"]))
        .unwrap_or_default();
    if !pairs.is_empty() {
        let cfg = first_enabled_config()
            .await
            .context("pve-config restore: no reachable endpoint")?;
        let http = cfg.build_reqwest_client()?;
        let url = format!("{}/cluster/options", cfg.base_url.trim_end_matches('/'));
        put_form(&http, &url, &pairs).await?;
    }
    // users / acl / storage are capture-only by design (see fn doc).
    Ok(Value::Null.to_string())
}

// ── shared helpers ──────────────────────────────────────────────────────────

fn enc(s: &str) -> String {
    plugin_toolkit::progenitor_client::encode_path(s)
}

/// Flatten a JSON object into `(key, value)` form pairs for a PVE config PUT,
/// dropping `skip` keys and JSON nulls. Strings pass through verbatim; other
/// scalars render via their JSON text.
fn form_pairs(obj: &serde_json::Map<String, Value>, skip: &[&str]) -> Vec<(String, String)> {
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

/// PUT a form-urlencoded body of `pairs` and fail on a non-2xx status. Uses the
/// delegated-http shim's `form_urlencoded` (over `QueryParam`), which sets the
/// `application/x-www-form-urlencoded` content-type.
async fn put_form(http: &reqwest::Client, url: &str, pairs: &[(String, String)]) -> Result<()> {
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
    let resp = http
        .put(url)
        .header(
            "content-type",
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .body(body.into_bytes())
        .send()
        .await
        .map_err(|e| anyhow!("PUT {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("PUT {url}: HTTP {}: {body}", status.as_u16()));
    }
    Ok(())
}

/// Parse a `"<node>/<vmid>"` instance id.
fn parse_instance(instance: &str) -> Result<(String, u64)> {
    let (node, vmid) = instance
        .split_once('/')
        .ok_or_else(|| anyhow!("backup: malformed instance '{instance}' (want <node>/<vmid>)"))?;
    let vmid: u64 = vmid
        .parse()
        .map_err(|_| anyhow!("backup: non-numeric vmid in '{instance}'"))?;
    Ok((node.to_string(), vmid))
}

/// Resolve the enabled endpoint whose cluster hosts `node`, returning its ready
/// [`Config`] and name. Probes each endpoint's `/nodes` listing and matches by
/// node name (unique within a cluster/fleet).
async fn resolve_endpoint_for_node(node: &str) -> Result<(Config, String)> {
    for name in crate::tools::enabled_endpoint_names() {
        let cfg = match crate::tools::resolve_config(&name).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(endpoint = %name, error = %e, "backup: resolve endpoint failed");
                continue;
            }
        };
        let http = cfg.build_reqwest_client()?;
        if let Ok(nodes) = raw_get_data(&http, &cfg.base_url, "nodes").await {
            let hit = nodes
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .any(|n| n.get("node").and_then(Value::as_str) == Some(node))
                })
                .unwrap_or(false);
            if hit {
                return Ok((cfg, name));
            }
        }
    }
    Err(anyhow!("backup: no enabled endpoint hosts node '{node}'"))
}

/// The first enabled endpoint that resolves — used for cluster-scoped config
/// that is identical on every member.
async fn first_enabled_config() -> Result<Config> {
    for name in crate::tools::enabled_endpoint_names() {
        match crate::tools::resolve_config(&name).await {
            Ok(c) => return Ok(c),
            Err(e) => {
                tracing::warn!(endpoint = %name, error = %e, "backup: resolve endpoint failed");
            }
        }
    }
    Err(anyhow!("backup: no enabled endpoint resolved"))
}

/// Raw GET against the PVE REST API, peeling the `{"data": …}` envelope every
/// endpoint wraps its payload in. `path` is joined onto the API root
/// (`Config::base_url`, e.g. `https://host:8006/api2/json`).
async fn raw_get_data(http: &reqwest::Client, base_url: &str, path: &str) -> Result<Value> {
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
