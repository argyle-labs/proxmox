use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::GuestKind;
use crate::backup::config_op;
use crate::responses::{ClusterResource, ResourceType, cluster_resources};
use crate::tools::{EndpointFailure, fan_out_enabled_endpoints};

pub const ORCA_TAG: &str = "orca-managed";
pub const BLOCK_BEGIN: &str = "<!-- orca-managed -->";
pub const BLOCK_END: &str = "<!-- /orca-managed -->";

pub const ROLES: &[(&str, &[&str])] = &[
    (
        "media",
        &[
            "plex",
            "jellyfin",
            "emby",
            "sonarr",
            "radarr",
            "lidarr",
            "readarr",
            "prowlarr",
            "bazarr",
            "mylar",
            "komga",
            "kavita",
            "audiobookshelf",
            "calibre",
            "lazylibrarian",
            "qbittorrent",
            "sabnzbd",
            "nzbget",
            "immich",
            "navidrome",
            "tautulli",
            "overseerr",
            "jellyseerr",
            "libation",
            "media",
        ],
    ),
    (
        "backup",
        &[
            "pbs",
            "backup",
            "restic",
            "borg",
            "duplicati",
            "kopia",
            "urbackup",
        ],
    ),
    (
        "ci",
        &[
            "runner",
            "ci",
            "jenkins",
            "drone",
            "woodpecker",
            "buildkite",
        ],
    ),
    (
        "ai",
        &[
            "ollama",
            "llm",
            "lmstudio",
            "openwebui",
            "comfyui",
            "whisper",
            "localai",
            "vllm",
        ],
    ),
    (
        "network",
        &[
            "adguard",
            "pihole",
            "unbound",
            "dns",
            "tailscale",
            "headscale",
            "wireguard",
            "nginx",
            "traefik",
            "caddy",
            "haproxy",
            "opnsense",
            "pfsense",
            "proxy",
            "gateway",
        ],
    ),
    (
        "storage",
        &[
            "nas",
            "nfs",
            "samba",
            "smb",
            "truenas",
            "garage",
            "minio",
            "ceph",
            "zfs",
            "storage",
            "seaweedfs",
        ],
    ),
    (
        "home",
        &[
            "homeassistant",
            "hass",
            "zwave",
            "zigbee",
            "zigbee2mqtt",
            "z2m",
            "mosquitto",
            "mqtt",
            "nodered",
            "esphome",
        ],
    ),
    (
        "infra",
        &[
            "gitea",
            "forgejo",
            "vault",
            "hydra",
            "authentik",
            "keycloak",
            "postgres",
            "mariadb",
            "mysql",
            "redis",
            "docker",
            "portainer",
            "zot",
            "registry",
            "orca",
            "grafana",
            "prometheus",
            "loki",
            "uptime",
        ],
    ),
];

const GENERIC_NAMES: &[&str] = &[
    "debian",
    "ubuntu",
    "alpine",
    "centos",
    "rocky",
    "fedora",
    "arch",
    "test",
    "new",
    "temp",
    "tmp",
    "unnamed",
    "default",
    "template",
    "container",
    "vm",
    "ct",
    "lxc",
    "localhost",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GuestLabels {
    pub tags: Vec<String>,
    pub description: String,
}

pub fn kind_tag(kind: GuestKind) -> &'static str {
    match kind {
        GuestKind::Qemu => "vm",
        GuestKind::Lxc => "lxc",
    }
}

pub fn parse_tags(raw: &str) -> Vec<String> {
    raw.split([';', ',', ' '])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn normalize_tag(raw: &str) -> Option<String> {
    let mapped: String = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let tag = mapped
        .trim_start_matches(['-', '+', '.'])
        .trim_end_matches('-');
    (!tag.is_empty()).then(|| tag.to_string())
}

pub fn merge_tags(existing: &[String], wanted: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in existing.iter().chain(wanted) {
        if !out.iter().any(|o| o.eq_ignore_ascii_case(t)) {
            out.push(t.clone());
        }
    }
    out
}

fn name_tokens(name: &str) -> Vec<String> {
    name.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

fn keyword_matches(token: &str, keyword: &str) -> bool {
    token == keyword || (keyword.len() >= 4 && token.starts_with(keyword))
}

pub fn known_role(tag: &str) -> Option<&'static str> {
    ROLES
        .iter()
        .find(|(role, _)| role.eq_ignore_ascii_case(tag))
        .map(|(role, _)| *role)
}

pub fn derive_role(name: &str, tags: &[String]) -> Option<(&'static str, Option<&'static str>)> {
    let tokens = name_tokens(name);
    let by_name = ROLES.iter().find_map(|(role, keywords)| {
        keywords
            .iter()
            .find(|k| tokens.iter().any(|t| keyword_matches(t, k)))
            .map(|k| (*role, *k))
    });
    match (tags.iter().find_map(|t| known_role(t)), by_name) {
        (Some(role), keyword) => Some((role, keyword.map(|(_, k)| k))),
        (None, Some((role, k))) => Some((role, Some(k))),
        (None, None) => None,
    }
}

pub fn scheme_tags(
    kind: GuestKind,
    role: Option<&str>,
    stack: Option<&str>,
    extra: &[String],
) -> Vec<String> {
    let mut raw = vec![kind_tag(kind).to_string()];
    raw.extend(role.map(str::to_string));
    raw.push(ORCA_TAG.to_string());
    raw.extend(stack.map(|s| format!("stack-{s}")));
    raw.extend(extra.iter().cloned());
    let normalized: Vec<String> = raw.iter().filter_map(|t| normalize_tag(t)).collect();
    merge_tags(&[], &normalized)
}

pub fn unclear_name(name: &str, kind: GuestKind, vmid: u64) -> Option<String> {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return Some("name is empty".into());
    }
    let id = vmid.to_string();
    let defaults = [
        format!("{}-{id}", kind_tag(kind)),
        format!("ct{id}"),
        format!("ct-{id}"),
        format!("vm{id}"),
        format!("vm-{id}"),
        format!("lxc{id}"),
        format!("lxc-{id}"),
        format!("{}-{id}", "qemu"),
        id.clone(),
    ];
    if defaults.contains(&lower) {
        return Some(format!("'{name}' is a default name derived from the vmid"));
    }
    if lower.starts_with("copy-of-") || lower.starts_with("clone-") {
        return Some(format!("'{name}' is a copy/clone name"));
    }
    if GENERIC_NAMES.contains(&lower.as_str()) {
        return Some(format!(
            "'{name}' names the OS or a placeholder, not the service"
        ));
    }
    if lower.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return Some(format!("'{name}' is only digits"));
    }
    let clean = name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    (!clean).then(|| format!("'{name}' is not a clean lowercase DNS label"))
}

pub fn service_text(
    service: Option<&str>,
    derived: Option<(&str, Option<&str>)>,
    kind: GuestKind,
) -> String {
    match (service.map(str::trim).filter(|s| !s.is_empty()), derived) {
        (Some(s), _) => s.to_string(),
        (None, Some((role, Some(keyword)))) => format!("{keyword} ({role})"),
        (None, Some((role, None))) => format!("{role} service"),
        (None, None) => format!("{} guest; service not yet described", kind_tag(kind)),
    }
}

pub fn orca_block(name: &str, service: &str, unit_id: &str) -> String {
    format!(
        "{BLOCK_BEGIN}\n**{name}**: {service}\n\nManaged by orca. Unit id: `{unit_id}`\n{BLOCK_END}"
    )
}

pub fn has_orca_block(description: &str) -> bool {
    description
        .find(BLOCK_BEGIN)
        .is_some_and(|start| description[start..].contains(BLOCK_END))
}

pub fn merge_description(existing: Option<&str>, block: &str) -> String {
    let existing = existing.unwrap_or_default();
    if let Some(start) = existing.find(BLOCK_BEGIN)
        && let Some(len) = existing[start..].find(BLOCK_END)
    {
        let tail = &existing[start + len + BLOCK_END.len()..];
        return format!("{}{block}{tail}", &existing[..start]);
    }
    let operator = existing.trim_end();
    if operator.is_empty() {
        block.to_string()
    } else {
        format!("{operator}\n\n{block}")
    }
}

#[allow(clippy::too_many_arguments)]
pub fn labels_for(
    kind: GuestKind,
    name: &str,
    unit_id: &str,
    role: Option<&str>,
    service: Option<&str>,
    stack: Option<&str>,
    extra: &[String],
    existing: &[String],
) -> GuestLabels {
    let hint = merge_tags(existing, extra);
    let derived = match role {
        Some(r) => Some((r, None)),
        None => derive_role(name, &hint),
    };
    GuestLabels {
        tags: scheme_tags(kind, derived.map(|(r, _)| r), stack, extra),
        description: orca_block(name, &service_text(service, derived, kind), unit_id),
    }
}

pub fn unit_id(cluster: Option<&str>, endpoint: &str, kind: GuestKind, vmid: u64) -> String {
    crate::unit_provider::canonical_id(cluster, endpoint, kind_tag(kind), vmid)
}

fn cluster_name(endpoint: &str) -> Option<String> {
    crate::cluster::fetch_cluster_status(endpoint)
        .ok()
        .and_then(|s| s.name)
}

fn guest_kind(r: &ClusterResource) -> Option<GuestKind> {
    match r.type_ {
        ResourceType::Qemu => Some(GuestKind::Qemu),
        ResourceType::Lxc => Some(GuestKind::Lxc),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct Guest {
    node: String,
    kind: GuestKind,
    vmid: u64,
    name: String,
    tags: Vec<String>,
    description: Option<String>,
    digest: Option<String>,
}

fn name_key(kind: GuestKind) -> &'static str {
    match kind {
        GuestKind::Qemu => "name",
        GuestKind::Lxc => "hostname",
    }
}

fn read_guest(
    endpoint: &str,
    node: &str,
    kind: GuestKind,
    vmid: u64,
    fallback: Option<&str>,
) -> Result<Guest> {
    let cfg: Value = plugin_toolkit::api::call(
        config_op(kind, "get"),
        endpoint,
        json!({ "node": node, "vmid": vmid }),
    )
    .map_err(|e| e.context(format!("{} {vmid} config", kind_tag(kind))))?;
    let text = |k: &str| cfg.get(k).and_then(Value::as_str).map(str::to_string);
    Ok(Guest {
        node: node.to_string(),
        kind,
        vmid,
        name: text(name_key(kind))
            .or_else(|| fallback.map(str::to_string))
            .unwrap_or_default(),
        tags: text("tags").map(|t| parse_tags(&t)).unwrap_or_default(),
        description: text("description").filter(|d| !d.trim().is_empty()),
        digest: text("digest"),
    })
}

type Located = (String, GuestKind, u64, Option<String>);

fn guests(endpoint: &str, node: Option<&str>) -> Result<Vec<Located>> {
    Ok(cluster_resources(endpoint, Some("vm"))?
        .into_iter()
        .filter(|r| r.template != Some(true))
        .filter_map(|r| {
            let kind = guest_kind(&r)?;
            let n = r.node.filter(|n| !n.is_empty())?;
            let vmid = u64::try_from(r.vmid?).ok().filter(|v| *v > 0)?;
            Some((n, kind, vmid, r.name))
        })
        .filter(|(n, ..)| node.is_none_or(|want| want == n))
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GuestLabelRow {
    pub endpoint: String,
    pub node: String,
    pub kind: String,
    pub vmid: u64,
    pub name: String,
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub unit_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub suggested_tags: Vec<String>,
    pub issues: Vec<String>,
}

fn audit_row(endpoint: &str, cluster: Option<&str>, g: &Guest) -> GuestLabelRow {
    let mut issues = Vec::new();
    if g.tags.is_empty() {
        issues.push("missing_tags".to_string());
    }
    if g.description.is_none() {
        issues.push("missing_description".to_string());
    }
    if let Some(reason) = unclear_name(&g.name, g.kind, g.vmid) {
        issues.push(format!("unclear_name: {reason}"));
    }
    let labelled = g.tags.iter().any(|t| t.eq_ignore_ascii_case(ORCA_TAG))
        && g.description.as_deref().is_some_and(has_orca_block);
    if !labelled && !g.tags.is_empty() && g.description.is_some() {
        issues.push("missing_orca_label".to_string());
    }
    let derived = derive_role(&g.name, &g.tags);
    GuestLabelRow {
        endpoint: endpoint.to_string(),
        node: g.node.clone(),
        kind: kind_tag(g.kind).to_string(),
        vmid: g.vmid,
        name: g.name.clone(),
        tags: g.tags.clone(),
        description: g.description.clone(),
        unit_id: unit_id(cluster, endpoint, g.kind, g.vmid),
        role: derived.map(|(r, _)| r.to_string()),
        suggested_tags: merge_tags(
            &g.tags,
            &scheme_tags(g.kind, derived.map(|(r, _)| r), None, &[]),
        ),
        issues,
    }
}

fn audit_endpoint(
    endpoint: &str,
    node: Option<&str>,
    all: bool,
) -> Result<(Vec<GuestLabelRow>, Vec<EndpointFailure>)> {
    let cluster = cluster_name(endpoint);
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    for (n, kind, vmid, fallback) in guests(endpoint, node)? {
        match read_guest(endpoint, &n, kind, vmid, fallback.as_deref()) {
            Ok(g) => {
                let row = audit_row(endpoint, cluster.as_deref(), &g);
                if all || !row.issues.is_empty() {
                    rows.push(row);
                }
            }
            Err(e) => failures.push(EndpointFailure {
                endpoint: Some(endpoint.to_string()),
                error: format!("{e:#}"),
            }),
        }
    }
    Ok((rows, failures))
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GuestLabelAuditArgs {
    /// Registered endpoint. Omit to audit every enabled endpoint.
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Limit to one node.
    #[arg(long)]
    #[serde(default)]
    pub node: Option<String>,
    /// Include guests with no issues.
    #[arg(long)]
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GuestLabelAudit {
    pub guests: Vec<GuestLabelRow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<EndpointFailure>,
}

/// List every VM and LXC missing tags or a description, or with a default or
/// unclear name, with its current tags, name, description, orca unit id and
/// the tags `proxmox.guest.label.apply` would add.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.label.audit",
    execute_gated = false,
    role = "read",
    reaches = [
        "proxmox.get_resources_cluster_resources",
        "proxmox.get_vm_config_nodes_node_qemu_vmid_config",
        "proxmox.get_vm_config_nodes_node_lxc_vmid_config"
    ]
)]
async fn proxmox_guest_label_audit(
    args: GuestLabelAuditArgs,
    _ctx: &ToolCtx,
) -> Result<GuestLabelAudit> {
    if let Some(name) = &args.endpoint {
        let (guests, failures) = audit_endpoint(name, args.node.as_deref(), args.all)?;
        return Ok(GuestLabelAudit { guests, failures });
    }
    let node = args.node.clone();
    let all = args.all;
    let fan = fan_out_enabled_endpoints("guest.label.audit", |_, ep| {
        let node = node.clone();
        async move { Ok(vec![audit_endpoint(&ep.name, node.as_deref(), all)?]) }
    })
    .await;
    if fan.items.is_empty() && fan.attempted == 0 && fan.failures.is_empty() {
        bail!("no enabled proxmox endpoints to audit");
    }
    let mut out = GuestLabelAudit {
        guests: Vec::new(),
        failures: fan.failures,
    };
    for (guests, failures) in fan.items {
        out.guests.extend(guests);
        out.failures.extend(failures);
    }
    Ok(out)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GuestLabelApplyArgs {
    #[arg(long)]
    pub endpoint: String,
    /// Guest ids (VM or LXC) to label.
    #[arg(long)]
    #[serde(default)]
    pub vmid: Vec<u64>,
    /// Label every guest on the endpoint (or `node`).
    #[arg(long)]
    #[serde(default)]
    pub all: bool,
    /// Limit `all` to one node.
    #[arg(long)]
    #[serde(default)]
    pub node: Option<String>,
    /// Role tag; derived from the guest name or tags when omitted.
    #[arg(long)]
    #[serde(default)]
    pub role: Option<String>,
    /// What the service is, for the description.
    #[arg(long)]
    #[serde(default)]
    pub service: Option<String>,
    /// Orca stack, tagged `stack-<stack>`.
    #[arg(long)]
    #[serde(default)]
    pub stack: Option<String>,
    /// Extra tags (orca unit tags and the like).
    #[arg(long)]
    #[serde(default)]
    pub tags: Vec<String>,
    /// New clean name; only with a single `vmid`.
    #[arg(long)]
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GuestLabelChange {
    pub node: String,
    pub kind: String,
    pub vmid: u64,
    pub name: String,
    pub tags_before: Vec<String>,
    pub tags_after: Vec<String>,
    pub description_changed: bool,
    pub renamed: bool,
    pub applied: bool,
}

fn plan_guest(
    g: &Guest,
    unit_id: &str,
    args: &GuestLabelApplyArgs,
) -> Result<(GuestLabelChange, serde_json::Map<String, Value>)> {
    if let Some(n) = &args.name
        && let Some(reason) = unclear_name(n, g.kind, g.vmid)
    {
        bail!("refusing name: {reason}");
    }
    let name = args.name.clone().unwrap_or_else(|| g.name.clone());
    let role = args.role.as_deref().and_then(normalize_tag);
    let labels = labels_for(
        g.kind,
        &name,
        unit_id,
        role.as_deref(),
        args.service.as_deref(),
        args.stack.as_deref(),
        &args.tags,
        &g.tags,
    );
    let tags_after = merge_tags(&g.tags, &labels.tags);
    let description = merge_description(g.description.as_deref(), &labels.description);
    let mut body = serde_json::Map::new();
    if tags_after != g.tags {
        body.insert("tags".into(), json!(tags_after.join(";")));
    }
    let description_changed = g.description.as_deref() != Some(description.as_str());
    if description_changed {
        body.insert("description".into(), json!(description));
    }
    let renamed = name != g.name;
    if renamed {
        body.insert(name_key(g.kind).into(), json!(name));
    }
    Ok((
        GuestLabelChange {
            node: g.node.clone(),
            kind: kind_tag(g.kind).to_string(),
            vmid: g.vmid,
            name,
            tags_before: g.tags.clone(),
            tags_after,
            description_changed,
            renamed,
            applied: false,
        },
        body,
    ))
}

fn apply_endpoint(args: &GuestLabelApplyArgs, dry_run: bool) -> Result<Vec<GuestLabelChange>> {
    if args.all != args.vmid.is_empty() {
        bail!("set either `vmid` or `all`");
    }
    if args.name.is_some() && args.vmid.len() != 1 {
        bail!("`name` needs exactly one `vmid`");
    }
    let found = guests(&args.endpoint, args.node.as_deref())?;
    let selected: Vec<_> = if args.all {
        found
    } else {
        args.vmid
            .iter()
            .map(|v| {
                found
                    .iter()
                    .find(|(_, _, id, _)| id == v)
                    .cloned()
                    .ok_or_else(|| anyhow!("guest {v} not found on '{}'", args.endpoint))
            })
            .collect::<Result<_>>()?
    };
    let cluster = cluster_name(&args.endpoint);
    let mut out = Vec::new();
    for (node, kind, vmid, fallback) in selected {
        let g = read_guest(&args.endpoint, &node, kind, vmid, fallback.as_deref())?;
        let uid = unit_id(cluster.as_deref(), &args.endpoint, kind, vmid);
        let (mut change, body) = plan_guest(&g, &uid, args)?;
        if !body.is_empty() && !dry_run {
            let Some(digest) = &g.digest else {
                bail!(
                    "{} {vmid} config read returned no digest; refusing an unguarded write",
                    kind_tag(kind)
                );
            };
            let mut body = body;
            body.insert("digest".into(), json!(digest));
            plugin_toolkit::api::call::<Value>(
                config_op(kind, "put"),
                &args.endpoint,
                json!({ "node": node, "vmid": vmid, "body": Value::Object(body) }),
            )
            .map_err(|e| e.context(format!("{} {vmid} config PUT", kind_tag(kind))))?;
            change.applied = true;
        }
        out.push(change);
    }
    Ok(out)
}

/// [MUTATES STATE] Set tags and the orca-managed description block on one or
/// more guests via the PVE config PUT. Existing tags and operator-written
/// description text are kept; only the orca block is added or replaced.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.label.apply",
    role = "admin",
    dry_run_aware = true,
    reaches = [
        "proxmox.get_resources_cluster_resources",
        "proxmox.get_vm_config_nodes_node_qemu_vmid_config",
        "proxmox.get_vm_config_nodes_node_lxc_vmid_config",
        "proxmox.put_update_vm_nodes_node_qemu_vmid_config",
        "proxmox.put_update_vm_nodes_node_lxc_vmid_config"
    ]
)]
async fn proxmox_guest_label_apply(
    args: GuestLabelApplyArgs,
    ctx: &ToolCtx,
) -> Result<Vec<GuestLabelChange>> {
    crate::execute::require_admin("proxmox.guest.label.apply", ctx.caller().as_ref())?;
    apply_endpoint(&args, ctx.dry_run())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::record_api_calls;

    fn guest(name: &str, tags: &[&str], description: Option<&str>) -> Guest {
        Guest {
            node: "thor".into(),
            kind: GuestKind::Lxc,
            vmid: 112,
            name: name.into(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            description: description.map(str::to_string),
            digest: Some("d".into()),
        }
    }

    fn apply_args() -> GuestLabelApplyArgs {
        serde_json::from_value(json!({ "endpoint": "pve", "vmid": [112] })).unwrap()
    }

    #[test]
    fn tags_parse_normalize_and_merge_without_duplicates() {
        assert_eq!(parse_tags("a;b, c d"), ["a", "b", "c", "d"]);
        assert_eq!(normalize_tag("Media Box").as_deref(), Some("media-box"));
        assert_eq!(normalize_tag("--"), None);
        let merged = merge_tags(
            &["Prod".into(), "lxc".into()],
            &["lxc".into(), "prod".into(), "orca-managed".into()],
        );
        assert_eq!(merged, ["Prod", "lxc", "orca-managed"]);
    }

    #[test]
    fn role_derives_from_name_tokens_or_existing_tags() {
        assert_eq!(
            derive_role("sonarr-4k", &[]),
            Some(("media", Some("sonarr")))
        );
        assert_eq!(
            derive_role("gitea-runner-1", &[]),
            Some(("ci", Some("runner")))
        );
        assert_eq!(
            derive_role("adguard", &[]),
            Some(("network", Some("adguard")))
        );
        assert_eq!(
            derive_role("freyr", &["media".into()]),
            Some(("media", None))
        );
        assert_eq!(
            derive_role("sonarr", &["infra".into()]),
            Some(("infra", Some("sonarr")))
        );
        assert_eq!(derive_role("freyr", &[]), None);
        assert_eq!(derive_role("pci-host", &[]), None);
    }

    #[test]
    fn scheme_orders_kind_role_orca_stack_extra() {
        assert_eq!(
            scheme_tags(
                GuestKind::Qemu,
                Some("ai"),
                Some("LLM Stack"),
                &["unit-x".into()]
            ),
            ["vm", "ai", "orca-managed", "stack-llm-stack", "unit-x"]
        );
        assert_eq!(
            scheme_tags(GuestKind::Lxc, None, None, &[]),
            ["lxc", "orca-managed"]
        );
    }

    #[test]
    fn unclear_names_are_flagged() {
        let k = GuestKind::Lxc;
        assert!(unclear_name("", k, 101).is_some());
        assert!(unclear_name("lxc-101", k, 101).is_some());
        assert!(unclear_name("CT101", k, 101).is_some());
        assert!(unclear_name("debian", k, 101).is_some());
        assert!(unclear_name("copy-of-plex", k, 101).is_some());
        assert!(unclear_name("Plex_Server", k, 101).is_some());
        assert!(unclear_name("plex", k, 101).is_none());
        assert!(unclear_name("vm-102", GuestKind::Qemu, 102).is_some());
    }

    #[test]
    fn description_keeps_operator_text_and_replaces_only_the_block() {
        let block = orca_block("plex", "plex (media)", "cluster:c/lxc/112");
        assert_eq!(merge_description(None, &block), block);
        let first = merge_description(Some("Operator notes.\n"), &block);
        assert_eq!(first, format!("Operator notes.\n\n{block}"));
        let newer = orca_block("plex", "plex media server", "cluster:c/lxc/112");
        let second = merge_description(Some(&format!("{first}\nfooter")), &newer);
        assert_eq!(second, format!("Operator notes.\n\n{newer}\nfooter"));
        assert!(!second.contains("plex (media)"));
    }

    #[test]
    fn audit_row_lists_every_issue_and_suggests_tags() {
        let row = audit_row("pve", Some("c"), &guest("lxc-112", &[], None));
        assert_eq!(row.unit_id, "cluster:c/lxc/112");
        assert_eq!(row.issues.len(), 3, "{:?}", row.issues);
        assert_eq!(row.suggested_tags, ["lxc", "orca-managed"]);
        let ok = guest(
            "plex",
            &["lxc", "media", "orca-managed"],
            Some(&orca_block("plex", "plex (media)", "u")),
        );
        assert!(audit_row("pve", None, &ok).issues.is_empty());
        let partial = audit_row("pve", None, &guest("plex", &["x"], Some("notes")));
        assert_eq!(partial.issues, ["missing_orca_label"]);
        assert_eq!(partial.role.as_deref(), Some("media"));
    }

    #[test]
    fn plan_adds_labels_and_is_idempotent() {
        let g = guest("sonarr", &["keep"], Some("Mine."));
        let (change, body) = plan_guest(&g, "endpoint:pve/lxc/112", &apply_args()).unwrap();
        assert_eq!(change.tags_after, ["keep", "lxc", "media", "orca-managed"]);
        assert_eq!(body["tags"], "keep;lxc;media;orca-managed");
        let desc = body["description"].as_str().unwrap();
        assert!(desc.starts_with("Mine.\n\n"), "{desc}");
        assert!(desc.contains("sonarr (media)") && desc.contains("endpoint:pve/lxc/112"));
        assert!(!change.renamed && !body.contains_key("hostname"));
        let again = guest(
            "sonarr",
            &["keep", "lxc", "media", "orca-managed"],
            Some(desc),
        );
        let (_, body) = plan_guest(&again, "endpoint:pve/lxc/112", &apply_args()).unwrap();
        assert!(body.is_empty(), "{body:?}");
    }

    #[test]
    fn plan_uses_caller_role_service_and_rename() {
        let mut args = apply_args();
        args.role = Some("AI".into());
        args.service = Some("Ollama inference".into());
        args.name = Some("ollama".into());
        let mut g = guest("ct112", &[], None);
        g.kind = GuestKind::Qemu;
        let (change, body) = plan_guest(&g, "u", &args).unwrap();
        assert_eq!(change.tags_after, ["vm", "ai", "orca-managed"]);
        assert_eq!(body["name"], "ollama");
        assert!(
            body["description"]
                .as_str()
                .unwrap()
                .contains("**ollama**: Ollama inference")
        );
        args.name = Some("Bad Name".into());
        assert!(plan_guest(&g, "u", &args).is_err());
    }

    #[test]
    fn apply_puts_tags_and_description_through_the_config_op() {
        let (out, calls) = record_api_calls(
            |method, path| match (method, path) {
                (_, "/cluster/resources") => {
                    r#"[{"type":"lxc","node":"thor","vmid":112,"name":"sonarr"}]"#.into()
                }
                (_, "/cluster/status") => r#"[{"type":"cluster","name":"asgard"}]"#.into(),
                ("GET", _) => r#"{"hostname":"sonarr","digest":"abc"}"#.into(),
                _ => "null".into(),
            },
            || apply_endpoint(&apply_args(), false),
        );
        let out = out.unwrap();
        assert!(out[0].applied);
        let put = calls.iter().find(|c| c.0 == "PUT").expect("a PUT");
        assert_eq!(put.1, "/nodes/thor/lxc/112/config");
        assert_eq!(put.2["body"]["tags"], "lxc;media;orca-managed");
        assert_eq!(put.2["body"]["digest"], "abc");
        let desc = put.2["body"]["description"].as_str().unwrap();
        assert!(desc.contains("Unit id: `cluster:asgard/lxc/112`"), "{desc}");
    }

    #[test]
    fn dry_run_plans_without_writing() {
        let (out, calls) = record_api_calls(
            |method, path| match (method, path) {
                (_, "/cluster/resources") => {
                    r#"[{"type":"lxc","node":"thor","vmid":112,"name":"sonarr"}]"#.into()
                }
                ("GET", _) => r#"{"hostname":"sonarr","digest":"abc"}"#.into(),
                _ => "null".into(),
            },
            || apply_endpoint(&apply_args(), true),
        );
        let out = out.unwrap();
        assert!(!out[0].applied);
        assert_eq!(out[0].tags_after, ["lxc", "media", "orca-managed"]);
        assert!(calls.iter().all(|c| c.0 != "PUT"));
    }

    #[test]
    fn apply_refuses_a_write_without_a_digest() {
        let (out, calls) = record_api_calls(
            |method, path| match (method, path) {
                (_, "/cluster/resources") => {
                    r#"[{"type":"lxc","node":"thor","vmid":112,"name":"sonarr"}]"#.into()
                }
                ("GET", _) => r#"{"hostname":"sonarr"}"#.into(),
                _ => "null".into(),
            },
            || apply_endpoint(&apply_args(), false),
        );
        assert!(out.is_err());
        assert!(calls.iter().all(|c| c.0 != "PUT"));
    }

    #[test]
    fn description_merge_ignores_a_stray_end_marker_before_the_block() {
        let block = orca_block("plex", "plex", "u");
        let existing = format!(
            "note {BLOCK_END} keep

{}",
            orca_block("plex", "old", "u")
        );
        let merged = merge_description(Some(&existing), &block);
        assert_eq!(merged, format!("note {BLOCK_END} keep\n\n{block}"));
        assert_eq!(merge_description(Some(&merged), &block), merged);
        assert!(!has_orca_block(&format!("{BLOCK_END}{BLOCK_BEGIN}")));
    }

    #[test]
    fn normalized_tags_match_the_pve_charset() {
        for raw in [
            "Media Box",
            "+x",
            ".y",
            "ü-tag",
            "a;b,c",
            "--",
            "Stack_1.2+3",
        ] {
            if let Some(t) = normalize_tag(raw) {
                let mut b = t.bytes();
                let first = b.next().unwrap();
                assert!(
                    first.is_ascii_lowercase() || first.is_ascii_digit() || first == b'_',
                    "{t}"
                );
                assert!(
                    t.bytes().all(|c| c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || matches!(c, b'_' | b'+' | b'.' | b'-')),
                    "{t}"
                );
            }
        }
    }

    #[test]
    fn apply_needs_vmid_or_all() {
        let mut args = apply_args();
        args.vmid.clear();
        assert!(apply_endpoint(&args, false).is_err());
        args.all = true;
        args.name = Some("x".into());
        assert!(apply_endpoint(&args, false).is_err());
    }
}
