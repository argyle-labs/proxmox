//! Planning a guest replacement: which settings of the old guest a new one
//! inherits. Identity (vmid, name), storage volumes, and generated
//! per-instance values stay with each guest; settings that define what the
//! guest is for carry over. Moving users, groups, and in-guest data is a
//! later slice.

use std::collections::BTreeMap;

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::GuestKind;
use crate::backup::config_op;
use crate::backup_jobs::{BackupJob, GuestRow, Selection, fetch_jobs, selects};
use crate::guest_label::{
    BLOCK_BEGIN, BLOCK_END, Located, guests, kind_tag, merge_tags, parse_tags, unit_id,
};

/// Keys never copied: identity, per-instance values, and storage the new guest
/// gets its own copy of.
const KEEP_OWN: &[&str] = &[
    "digest",
    "name",
    "hostname",
    "vmgenid",
    "smbios1",
    "meta",
    "lock",
    "parent",
    "template",
    "rootfs",
    "unprivileged",
    "ostype",
    "arch",
];

/// Prefixes of indexed keys never copied: disks and unused volumes.
const KEEP_OWN_PREFIX: &[&str] = &[
    "unused", "scsi", "sata", "ide", "virtio", "efidisk", "tpmstate",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CarryPlan {
    /// Settings to write to the new guest.
    pub copy: BTreeMap<String, String>,
    /// Settings the new guest keeps for itself; listed so nothing is dropped silently.
    pub skipped: Vec<String>,
    /// `mpN` values that point at a guest volume, not a host path. They need
    /// a data move, not a config copy.
    pub volumes_to_move: Vec<String>,
}

fn keep_own(key: &str) -> bool {
    KEEP_OWN.contains(&key)
        || KEEP_OWN_PREFIX.iter().any(|p| {
            key.strip_prefix(p)
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
        })
}

/// `net*` values with the MAC removed (LXC `hwaddr=`, QEMU `model=MAC`), so
/// PVE generates a new one.
fn without_mac(value: &str) -> String {
    value
        .split(',')
        .filter_map(|p| match p.split_once('=') {
            Some(("hwaddr", _)) => None,
            Some((model, mac)) if mac.len() == 17 && mac.matches(':').count() == 5 => {
                Some(model.to_string())
            }
            _ => Some(p.to_string()),
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn carry_over(old: &BTreeMap<String, String>) -> CarryPlan {
    let mut plan = CarryPlan {
        copy: BTreeMap::new(),
        skipped: Vec::new(),
        volumes_to_move: Vec::new(),
    };
    for (k, v) in old {
        if keep_own(k) {
            plan.skipped.push(k.clone());
        } else if k.starts_with("mp") && !v.starts_with('/') {
            plan.volumes_to_move.push(k.clone());
        } else if k.starts_with("net") {
            plan.copy.insert(k.clone(), without_mac(v));
        } else {
            plan.copy.insert(k.clone(), v.clone());
        }
    }
    plan
}

const GATEWAY_NAMES: &[&str] = &["opnsense", "pfsense", "gateway"];

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuestMigrationPlanArgs {
    #[arg(long)]
    pub endpoint: String,
    /// The guest whose identity and config move.
    #[arg(long)]
    pub source_vmid: u64,
    /// The replacement guest that takes them.
    #[arg(long)]
    pub target_vmid: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MigrationGuest {
    pub node: String,
    pub kind: String,
    pub vmid: u64,
    pub name: String,
    pub unit_id: String,
    /// The orca system id (a UUID) found in the guest's description.
    /// Will come from the core system registry once it exposes a plugin-callable lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_id: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FieldMove {
    pub field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupJobMove {
    pub id: String,
    pub covers_source: bool,
    pub covers_target: bool,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FirewallMove {
    pub source_options: Value,
    pub source_rules: usize,
    pub source_ipsets: Vec<String>,
    pub target_rules: usize,
    pub target_ipsets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuestMigrationPlan {
    /// Always `true`: this tool only reads.
    pub dry_run: bool,
    pub endpoint: String,
    pub source: MigrationGuest,
    pub target: MigrationGuest,
    /// Hostname, MAC and IP the target takes from the source.
    pub identity: Vec<FieldMove>,
    /// The target's tags after the move: its own plus the source's.
    pub tags: Vec<String>,
    pub carry: CarryPlan,
    pub backup_jobs: Vec<BackupJobMove>,
    pub firewall: FirewallMove,
    pub conflicts: Vec<String>,
}

fn is_uuid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    groups.iter().map(|g| g.len()).eq([8, 4, 4, 4, 12])
        && groups
            .iter()
            .all(|g| g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The first UUID-shaped token in the orca-managed block of a description.
pub fn system_id(description: &str) -> Option<String> {
    let start = description.find(BLOCK_BEGIN)?;
    let block = &description[start..];
    let block = &block[..block.find(BLOCK_END).unwrap_or(block.len())];
    block
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .find(|t| is_uuid(t))
        .map(str::to_ascii_lowercase)
}

/// Name/tag match is a stopgap until orca core exposes a gateway/router role in the system registry.
pub fn is_gateway(name: &str, tags: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .chain(tags.iter().map(String::as_str))
        .any(|t| GATEWAY_NAMES.iter().any(|g| t.eq_ignore_ascii_case(g)))
}

fn net_field<'a>(spec: &'a str, key: &str) -> Option<&'a str> {
    spec.split(',').find_map(|p| match p.split_once('=') {
        Some((k, v)) if k == key => Some(v),
        _ => None,
    })
}

fn mac(spec: &str) -> Option<&str> {
    net_field(spec, "hwaddr").or_else(|| {
        spec.split(',').find_map(|p| {
            p.split_once('=')
                .map(|(_, v)| v)
                .filter(|v| v.len() == 17 && v.matches(':').count() == 5)
        })
    })
}

fn indexed(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
}

fn string_map(config: &Value) -> BTreeMap<String, String> {
    config
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => u8::from(*b).to_string(),
                _ => return None,
            };
            Some((k.clone(), s))
        })
        .collect()
}

fn name_of(kind: GuestKind, cfg: &BTreeMap<String, String>) -> Option<String> {
    let key = match kind {
        GuestKind::Qemu => "name",
        GuestKind::Lxc => "hostname",
    };
    cfg.get(key).cloned()
}

/// Hostname, then per `netN` the MAC and address. A QEMU guest's address
/// lives in its cloud-init `ipconfigN`.
pub fn identity_moves(
    src_kind: GuestKind,
    src: &BTreeMap<String, String>,
    dst_kind: GuestKind,
    dst: &BTreeMap<String, String>,
    conflicts: &mut Vec<String>,
) -> Vec<FieldMove> {
    let address = |kind: GuestKind, cfg: &BTreeMap<String, String>, n: &str| match kind {
        GuestKind::Lxc => cfg
            .get(&format!("net{n}"))
            .and_then(|s| net_field(s, "ip"))
            .map(str::to_string),
        GuestKind::Qemu => cfg
            .get(&format!("ipconfig{n}"))
            .and_then(|s| net_field(s, "ip"))
            .map(str::to_string),
    };
    let mut moves = vec![FieldMove {
        field: "hostname".into(),
        from: name_of(dst_kind, dst),
        to: name_of(src_kind, src),
    }];
    for (key, spec) in src.iter().filter(|(k, _)| indexed(k, "net")) {
        let n = &key[3..];
        let Some(target) = dst.get(key) else {
            conflicts.push(format!("target has no {key} to take the source's {key}"));
            continue;
        };
        moves.push(FieldMove {
            field: format!("{key}.mac"),
            from: mac(target).map(str::to_string),
            to: mac(spec).map(str::to_string),
        });
        moves.push(FieldMove {
            field: format!("{key}.ip"),
            from: address(dst_kind, dst, n),
            to: address(src_kind, src, n),
        });
    }
    moves
}

pub fn backup_job_moves(
    jobs: &[BackupJob],
    source: &GuestRow,
    target: &GuestRow,
) -> Vec<BackupJobMove> {
    jobs.iter()
        .filter_map(|j| {
            let (s, t) = (selects(j, source), selects(j, target));
            let action = match (s, t, &j.selection) {
                (false, _, _) => return None,
                (true, true, _) => "already covers the target",
                (true, false, Some(Selection::Vmids { .. })) => {
                    "add the target vmid; drop the source at cutover"
                }
                (true, false, Some(Selection::All { .. })) => {
                    "remove the target from the exclude list"
                }
                (true, false, _) => "put the target in the job's pool",
            };
            Some(BackupJobMove {
                id: j.id.clone(),
                covers_source: s,
                covers_target: t,
                action: action.into(),
            })
        })
        .collect()
}

fn firewall(endpoint: &str, node: &str, kind: GuestKind, vmid: u64, what: &str) -> Result<Value> {
    crate::api_path::get(
        endpoint,
        &format!("nodes/{node}/{}/{vmid}/firewall/{what}", kind.as_str()),
    )
}

fn ipset_names(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s.get("name").and_then(Value::as_str).map(str::to_string))
        .collect()
}

fn rule_count(v: &Value) -> usize {
    v.as_array().map_or(0, Vec::len)
}

struct Read {
    node: String,
    kind: GuestKind,
    cfg: BTreeMap<String, String>,
    guest: MigrationGuest,
}

fn read(endpoint: &str, cluster: Option<&str>, located: &[Located], vmid: u64) -> Result<Read> {
    let (node, kind, _, fallback) = located
        .iter()
        .find(|(_, _, id, _)| *id == vmid)
        .ok_or_else(|| anyhow!("guest {vmid} not found on {endpoint}"))?
        .clone();
    let raw: Value = plugin_toolkit::api::call(
        config_op(kind, "get"),
        endpoint,
        json!({ "node": node, "vmid": vmid }),
    )
    .map_err(|e| e.context(format!("{} {vmid} config", kind.as_str())))?;
    let cfg = string_map(&raw);
    let guest = MigrationGuest {
        node: node.clone(),
        kind: kind_tag(kind).into(),
        vmid,
        name: name_of(kind, &cfg).or(fallback).unwrap_or_default(),
        unit_id: unit_id(cluster, endpoint, kind, vmid),
        system_id: cfg.get("description").and_then(|d| system_id(d)),
        tags: cfg.get("tags").map(|t| parse_tags(t)).unwrap_or_default(),
    };
    Ok(Read {
        node,
        kind,
        cfg,
        guest,
    })
}

fn row(r: &Read) -> GuestRow {
    GuestRow {
        vmid: r.guest.vmid,
        kind: r.kind.as_str().into(),
        node: r.node.clone(),
        name: Some(r.guest.name.clone()),
        running: false,
        template: false,
        pool: None,
    }
}

pub fn plan(endpoint: &str, source_vmid: u64, target_vmid: u64) -> Result<GuestMigrationPlan> {
    if source_vmid == target_vmid {
        bail!("source and target are the same guest ({source_vmid})");
    }
    let located = guests(endpoint, None)?;
    let cluster = crate::cluster::fetch_cluster_status(endpoint)
        .ok()
        .and_then(|s| s.name);
    let src = read(endpoint, cluster.as_deref(), &located, source_vmid)?;
    let dst = read(endpoint, cluster.as_deref(), &located, target_vmid)?;

    for (side, r) in [("source", &src), ("target", &dst)] {
        if is_gateway(&r.guest.name, &r.guest.tags) {
            bail!(
                "{side} {} ('{}') is a gateway; a migration would take the network down",
                r.guest.vmid,
                r.guest.name
            );
        }
    }

    let mut conflicts = Vec::new();
    let identity = identity_moves(src.kind, &src.cfg, dst.kind, &dst.cfg, &mut conflicts);
    if src.kind != dst.kind {
        conflicts.push(format!(
            "kind changes {} -> {}: net*, disks and cloud-init keys do not translate one to one",
            src.guest.kind, dst.guest.kind
        ));
    }
    for (side, g) in [("source", &src.guest), ("target", &dst.guest)] {
        if g.system_id.is_none() {
            conflicts.push(format!(
                "{side} {} has no orca system id; identity takeover can't be verified",
                g.vmid
            ));
        }
    }
    if let (Some(s), Some(t)) = (&src.guest.system_id, &dst.guest.system_id)
        && s != t
    {
        conflicts.push(format!(
            "target already carries orca system id {t}, source has {s}"
        ));
    }
    let carry = carry_over(&src.cfg);
    if src.node != dst.node {
        for (k, v) in carry
            .copy
            .iter()
            .filter(|(k, v)| indexed(k, "mp") && v.starts_with('/'))
        {
            conflicts.push(format!(
                "{k} binds host path {} on {}; the target is on {}",
                v.split(',').next().unwrap_or_default(),
                src.node,
                dst.node
            ));
        }
    }
    for k in carry
        .copy
        .keys()
        .filter(|k| indexed(k, "mp") && dst.cfg.contains_key(*k))
    {
        conflicts.push(format!("target already has {k}"));
    }

    let jobs = fetch_jobs(endpoint)?;
    let backup_jobs = backup_job_moves(&jobs, &row(&src), &row(&dst));

    let source_rules = firewall(endpoint, &src.node, src.kind, source_vmid, "rules")?;
    let target_rules = firewall(endpoint, &dst.node, dst.kind, target_vmid, "rules")?;
    let fw = FirewallMove {
        source_options: firewall(endpoint, &src.node, src.kind, source_vmid, "options")?,
        source_rules: rule_count(&source_rules),
        source_ipsets: ipset_names(&firewall(
            endpoint,
            &src.node,
            src.kind,
            source_vmid,
            "ipset",
        )?),
        target_rules: rule_count(&target_rules),
        target_ipsets: ipset_names(&firewall(
            endpoint,
            &dst.node,
            dst.kind,
            target_vmid,
            "ipset",
        )?),
    };
    if fw.target_rules > 0 && fw.source_rules > 0 {
        conflicts.push(format!(
            "target already has {} firewall rules; the source's {} would replace them",
            fw.target_rules, fw.source_rules
        ));
    }
    for name in fw
        .source_ipsets
        .iter()
        .filter(|n| fw.target_ipsets.contains(n))
    {
        conflicts.push(format!("ipset '{name}' exists on both guests"));
    }

    Ok(GuestMigrationPlan {
        dry_run: true,
        endpoint: endpoint.to_string(),
        tags: merge_tags(&dst.guest.tags, &src.guest.tags),
        source: src.guest,
        target: dst.guest,
        identity,
        carry,
        backup_jobs,
        firewall: fw,
        conflicts,
    })
}

/// Plan moving a guest's identity and config onto a replacement guest:
/// hostname, each `netN` MAC and IP, tags, the orca system id, the config
/// keys and mounts that carry over, the vzdump jobs and firewall rules to
/// follow it, and every conflict. Gateway guests (OPNsense, pfSense) are
/// refused. Reads only; nothing changes. Admin only: the plan carries MACs,
/// IPs and host paths.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.migration.plan",
    execute_gated = false,
    role = "admin",
    reaches = [
        "proxmox.get_resources_cluster_resources",
        "proxmox.get_vm_config_nodes_node_qemu_vmid_config",
        "proxmox.get_vm_config_nodes_node_lxc_vmid_config",
        "proxmox.get_get_status_cluster_status",
        "proxmox.get_index_cluster_backup",
        "proxmox.get_get_options_nodes_node_lxc_vmid_firewall_options",
        "proxmox.get_get_rules_nodes_node_lxc_vmid_firewall_rules",
        "proxmox.get_ipset_index_nodes_node_lxc_vmid_firewall_ipset",
        "proxmox.get_get_options_nodes_node_qemu_vmid_firewall_options",
        "proxmox.get_get_rules_nodes_node_qemu_vmid_firewall_rules",
        "proxmox.get_ipset_index_nodes_node_qemu_vmid_firewall_ipset"
    ]
)]
async fn proxmox_guest_migration_plan(
    args: GuestMigrationPlanArgs,
    ctx: &ToolCtx,
) -> Result<GuestMigrationPlan> {
    crate::execute::require_admin("proxmox.guest.migration.plan", ctx.caller().as_ref())?;
    plan(&args.endpoint, args.source_vmid, args.target_vmid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_purpose_skips_identity_and_routes_volumes_to_a_move() {
        let old: BTreeMap<String, String> = [
            ("hostname", "guest-c"),
            ("cores", "4"),
            ("memory", "8192"),
            (
                "net0",
                "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=dhcp",
            ),
            ("mp0", "/mnt/media,mp=/media"),
            ("mp1", "local-lvm:vm-102-disk-1,mp=/data,size=50G"),
            ("rootfs", "local-lvm:vm-102-disk-0,size=8G"),
            ("unused0", "local-lvm:vm-102-disk-2"),
            ("tags", "media"),
            ("digest", "abc"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let p = carry_over(&old);
        assert_eq!(p.copy["net0"], "name=eth0,bridge=vmbr0,ip=dhcp");
        assert_eq!(p.copy["mp0"], "/mnt/media,mp=/media");
        assert_eq!(p.copy["cores"], "4");
        assert!(p.copy.contains_key("tags"));
        assert_eq!(p.volumes_to_move, vec!["mp1".to_string()]);
        assert_eq!(p.skipped, vec!["digest", "hostname", "rootfs", "unused0"]);
    }

    #[test]
    fn qemu_disks_stay_and_netmodel_mac_is_dropped() {
        assert!(keep_own("scsi0") && keep_own("efidisk0") && !keep_own("scsihw"));
        assert_eq!(
            without_mac("virtio=BC:24:11:00:00:01,bridge=vmbr0"),
            "virtio,bridge=vmbr0"
        );
    }

    use crate::test_support::record_api_calls;

    const SYS: &str = "0192f3a4-5b6c-7d8e-9f01-23456789abcd";

    fn routes(method: &str, path: &str) -> String {
        match (method, path) {
            (_, "/cluster/resources") => r#"[
                {"type":"qemu","node":"node-a","vmid":9001,"name":"guest-a"},
                {"type":"lxc","node":"node-a","vmid":9002,"name":"guest-b"},
                {"type":"lxc","node":"node-b","vmid":9003,"name":"elsewhere"},
                {"type":"qemu","node":"node-a","vmid":9004,"name":"gw-test"}
            ]"#
            .into(),
            (_, "/cluster/status") => r#"[{"type":"cluster","name":"lab","id":"cluster"}]"#.into(),
            ("GET", "/nodes/node-a/qemu/9001/config") => format!(
                r#"{{"name":"guest-a","cores":4,"memory":8192,"onboot":1,"startup":"order=2",
                "tags":"media;orca-managed",
                "description":"<!-- orca-managed -->\nSystem id: `{SYS}`\n<!-- /orca-managed -->",
                "net0":"virtio=BC:24:11:AA:BB:CC,bridge=vmbr0",
                "ipconfig0":"ip=10.0.0.5/24,gw=10.0.0.1",
                "scsi0":"local-lvm:vm-9001-disk-0,size=64G",
                "smbios1":"uuid=1234","digest":"d1"}}"#
            ),
            ("GET", "/nodes/node-a/lxc/9002/config") => r#"{"hostname":"guest-b","cores":2,
                "tags":"lxc","rootfs":"local-lvm:vm-9002-disk-0,size=8G",
                "net0":"name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:00:01,ip=dhcp,type=veth",
                "mp0":"/mnt/old,mp=/old"}"#
                .into(),
            ("GET", "/nodes/node-b/lxc/9003/config") => r#"{"hostname":"elsewhere"}"#.into(),
            ("GET", "/nodes/node-a/qemu/9004/config") => r#"{"name":"gw-test","tags":"gateway","net0":"virtio=BC:24:11:FF:FF:FF,bridge=vmbr0"}"#.into(),
            ("GET", "/cluster/backup") => r#"[
                {"id":"nightly","type":"vzdump","enabled":1,"schedule":"03:00","storage":"pbs","vmid":"9001"},
                {"id":"weekly","type":"vzdump","enabled":1,"schedule":"sun 01:00","storage":"pbs","all":1},
                {"id":"other","type":"vzdump","enabled":1,"schedule":"02:00","storage":"pbs","vmid":"200"}
            ]"#
            .into(),
            ("GET", "/nodes/node-a/qemu/9001/firewall/rules") => r#"[{"pos":0,"type":"in","action":"ACCEPT"},{"pos":1,"type":"in","action":"DROP"}]"#.into(),
            ("GET", "/nodes/node-a/qemu/9001/firewall/options") => r#"{"enable":1,"policy_in":"DROP"}"#.into(),
            ("GET", "/nodes/node-a/qemu/9001/firewall/ipset") => r#"[{"name":"trusted"}]"#.into(),
            ("GET", "/nodes/node-a/lxc/9002/firewall/rules") => r#"[{"pos":0,"type":"in","action":"ACCEPT"}]"#.into(),
            ("GET", "/nodes/node-a/lxc/9002/firewall/ipset") => r#"[{"name":"trusted"}]"#.into(),
            (_, p) if p.contains("/firewall/") => "[]".into(),
            _ => "null".into(),
        }
    }

    #[test]
    fn plans_identity_tags_jobs_and_firewall_and_only_reads() {
        let (out, calls) = record_api_calls(routes, || plan("pve", 9001, 9002));
        let p = out.unwrap();
        assert!(calls.iter().all(|(m, ..)| m == "GET"), "{calls:?}");
        assert!(p.dry_run);
        assert_eq!(p.source.system_id.as_deref(), Some(SYS));
        assert_eq!(p.source.unit_id, "cluster:lab/vm/9001");
        assert_eq!(p.target.kind, "lxc");
        let field = |f: &str| p.identity.iter().find(|m| m.field == f).cloned().unwrap();
        assert_eq!(field("hostname").to.as_deref(), Some("guest-a"));
        assert_eq!(field("hostname").from.as_deref(), Some("guest-b"));
        assert_eq!(field("net0.mac").to.as_deref(), Some("BC:24:11:AA:BB:CC"));
        assert_eq!(field("net0.mac").from.as_deref(), Some("BC:24:11:00:00:01"));
        assert_eq!(field("net0.ip").to.as_deref(), Some("10.0.0.5/24"));
        assert_eq!(field("net0.ip").from.as_deref(), Some("dhcp"));
        assert_eq!(p.tags, vec!["lxc", "media", "orca-managed"]);
        assert_eq!(p.carry.copy["startup"], "order=2");
        assert!(p.carry.skipped.contains(&"scsi0".to_string()));
        let jobs: Vec<_> = p
            .backup_jobs
            .iter()
            .map(|j| (j.id.as_str(), j.covers_target))
            .collect();
        assert_eq!(jobs, vec![("nightly", false), ("weekly", true)]);
        assert_eq!((p.firewall.source_rules, p.firewall.target_rules), (2, 1));
        assert_eq!(p.firewall.source_options["policy_in"], "DROP");
        let c = p.conflicts.join("\n");
        assert!(c.contains("kind changes vm -> lxc"), "{c}");
        assert!(c.contains("1 firewall rules"), "{c}");
        assert!(c.contains("ipset 'trusted'"), "{c}");
        assert!(
            c.contains("target 9002 has no orca system id; identity takeover can't be verified"),
            "{c}"
        );
        assert!(!c.contains("source 9001 has no orca system id"), "{c}");
    }

    #[test]
    fn a_missing_system_id_on_either_side_is_a_conflict() {
        let (out, _) = record_api_calls(routes, || plan("pve", 9002, 9003));
        let c = out.unwrap().conflicts.join("\n");
        assert!(c.contains("source 9002 has no orca system id"), "{c}");
        assert!(c.contains("target 9003 has no orca system id"), "{c}");
    }

    #[test]
    fn a_gateway_on_either_side_is_refused() {
        let (out, _) = record_api_calls(routes, || plan("pve", 9002, 9004));
        let e = out.unwrap_err().to_string();
        assert!(e.contains("target 9004 ('gw-test') is a gateway"), "{e}");
        assert!(is_gateway("edge", &["opnsense".into()]));
        assert!(is_gateway("OPNsense-fw", &[]));
        assert!(!is_gateway("gatewayless-docs", &[]));
    }

    #[test]
    fn host_path_mounts_conflict_across_nodes_and_missing_nics_are_flagged() {
        let (out, _) = record_api_calls(
            |m, p| {
                match p {
                "/nodes/node-a/lxc/9002/config" => r#"{"hostname":"a","mp0":"/mnt/media,mp=/media","net1":"name=eth1,bridge=vmbr1"}"#.into(),
                _ => routes(m, p),
            }
            },
            || plan("pve", 9002, 9003),
        );
        let c = out.unwrap().conflicts.join("\n");
        assert!(
            c.contains("mp0 binds host path /mnt/media on node-a; the target is on node-b"),
            "{c}"
        );
        assert!(c.contains("target has no net1"), "{c}");
    }

    #[test]
    fn same_guest_and_unknown_guest_are_errors() {
        assert!(
            plan("pve", 5, 5)
                .unwrap_err()
                .to_string()
                .contains("same guest")
        );
        let (out, _) = record_api_calls(routes, || plan("pve", 9001, 999));
        assert!(out.unwrap_err().to_string().contains("guest 999 not found"));
    }

    #[test]
    fn system_id_is_read_only_from_the_orca_block() {
        let d = format!("note {SYS}\n<!-- orca-managed -->\nno id\n<!-- /orca-managed -->");
        assert_eq!(system_id(&d), None);
        let d = format!(
            "<!-- orca-managed -->\nid {}\n<!-- /orca-managed -->",
            SYS.to_uppercase()
        );
        assert_eq!(system_id(&d).as_deref(), Some(SYS));
    }

    #[test]
    fn the_plan_tool_is_admin_and_not_execute_gated() {
        let manifest: Vec<Value> =
            plugin_toolkit::serde_json::from_str(&plugin_toolkit::dispatch::tool_manifest_json())
                .unwrap();
        let t = manifest
            .iter()
            .find(|t| t["name"] == "proxmox.guest.migration.plan")
            .expect("registered");
        assert_eq!(t["role"], "admin");
        assert_eq!(t["tool_callable"], false);
    }
}
