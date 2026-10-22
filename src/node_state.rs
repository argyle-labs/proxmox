use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use plugin_toolkit::serde_json::{Value, json};

const HOST_SKIPPED: &str = "host files (/etc/ssh, /etc/cron.d, /etc/fstab, /usr/local/{bin,sbin}, \
     /root/.ssh, /var/spool/cron/crontabs): unsupported: needs in-guest orca member\n";

const SUMS: &str = "SHA256SUMS";
const API_DIR: &str = "api";
const SKIPPED: &str = "SKIPPED";
const CLUSTER_PREFIX: &str = "cluster:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    Core,
    Filtered,
    Plain,
}

pub(crate) struct Read {
    pub(crate) path: &'static str,
    pub(crate) file: &'static str,
    pub(crate) rule: Rule,
    pub(crate) scrub: bool,
}

const fn read(path: &'static str, file: &'static str, rule: Rule, scrub: bool) -> Read {
    Read {
        path,
        file,
        rule,
        scrub,
    }
}

pub const REACHES: [&str; 1] = ["proxmox.get_server_index_cluster_metrics_server"];

pub(crate) const NODE_READS: &[Read] = &[
    read("nodes/{node}/config", "node-config.json", Rule::Core, false),
    read("nodes/{node}/network", "network.json", Rule::Core, false),
    read("nodes/{node}/dns", "dns.json", Rule::Plain, false),
    read("nodes/{node}/hosts", "hosts.json", Rule::Plain, false),
    read("nodes/{node}/time", "time.json", Rule::Plain, false),
    read(
        "nodes/{node}/apt/repositories",
        "apt-repositories.json",
        Rule::Plain,
        false,
    ),
    read(
        "nodes/{node}/firewall/options",
        "node-firewall-options.json",
        Rule::Plain,
        false,
    ),
    read(
        "nodes/{node}/firewall/rules",
        "node-firewall-rules.json",
        Rule::Plain,
        false,
    ),
    read(
        "nodes/{node}/certificates/info",
        "certificates.json",
        Rule::Plain,
        false,
    ),
    read("nodes/{node}/disks/list", "disks.json", Rule::Plain, false),
];

pub(crate) const CLUSTER_READS: &[Read] = &[
    read(
        "cluster/config/nodes",
        "cluster-nodes.json",
        Rule::Core,
        false,
    ),
    read("storage", "storage.json", Rule::Core, false),
    read(
        "cluster/config/totem",
        "cluster-totem.json",
        Rule::Plain,
        false,
    ),
    read(
        "cluster/options",
        "cluster-options.json",
        Rule::Plain,
        false,
    ),
    read("pools", "pools.json", Rule::Filtered, false),
    read("cluster/backup", "backup-jobs.json", Rule::Plain, false),
    read(
        "cluster/replication",
        "replication.json",
        Rule::Filtered,
        false,
    ),
    read(
        "cluster/ha/resources",
        "ha-resources.json",
        Rule::Plain,
        false,
    ),
    read("cluster/ha/groups", "ha-groups.json", Rule::Plain, false),
    read(
        "cluster/firewall/options",
        "cluster-firewall-options.json",
        Rule::Plain,
        false,
    ),
    read(
        "cluster/firewall/rules",
        "cluster-firewall-rules.json",
        Rule::Plain,
        false,
    ),
    read(
        "cluster/firewall/groups",
        "cluster-firewall-groups.json",
        Rule::Plain,
        false,
    ),
    read(
        "cluster/firewall/aliases",
        "cluster-firewall-aliases.json",
        Rule::Plain,
        false,
    ),
    read(
        "cluster/firewall/ipset",
        "cluster-firewall-ipset.json",
        Rule::Plain,
        false,
    ),
    read("cluster/sdn/zones", "sdn-zones.json", Rule::Filtered, false),
    read("cluster/sdn/vnets", "sdn-vnets.json", Rule::Filtered, false),
    read(
        "cluster/mapping/pci",
        "mapping-pci.json",
        Rule::Filtered,
        false,
    ),
    read(
        "cluster/mapping/usb",
        "mapping-usb.json",
        Rule::Filtered,
        false,
    ),
    read(
        "cluster/metrics/server",
        "metrics-servers.json",
        Rule::Plain,
        true,
    ),
    read(
        "cluster/notifications/endpoints",
        "notification-endpoints.json",
        Rule::Filtered,
        true,
    ),
    read(
        "cluster/notifications/matchers",
        "notification-matchers.json",
        Rule::Filtered,
        true,
    ),
    read("access/users", "users.json", Rule::Filtered, false),
    read("access/groups", "groups.json", Rule::Filtered, false),
    read("access/roles", "roles.json", Rule::Plain, false),
    read("access/domains", "domains.json", Rule::Plain, false),
];

const MEMBERSHIP: &str = "cluster/config/nodes";
const STANDALONE_ABSENT: &[&str] = &["cluster/config/totem"];
const NEVER_EMPTY: &[&str] = &["access/users"];

pub(crate) const NOT_CAPTURABLE: &[(&str, &str)] = &[(
    "access/acl",
    "not capturable by token: PVE lists ACLs only with Permissions.Modify, which the runtime role does not hold",
)];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Scope {
    Node(String),
    Cluster,
}

pub(crate) trait ApiRead {
    async fn get(&self, path: &str) -> Result<Value>;
}

struct Endpoint(String);

impl ApiRead for Endpoint {
    async fn get(&self, path: &str) -> Result<Value> {
        crate::api_path::get(&self.0, path)
    }
}

pub async fn instances() -> Vec<String> {
    let found =
        crate::tools::for_each_enabled_endpoint("node_state.instances", |_, ep| async move {
            let status = crate::api_path::get(&ep.name, "cluster/status")
                .inspect_err(|e| {
                    tracing::warn!(endpoint = %ep.name, error = %e, "pve-node-state: cluster/status failed; skipping its cluster slot")
                })
                .ok();
            let nodes = crate::api_path::get(&ep.name, "nodes")?;
            Ok(slots(&ep.name, status.as_ref(), &nodes))
        })
        .await;
    found
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn slots(endpoint: &str, status: Option<&Value>, nodes: &Value) -> Vec<String> {
    let mut out: Vec<String> = status
        .map(|s| format!("{CLUSTER_PREFIX}{}", cluster_key(endpoint, s)))
        .into_iter()
        .collect();
    out.extend(node_names(nodes));
    out
}

fn cluster_name(status: &Value) -> Option<String> {
    status
        .as_array()?
        .iter()
        .find(|e| e.get("type").and_then(Value::as_str) == Some("cluster"))?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

fn cluster_key(endpoint: &str, status: &Value) -> String {
    cluster_name(status).unwrap_or_else(|| format!("endpoint/{endpoint}"))
}

fn standalone_proof(status: &Value, nodes: &Value) -> Result<(), String> {
    let entries = status
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("cluster/status is empty")?;
    if cluster_name(status).is_some() {
        return Err("cluster/status reports a cluster".to_string());
    }
    let status_nodes: Vec<&str> = entries
        .iter()
        .filter(|e| e.get("type").and_then(Value::as_str) == Some("node"))
        .filter_map(|e| e.get("name")?.as_str())
        .collect();
    let listed = node_names(nodes);
    match (status_nodes.as_slice(), listed.as_slice()) {
        ([a], [b]) if a == b => Ok(()),
        _ => Err(format!(
            "not provably standalone: cluster/status nodes {status_nodes:?}, /nodes {listed:?}"
        )),
    }
}

pub(crate) fn pick_cluster_slot(
    key: &str,
    candidates: Vec<(String, Result<Value, String>)>,
) -> Result<String> {
    let mut rejected = Vec::new();
    for (name, status) in candidates {
        match status {
            Ok(s) if cluster_key(&name, &s) == key => return Ok(name),
            Ok(s) => rejected.push(format!("{name}: serves '{}'", cluster_key(&name, &s))),
            Err(e) => rejected.push(format!("{name}: {e}")),
        }
    }
    if rejected.is_empty() {
        rejected.push("no enabled endpoints".to_string());
    }
    bail!(
        "pve-node-state: no enabled endpoint serves cluster slot '{key}' ({})",
        rejected.join("; ")
    )
}

fn resolve_cluster_slot(key: &str) -> Result<String> {
    let candidates = crate::tools::enabled_endpoint_names()
        .into_iter()
        .map(|name| {
            let status = crate::api_path::get(&name, "cluster/status")
                .map_err(|e| scrub_text(&format!("cluster/status: {e:#}")));
            (name, status)
        })
        .collect();
    pick_cluster_slot(key, candidates)
}

fn node_names(nodes: &Value) -> Vec<String> {
    nodes
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| n.get("node")?.as_str().map(str::to_string))
        .collect()
}

pub async fn backup(dir: &str, instance: &str) -> Result<Value> {
    if let Some(key) = instance.strip_prefix(CLUSTER_PREFIX) {
        let api = Endpoint(resolve_cluster_slot(key)?);
        return capture(&api, &Scope::Cluster, Path::new(dir)).await;
    }
    let api = Endpoint(crate::backup::resolve_endpoint_for_node(instance).await?);
    capture(&api, &Scope::Node(instance.to_string()), Path::new(dir)).await
}

pub(crate) async fn capture<A: ApiRead>(api: &A, scope: &Scope, dest: &Path) -> Result<Value> {
    let dir = dest.join(API_DIR);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let (label, reads) = match scope {
        Scope::Node(n) => (n.clone(), NODE_READS),
        Scope::Cluster => ("cluster".to_string(), CLUSTER_READS),
    };
    let mut warnings = Vec::new();
    let mut skipped = String::new();
    let mut captured = 0;
    let mut standalone = false;
    for r in reads {
        let path = match scope {
            Scope::Node(n) => r.path.replace("{node}", n),
            Scope::Cluster => r.path.to_string(),
        };
        let mut file = r.file;
        let mut data = match api.get(&path).await {
            Ok(d) => d,
            Err(e) if path == MEMBERSHIP => {
                let first = scrub_text(&format!("{path}: {e:#}"));
                let status = api.get("cluster/status").await.map_err(|e2| {
                    anyhow!(
                        "pve-node-state: core read failed: {first}; cluster/status: {}",
                        scrub_text(&format!("{e2:#}"))
                    )
                })?;
                ensure!(
                    cluster_name(&status).is_none(),
                    "pve-node-state: core read failed: {first}"
                );
                let d = api.get("nodes").await.map_err(|e2| {
                    anyhow!(
                        "pve-node-state: core read failed: {first}; standalone fallback {}",
                        scrub_text(&format!("nodes: {e2:#}"))
                    )
                })?;
                standalone_proof(&status, &d)
                    .map_err(|why| anyhow!("pve-node-state: core read failed: {first}; {why}"))?;
                standalone = true;
                skipped.push_str(&format!(
                    "{path}: standalone node (cluster/status lists only this node); nodes stands in as membership\n"
                ));
                file = "nodes.json";
                d
            }
            Err(_) if standalone && STANDALONE_ABSENT.contains(&path.as_str()) => {
                skipped.push_str(&format!("{path}: absent on a standalone node\n"));
                continue;
            }
            Err(e) => {
                let msg = scrub_text(&format!("{path}: {e:#}"));
                ensure!(
                    r.rule != Rule::Core,
                    "pve-node-state: core read failed: {msg}"
                );
                skipped.push_str(&format!("{msg}\n"));
                warnings.push(msg);
                continue;
            }
        };
        if NEVER_EMPTY.contains(&path.as_str()) && data.as_array().is_some_and(Vec::is_empty) {
            let msg = format!(
                "{path}: empty, which PVE never returns legitimately; the token cannot see users"
            );
            skipped.push_str(&format!("{msg}\n"));
            warnings.push(msg);
            continue;
        }
        if r.rule == Rule::Filtered && data.as_array().is_some_and(Vec::is_empty) {
            skipped.push_str(&format!(
                "{path}: empty list; PVE filters it by token privileges, so none configured and none visible look alike\n"
            ));
            continue;
        }
        if r.scrub {
            scrub_json(&mut data);
        }
        std::fs::write(
            dir.join(file),
            plugin_toolkit::serde_json::to_vec_pretty(&data)?,
        )
        .with_context(|| format!("write {file}"))?;
        captured += 1;
    }
    match scope {
        Scope::Cluster => {
            for (path, why) in NOT_CAPTURABLE {
                skipped.push_str(&format!("{path}: {why}\n"));
            }
        }
        Scope::Node(_) => skipped.push_str(HOST_SKIPPED),
    }
    if !skipped.is_empty() {
        std::fs::write(dir.join(SKIPPED), &skipped).context("write SKIPPED")?;
    }
    write_sums(dest)?;
    let (files, digest) = verify_sums(dest)?;
    let prefix = if warnings.is_empty() {
        String::new()
    } else {
        format!("PARTIAL: {} warnings; ", warnings.len())
    };
    Ok(json!({
        "checksum": format!("sha256:{digest}"),
        "partial": !warnings.is_empty(),
        "warnings": warnings,
        "note": format!(
            "{prefix}{label}: {captured} API read(s); {} SKIPPED line(s); \
             {files} file(s) in SHA256SUMS",
            skipped.lines().count()
        ),
    }))
}

pub fn restore(dir: &str) -> Result<Value> {
    let (files, _) = verify_sums(Path::new(dir))?;
    bail!(
        "pve-node-state is capture-only: {files} file(s) verified against SHA256SUMS in {dir}; \
         apply the captured config through the PVE API by hand"
    )
}

pub(crate) fn scrub_text(s: &str) -> String {
    let scrubbed = plugin_toolkit::scrub::scrub_line(s);
    scrubbed
        .split(' ')
        .map(|tok| {
            let core = tok.trim_matches(|c: char| "\"'(),;:<>[]".contains(c));
            match scrub_url(core) {
                Some(clean) => tok.replace(core, &clean),
                None => tok.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn scrub_url(s: &str) -> Option<String> {
    let mut u = url::Url::parse(s).ok().filter(url::Url::has_host)?;
    if u.username().is_empty() && u.password().is_none() && u.query().is_none() {
        return None;
    }
    u.set_username("").ok();
    u.set_password(None).ok();
    if u.query().is_some() {
        u.set_query(Some("***"));
    }
    Some(u.into())
}

pub(crate) fn scrub_json(v: &mut Value) {
    plugin_toolkit::scrub::redact_json_in_place(v);
    scrub_strings(v, false);
}

fn scrub_strings(v: &mut Value, in_header: bool) {
    match v {
        Value::String(s) => {
            if in_header {
                *s = s
                    .split(',')
                    .map(|part| {
                        if part.trim_start().starts_with("value=") {
                            "value=***"
                        } else {
                            part
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",");
            }
            if let Some(clean) = scrub_url(s) {
                *s = clean;
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| scrub_strings(x, in_header)),
        Value::Object(o) => o.iter_mut().for_each(|(k, x)| {
            scrub_strings(x, in_header || k.to_ascii_lowercase().contains("header"))
        }),
        _ => {}
    }
}

fn payload_files(dir: &Path) -> Result<BTreeMap<String, PathBuf>> {
    fn walk(dir: &Path, at: &Path, out: &mut BTreeMap<String, PathBuf>) -> Result<()> {
        for e in std::fs::read_dir(at).with_context(|| format!("list {}", at.display()))? {
            let p = e?.path();
            let m = std::fs::symlink_metadata(&p)?;
            if m.is_dir() {
                walk(dir, &p, out)?;
            } else if m.is_file() {
                let rel = p.strip_prefix(dir).expect("walk stays under dir");
                out.insert(rel.to_string_lossy().into_owned(), p);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out)?;
    out.remove(SUMS);
    Ok(out)
}

fn write_sums(dir: &Path) -> Result<()> {
    let mut sums = String::new();
    for (rel, path) in payload_files(dir)? {
        let h = plugin_toolkit::hash::sha256_file(&path)?;
        sums.push_str(&format!("{h}  {rel}\n"));
    }
    std::fs::write(dir.join(SUMS), sums).context("write SHA256SUMS")
}

pub fn verify_sums(dir: &Path) -> Result<(usize, String)> {
    let raw = std::fs::read(dir.join(SUMS))
        .with_context(|| format!("read {}", dir.join(SUMS).display()))?;
    let text = std::str::from_utf8(&raw).context("SHA256SUMS is not utf-8")?;
    let mut listed = BTreeMap::new();
    for line in text.lines() {
        let (h, rel) = line
            .split_once("  ")
            .ok_or_else(|| anyhow!("malformed SHA256SUMS line '{line}'"))?;
        listed.insert(rel.to_string(), h.to_string());
    }
    let present = payload_files(dir)?;
    for rel in present.keys() {
        ensure!(listed.contains_key(rel), "{rel} is not in SHA256SUMS");
    }
    for (rel, want) in &listed {
        let path = present
            .get(rel)
            .ok_or_else(|| anyhow!("{rel} is in SHA256SUMS but missing"))?;
        let got = plugin_toolkit::hash::sha256_file(path)?;
        ensure!(&got == want, "{rel}: sha256 {got} != {want}");
    }
    Ok((listed.len(), plugin_toolkit::hash::sha256_hex(&raw)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_read_resolves_to_a_surface_op() {
        for r in NODE_READS.iter().chain(CLUSTER_READS) {
            let path = r.path.replace("{node}", "thor");
            crate::api_path::resolve("GET", &path).unwrap_or_else(|e| panic!("{e:#}"));
        }
        let (op, _) = crate::api_path::resolve("GET", "cluster/metrics/server").unwrap();
        assert_eq!(op, REACHES[0]);
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "proxmox-nodestate-{name}-{}-{}",
            std::process::id(),
            plugin_toolkit::time::now().unix_seconds()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    struct FakeApi {
        refuse: Vec<&'static str>,
        empty: Vec<&'static str>,
        clustered: bool,
        nodes: Vec<&'static str>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    fn fake(refuse: Vec<&'static str>, empty: Vec<&'static str>) -> FakeApi {
        FakeApi {
            refuse,
            empty,
            clustered: true,
            nodes: vec!["n1"],
            calls: Default::default(),
        }
    }

    impl ApiRead for FakeApi {
        async fn get(&self, path: &str) -> Result<Value> {
            self.calls.lock().unwrap().push(path.to_string());
            if self.refuse.iter().any(|r| path.starts_with(r)) {
                bail!("HTTP 403 GET https://u:pw@pve:8006/x?token=abc: permission check failed");
            }
            if self.empty.iter().any(|r| path.starts_with(r)) {
                return Ok(json!([]));
            }
            if path == "nodes" {
                return Ok(json!(
                    self.nodes
                        .iter()
                        .map(|n| json!({ "node": n }))
                        .collect::<Vec<_>>()
                ));
            }
            if path == "cluster/status" {
                return Ok(if self.clustered {
                    json!([{"type": "cluster", "name": "lab"}, {"type": "node", "name": "n1"}])
                } else {
                    json!([{"type": "node", "name": "n1"}])
                });
            }
            Ok(json!([{ "path": path }]))
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn node() -> Scope {
        Scope::Node("n1".to_string())
    }

    #[test]
    fn node_slot_reads_only_node_scoped_paths() {
        let dest = scratch("node");
        let api = fake(vec![], vec![]);
        let out = rt().block_on(capture(&api, &node(), &dest)).unwrap();
        let calls = api.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), NODE_READS.len());
        assert!(
            calls.iter().all(|c| c.starts_with("nodes/n1/")),
            "{calls:?}"
        );
        assert_eq!(out["partial"], false);
        assert_eq!(out["warnings"], json!([]));
        assert_eq!(verify_sums(&dest).unwrap().0, NODE_READS.len() + 1);
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn cluster_slot_reads_cluster_paths_once_and_skips_acl() {
        let dest = scratch("cluster");
        let api = fake(vec![], vec![]);
        rt().block_on(capture(&api, &Scope::Cluster, &dest))
            .unwrap();
        let calls = api.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), CLUSTER_READS.len());
        assert!(
            !calls
                .iter()
                .any(|c| c.starts_with("nodes/") || c == "access/acl")
        );
        assert!(!dest.join("api/acl.json").exists());
        let skipped = std::fs::read_to_string(dest.join("api").join(SKIPPED)).unwrap();
        assert!(
            skipped.contains("access/acl: not capturable by token"),
            "{skipped}"
        );
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn empty_filtered_lists_land_in_skipped_without_a_file() {
        let dest = scratch("empty");
        let api = fake(
            vec![],
            vec![
                "cluster/notifications/endpoints",
                "cluster/replication",
                "cluster/ha/groups",
            ],
        );
        let out = rt()
            .block_on(capture(&api, &Scope::Cluster, &dest))
            .unwrap();
        let skipped = std::fs::read_to_string(dest.join("api").join(SKIPPED)).unwrap();
        assert!(
            skipped.contains("cluster/notifications/endpoints: empty list"),
            "{skipped}"
        );
        assert!(
            skipped.contains("cluster/replication: empty list"),
            "{skipped}"
        );
        assert!(!skipped.contains("cluster/ha/groups"), "{skipped}");
        assert!(!dest.join("api/notification-endpoints.json").exists());
        assert!(dest.join("api/ha-groups.json").exists());
        assert_eq!(out["partial"], false);
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn refused_reads_are_scrubbed_warnings_and_partial() {
        let dest = scratch("skip");
        let api = fake(vec!["nodes/n1/dns", "nodes/n1/time"], vec![]);
        let out = rt().block_on(capture(&api, &node(), &dest)).unwrap();
        let skipped = std::fs::read_to_string(dest.join("api").join(SKIPPED)).unwrap();
        assert_eq!(skipped.lines().count(), 3);
        assert!(
            !skipped.contains("pw@") && !skipped.contains("token=abc"),
            "{skipped}"
        );
        assert_eq!(out["partial"], true);
        assert_eq!(out["warnings"].as_array().unwrap().len(), 2);
        verify_sums(&dest).unwrap();
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn a_failed_core_read_fails_the_slot() {
        for (scope, core) in [(node(), "nodes/n1/network"), (Scope::Cluster, "storage")] {
            let dest = scratch("core");
            let api = fake(vec![core], vec![]);
            let err = rt().block_on(capture(&api, &scope, &dest)).unwrap_err();
            assert!(err.to_string().contains("core read failed"), "{err}");
            assert!(!dest.join(SUMS).exists());
            std::fs::remove_dir_all(&dest).unwrap();
        }
    }

    #[test]
    fn a_confirmed_standalone_node_falls_back_to_the_nodes_list() {
        let dest = scratch("standalone");
        let mut api = fake(vec!["cluster/config/nodes", "cluster/config/totem"], vec![]);
        api.clustered = false;
        let out = rt()
            .block_on(capture(&api, &Scope::Cluster, &dest))
            .unwrap();
        assert!(dest.join("api/nodes.json").exists());
        assert!(!dest.join("api/cluster-nodes.json").exists());
        let skipped = std::fs::read_to_string(dest.join("api").join(SKIPPED)).unwrap();
        assert!(skipped.contains("standalone node"), "{skipped}");
        assert!(
            skipped.contains("cluster/config/totem: absent on a standalone node"),
            "{skipped}"
        );
        assert_eq!(out["partial"], false);
        assert!(!out["note"].as_str().unwrap().starts_with("PARTIAL"));
        std::fs::remove_dir_all(&dest).unwrap();

        let dest = scratch("standalone-dead");
        let mut api = fake(vec!["cluster/config/nodes", "nodes"], vec![]);
        api.clustered = false;
        let err = rt()
            .block_on(capture(&api, &Scope::Cluster, &dest))
            .unwrap_err();
        assert!(err.to_string().contains("standalone fallback"), "{err}");
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn a_membership_error_on_a_cluster_stays_a_core_failure() {
        let dest = scratch("clustered-403");
        let api = fake(vec!["cluster/config/nodes"], vec![]);
        let err = rt()
            .block_on(capture(&api, &Scope::Cluster, &dest))
            .unwrap_err();
        assert!(err.to_string().contains("core read failed"), "{err}");
        assert!(!api.calls.lock().unwrap().contains(&"nodes".to_string()));
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn empty_users_is_partial_and_named_in_the_note() {
        let dest = scratch("nousers");
        let api = fake(vec![], vec!["access/users"]);
        let out = rt()
            .block_on(capture(&api, &Scope::Cluster, &dest))
            .unwrap();
        assert_eq!(out["partial"], true);
        assert!(
            out["note"]
                .as_str()
                .unwrap()
                .starts_with("PARTIAL: 1 warnings; "),
            "{out}"
        );
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn instances_emit_a_cluster_slot_keyed_on_the_cluster_name() {
        let nodes = json!([{"node": "thor"}, {"node": "odin"}]);
        let clustered =
            json!([{"type": "cluster", "name": "asgard"}, {"type": "node", "name": "thor"}]);
        assert_eq!(
            slots("pve", Some(&clustered), &nodes),
            ["cluster:asgard", "thor", "odin"]
        );
        let standalone = json!([{"type": "node", "name": "thor"}]);
        assert_eq!(
            slots("pve", Some(&standalone), &json!([{"node": "thor"}])),
            ["cluster:endpoint/pve", "thor"]
        );
        assert_eq!(slots("pve", None, &nodes), ["thor", "odin"]);
    }

    #[test]
    fn standalone_needs_one_matching_node_entry() {
        let one = json!([{"type": "node", "name": "thor"}]);
        assert!(standalone_proof(&one, &json!([{"node": "thor"}])).is_ok());
        assert!(standalone_proof(&json!([]), &json!([{"node": "thor"}])).is_err());
        assert!(standalone_proof(&one, &json!([{"node": "odin"}])).is_err());
        assert!(standalone_proof(&one, &json!([{"node": "thor"}, {"node": "odin"}])).is_err());
        let two = json!([{"type": "node", "name": "thor"}, {"type": "node", "name": "odin"}]);
        assert!(standalone_proof(&two, &json!([{"node": "thor"}])).is_err());
        let cluster = json!([{"type": "cluster", "name": "c"}, {"type": "node", "name": "thor"}]);
        assert!(standalone_proof(&cluster, &json!([{"node": "thor"}])).is_err());
    }

    #[test]
    fn an_unproven_standalone_fails_the_slot() {
        let dest = scratch("unproven");
        let mut api = fake(vec!["cluster/config/nodes"], vec![]);
        api.clustered = false;
        api.nodes = vec!["n1", "n2"];
        let err = rt()
            .block_on(capture(&api, &Scope::Cluster, &dest))
            .unwrap_err();
        assert!(err.to_string().contains("not provably standalone"), "{err}");
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn cluster_slot_resolution_lists_each_rejection() {
        let cluster = json!([{"type": "cluster", "name": "asgard"}]);
        let standalone = json!([{"type": "node", "name": "thor"}]);
        let pick = pick_cluster_slot(
            "endpoint/b",
            vec![
                ("a".into(), Ok(cluster.clone())),
                ("b".into(), Ok(standalone)),
            ],
        );
        assert_eq!(pick.unwrap(), "b");
        let err = pick_cluster_slot(
            "midgard",
            vec![
                ("a".into(), Ok(cluster)),
                ("bad".into(), Err("resolve: no token".into())),
                ("c".into(), Err("client: tls".into())),
            ],
        )
        .unwrap_err()
        .to_string();
        for want in [
            "a: serves 'asgard'",
            "bad: resolve: no token",
            "c: client: tls",
        ] {
            assert!(err.contains(want), "{want} missing from {err}");
        }
    }

    #[test]
    #[ignore = "core utils::scrub::scrub_url will scrub path and fragment secrets; swap scrub_url to it"]
    fn slack_webhook_path_secret_is_scrubbed() {
        let mut v = json!([{"url": "https://hooks.slack.com/services/T000/B000/XXXXSECRET"}]);
        scrub_json(&mut v);
        assert!(!v.to_string().contains("XXXXSECRET"), "{v}");
    }

    #[test]
    fn host_files_are_skipped_without_making_the_node_slot_partial() {
        let dest = scratch("host");
        let out = rt()
            .block_on(capture(&fake(vec![], vec![]), &node(), &dest))
            .unwrap();
        assert_eq!(out["partial"], false);
        let skipped = std::fs::read_to_string(dest.join("api").join(SKIPPED)).unwrap();
        assert_eq!(skipped, HOST_SKIPPED);
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn scrub_json_strips_secrets_userinfo_queries_and_headers() {
        let mut v = json!([{
            "name": "hook",
            "url": "https://user:pw@hooks.example/notify?token=abc&x=1",
            "header": ["name=Authorization,value=QmVhcmVyIHNlY3JldA=="],
            "token": "influx-secret",
            "server": "10.0.0.5",
        }]);
        scrub_json(&mut v);
        let text = v.to_string();
        for leak in ["pw@", "user:", "token=abc", "QmVhcmVy", "influx-secret"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        assert_eq!(v[0]["url"], "https://hooks.example/notify?***");
        assert_eq!(v[0]["header"][0], "name=Authorization,value=***");
        assert_eq!(v[0]["server"], "10.0.0.5");
    }

    #[test]
    fn scrub_text_strips_urls_inside_messages() {
        let s = scrub_text("GET \"https://a:b@pve:8006/api2/json/x?ticket=t\": HTTP 500");
        assert_eq!(s, "GET \"https://pve:8006/api2/json/x?***\": HTTP 500");
    }

    #[test]
    fn reads_are_permitted_to_the_runtime_role_per_apidoc() {
        let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/specs/apidoc.js"))
            .unwrap();
        let start = raw.find('[').unwrap();
        let end = raw.find("\n]").unwrap() + 2;
        let schema: Vec<Value> = plugin_toolkit::serde_json::from_str(&raw[start..end]).unwrap();
        fn find<'a>(nodes: &'a [Value], path: &str) -> Option<&'a Value> {
            for n in nodes {
                if n["path"] == path {
                    return Some(n);
                }
                if let Some(hit) = n["children"].as_array().and_then(|c| find(c, path)) {
                    return Some(hit);
                }
            }
            None
        }
        fn privs(v: &Value, out: &mut Vec<String>) {
            match v {
                Value::String(s)
                    if s.contains('.') && s.starts_with(|c: char| c.is_ascii_uppercase()) =>
                {
                    out.push(s.clone())
                }
                Value::Array(a) => a.iter().for_each(|x| privs(x, out)),
                _ => {}
            }
        }
        let granted: Vec<&str> = crate::access::ORCA_OPS_PRIVS.split_whitespace().collect();
        for r in NODE_READS.iter().chain(CLUSTER_READS) {
            let path = format!("/{}", r.path);
            let node = find(&schema, &path).unwrap_or_else(|| panic!("{path} not in apidoc"));
            let get = &node["info"]["GET"];
            assert_eq!(get["allowtoken"], 1, "{path} refuses tokens");
            let perms = &get["permissions"];
            let mut needed = Vec::new();
            privs(&perms["check"], &mut needed);
            if needed.is_empty() {
                assert!(
                    r.rule == Rule::Filtered
                        || perms["user"] == "all"
                        || perms["user"] == "world"
                        || perms.is_null(),
                    "{path}: no privilege check, so it filters; mark it Filtered ({perms})"
                );
            } else {
                assert!(
                    needed.iter().any(|p| granted.contains(&p.as_str())),
                    "{path} needs one of {needed:?}, ORCA_OPS_PRIVS grants none"
                );
            }
        }
        for (path, _) in NOT_CAPTURABLE {
            assert!(find(&schema, &format!("/{path}")).is_some());
        }
        assert!(!granted.contains(&"Permissions.Modify"));
    }

    #[test]
    fn node_names_reads_the_nodes_list() {
        let nodes = json!([{"node": "thor"}, {"node": "odin"}, {"status": "x"}]);
        assert_eq!(node_names(&nodes), ["thor", "odin"]);
        assert!(node_names(&json!({})).is_empty());
    }

    #[test]
    fn verify_catches_tamper_unlisted_and_missing() {
        let dir = scratch("sums");
        std::fs::create_dir_all(dir.join("api")).unwrap();
        std::fs::write(dir.join("api/a.json"), "{}").unwrap();
        std::fs::write(dir.join("config.db"), "db").unwrap();
        write_sums(&dir).unwrap();
        assert_eq!(verify_sums(&dir).unwrap().0, 2);

        std::fs::write(dir.join("config.db"), "changed").unwrap();
        assert!(
            verify_sums(&dir)
                .unwrap_err()
                .to_string()
                .contains("config.db")
        );

        write_sums(&dir).unwrap();
        std::fs::write(dir.join("extra"), "x").unwrap();
        assert!(
            verify_sums(&dir)
                .unwrap_err()
                .to_string()
                .contains("not in SHA256SUMS")
        );

        std::fs::remove_file(dir.join("extra")).unwrap();
        std::fs::remove_file(dir.join("api/a.json")).unwrap();
        assert!(
            verify_sums(&dir)
                .unwrap_err()
                .to_string()
                .contains("missing")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restore_verifies_then_refuses() {
        let dir = scratch("restore");
        std::fs::write(dir.join("config.db"), "db").unwrap();
        write_sums(&dir).unwrap();
        let err = restore(dir.to_str().unwrap()).unwrap_err().to_string();
        assert!(err.contains("capture-only: 1 file(s) verified"), "{err}");
        std::fs::remove_file(dir.join(SUMS)).unwrap();
        assert!(
            restore(dir.to_str().unwrap())
                .unwrap_err()
                .to_string()
                .contains("read")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
