//! `pve-node-state` backup kind: one PVE node's own state, which neither
//! vzdump nor the API-only `pve-config` kind covers.
//!
//! Instances are each PVE node plus one `cluster:<endpoint>` slot, so
//! cluster-scoped reads are captured once. The payload is:
//!
//! * `api/*.json` — the [`NODE_READS`] or [`CLUSTER_READS`] for the slot,
//!   fetched with the endpoint's API token; notification and metrics reads are
//!   scrubbed of secrets, URL userinfo, query strings and header values;
//! * `api/SKIPPED` — each read refused (scrubbed), each filtered list that came
//!   back empty, and each read the token cannot make ([`NOT_CAPTURABLE`]);
//! * `host/<abs path>` — the root-only host files in [`HOST_PATHS`], which no
//!   PVE API exposes, captured as [`OP_CAPTURE`] through orca's privileged seam
//!   when the admin has granted it and the node is this host;
//! * `OWNERSHIP` — `mode uid gid path` of every captured host entry;
//! * `SECRETS_EXCLUDED` — `mode uid gid size sha256 path` of every secret left
//!   out of the payload;
//! * `SHA256SUMS` — `sha256sum -c` format over every other file.
//!
//! A failed core read fails the slot. A failed other read, a failed host
//! capture, or a node that is not this host makes the result `partial` with a
//! `warnings` entry.
//!
//! Restore is capture-only: it verifies `SHA256SUMS` and refuses.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};
use plugin_toolkit::serde_json::{Value, json};
use serde::{Deserialize, Serialize};

pub const OP_CAPTURE: &str = "node_state.capture";

const OWNERSHIP: &str = "OWNERSHIP";
const HOST_DIR: &str = "host";
const SECRETS_EXCLUDED: &str = "SECRETS_EXCLUDED";

pub const HOST_PATHS: &[&str] = &[
    "/etc/ssh",
    "/etc/sudoers.d",
    "/etc/cron.d",
    "/etc/fstab",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/root/.ssh",
    "/var/spool/cron/crontabs",
];

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

struct Endpoint {
    http: plugin_toolkit::reqwest::Client,
    base_url: String,
}

impl ApiRead for Endpoint {
    async fn get(&self, path: &str) -> Result<Value> {
        crate::backup::raw_get_data(&self.http, &self.base_url, path).await
    }
}

pub async fn instances() -> Vec<String> {
    let found =
        crate::tools::for_each_enabled_endpoint("node_state.instances", |cfg, ep| async move {
            let http = cfg.build_reqwest_client()?;
            let nodes = crate::backup::raw_get_data(&http, &cfg.base_url, "nodes").await?;
            let mut out = vec![format!("{CLUSTER_PREFIX}{}", ep.name)];
            out.extend(node_names(&nodes));
            Ok(out)
        })
        .await;
    found
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
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
    if let Some(endpoint) = instance.strip_prefix(CLUSTER_PREFIX) {
        let cfg = crate::tools::resolve_config(endpoint).await?;
        let api = Endpoint {
            http: cfg.build_reqwest_client()?,
            base_url: cfg.base_url.clone(),
        };
        return capture(&api, &Scope::Cluster, Path::new(dir), None).await;
    }
    let (cfg, _) = crate::backup::resolve_endpoint_for_node(instance).await?;
    let api = Endpoint {
        http: cfg.build_reqwest_client()?,
        base_url: cfg.base_url.clone(),
    };
    let host =
        host_capture(
            dir,
            instance,
            &crate::diagnostics::local_node(),
            |op| async move {
                plugin_toolkit::privileged::apply("proxmox", OP_CAPTURE, Some(&op)).await
            },
        )
        .await;
    capture(
        &api,
        &Scope::Node(instance.to_string()),
        Path::new(dir),
        Some(host),
    )
    .await
}

pub(crate) async fn host_capture<F, Fut>(
    dir: &str,
    node: &str,
    local: &str,
    apply: F,
) -> Result<String, String>
where
    F: FnOnce(CaptureOp) -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    if node != local {
        return Err(format!(
            "host files not captured: {node} is not this host ({local})"
        ));
    }
    apply(CaptureOp {
        dest: dir.to_string(),
    })
    .await
    .map_err(|e| scrub_text(&format!("host files not captured: {OP_CAPTURE}: {e:#}")))
}

pub(crate) async fn capture<A: ApiRead>(
    api: &A,
    scope: &Scope,
    dest: &Path,
    host: Option<Result<String, String>>,
) -> Result<Value> {
    let dir = dest.join(API_DIR);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let (label, reads) = match scope {
        Scope::Node(n) => (n.clone(), NODE_READS),
        Scope::Cluster => ("cluster".to_string(), CLUSTER_READS),
    };
    let mut warnings = Vec::new();
    let mut skipped = String::new();
    let mut captured = 0;
    for r in reads {
        let path = match scope {
            Scope::Node(n) => r.path.replace("{node}", &crate::backup::enc(n)),
            Scope::Cluster => r.path.to_string(),
        };
        let mut data = match api.get(&path).await {
            Ok(d) => d,
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
            dir.join(r.file),
            plugin_toolkit::serde_json::to_vec_pretty(&data)?,
        )
        .with_context(|| format!("write {}", r.file))?;
        captured += 1;
    }
    if *scope == Scope::Cluster {
        for (path, why) in NOT_CAPTURABLE {
            skipped.push_str(&format!("{path}: {why}\n"));
        }
    }
    if !skipped.is_empty() {
        std::fs::write(dir.join(SKIPPED), &skipped).context("write SKIPPED")?;
    }
    let host_note = match host {
        Some(Ok(detail)) => detail,
        Some(Err(w)) => {
            warnings.push(w.clone());
            w
        }
        None => "no host files in the cluster slot".to_string(),
    };
    write_sums(dest)?;
    let (files, digest) = verify_sums(dest)?;
    Ok(json!({
        "checksum": format!("sha256:{digest}"),
        "partial": !warnings.is_empty(),
        "warnings": warnings,
        "note": format!(
            "{label}: {host_note}; {captured} API read(s); {} SKIPPED line(s); \
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
            match url::Url::parse(core) {
                Ok(mut u) if u.has_host() => {
                    if scrub_url(&mut u) {
                        tok.replace(core, u.as_str())
                    } else {
                        tok.to_string()
                    }
                }
                _ => tok.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn scrub_url(u: &mut url::Url) -> bool {
    let dirty = !u.username().is_empty() || u.password().is_some() || u.query().is_some();
    if dirty {
        u.set_username("").ok();
        u.set_password(None).ok();
        if u.query().is_some() {
            u.set_query(Some("***"));
        }
    }
    dirty
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
            if let Ok(mut u) = url::Url::parse(s)
                && u.has_host()
                && scrub_url(&mut u)
            {
                *s = u.to_string();
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| scrub_strings(x, in_header)),
        Value::Object(o) => o.iter_mut().for_each(|(k, x)| {
            scrub_strings(x, in_header || k.to_ascii_lowercase().contains("header"))
        }),
        _ => {}
    }
}

// ── root side ───────────────────────────────────────────────────────────────

/// Payload of [`OP_CAPTURE`]: the engine's payload dir for this slot.
#[derive(Serialize, Deserialize)]
pub struct CaptureOp {
    pub dest: String,
}

/// Root entry for [`OP_CAPTURE`].
pub async fn root_capture_op(op: CaptureOp) -> plugin_toolkit::anyhow::Result<String> {
    capture_in(Path::new("/"), Path::new(&op.dest))
}

/// Capture [`HOST_PATHS`] under `root` into `dest`, handing the copies to
/// `dest`'s owner. `root` is `/` in production.
pub fn capture_in(root: &Path, dest: &Path) -> Result<String> {
    let owner = check_dest(dest)?;

    let mut excluded = Vec::new();

    let host = dest.join(HOST_DIR);
    let mut files = 0;
    let mut missing = Vec::new();
    for p in HOST_PATHS {
        if std::fs::symlink_metadata(under(root, p)).is_err() {
            missing.push(*p);
            continue;
        }
        files += copy_without_secrets(root, Path::new(p), &host, &mut excluded)
            .with_context(|| format!("copy {p}"))?;
    }

    let mut ownership = String::new();
    record_and_chown(&host, &host, root, owner, &mut ownership)?;
    std::fs::write(dest.join(OWNERSHIP), ownership).context("write OWNERSHIP")?;
    std::fs::write(dest.join(SECRETS_EXCLUDED), excluded.concat())
        .context("write SECRETS_EXCLUDED")?;
    chown(&dest.join(OWNERSHIP), owner)?;
    chown(&dest.join(SECRETS_EXCLUDED), owner)?;

    let mut detail = format!(
        "{files} host file(s), {} secret(s) excluded",
        excluded.len()
    );
    if !missing.is_empty() {
        detail.push_str(&format!(" (absent: {})", missing.join(", ")));
    }
    Ok(detail)
}

/// `dest` comes from the unprivileged side, so root writes only into an
/// existing, non-root-owned real directory that has no capture in it yet.
fn check_dest(dest: &Path) -> Result<(u32, u32)> {
    ensure!(
        dest.is_absolute(),
        "payload dir {} is not absolute",
        dest.display()
    );
    let meta = std::fs::symlink_metadata(dest)
        .with_context(|| format!("stat payload dir {}", dest.display()))?;
    ensure!(
        meta.is_dir(),
        "payload dir {} is not a directory",
        dest.display()
    );
    ensure!(
        meta.uid() != 0,
        "payload dir {} is owned by root",
        dest.display()
    );
    for name in [HOST_DIR, OWNERSHIP, SECRETS_EXCLUDED, API_DIR] {
        ensure!(
            std::fs::symlink_metadata(dest.join(name)).is_err(),
            "payload dir {} already holds {name}",
            dest.display()
        );
    }
    Ok((meta.uid(), meta.gid()))
}

/// Copy `abs` from under `root` into `host`, leaving out every secret file and
/// recording it in `excluded` instead.
fn copy_without_secrets(
    root: &Path,
    abs: &Path,
    host: &Path,
    excluded: &mut Vec<String>,
) -> Result<u64> {
    let src = under(root, abs);
    let meta =
        std::fs::symlink_metadata(&src).with_context(|| format!("stat {}", src.display()))?;
    if meta.is_dir() {
        std::fs::create_dir_all(under(host, abs))
            .with_context(|| format!("create {}", abs.display()))?;
        let mut names: Vec<_> = std::fs::read_dir(&src)
            .with_context(|| format!("list {}", src.display()))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<std::io::Result<_>>()?;
        names.sort();
        let mut n = 0;
        for name in names {
            n += copy_without_secrets(root, &abs.join(name), host, excluded)?;
        }
        return Ok(n);
    }
    if meta.is_file() && is_secret(abs, &src)? {
        excluded.push(format!(
            "{:o} {} {} {} {} {}\n",
            meta.mode() & 0o7777,
            meta.uid(),
            meta.gid(),
            meta.len(),
            plugin_toolkit::hash::sha256_file(&src)?,
            abs.display()
        ));
        return Ok(0);
    }
    crate::bind_mounts::copy_tree(&src, &under(host, abs))
}

/// `abs` is the host path; `src` is where it is read from.
fn is_secret(abs: &Path, src: &Path) -> Result<bool> {
    let name = abs
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    if is_secret_name(&name) {
        return Ok(true);
    }
    if abs.starts_with("/root/.ssh")
        && !(name.ends_with(".pub")
            || matches!(
                &*name,
                "authorized_keys" | "authorized_keys2" | "known_hosts" | "config"
            ))
    {
        return Ok(true);
    }
    use std::io::Read;
    let mut head = Vec::new();
    std::fs::File::open(src)
        .with_context(|| format!("open {}", src.display()))?
        .take(16 * 1024)
        .read_to_end(&mut head)
        .with_context(|| format!("read {}", src.display()))?;
    Ok(looks_like_private_key(&head))
}

/// SSH host keys, TLS keys, keyrings.
fn is_secret_name(name: &str) -> bool {
    (name.starts_with("ssh_host_") && name.ends_with("_key"))
        || name.ends_with(".key")
        || name.ends_with(".keyring")
        || name == "authkey"
}

fn looks_like_private_key(head: &[u8]) -> bool {
    head.windows(16).any(|w| w == b"PRIVATE KEY-----")
}

fn under(root: &Path, abs: impl AsRef<Path>) -> PathBuf {
    let rel = abs.as_ref().strip_prefix("/").unwrap_or(abs.as_ref());
    root.join(rel)
}

/// Walk the copied tree, record each source entry's mode/uid/gid, and chown
/// the copy to `owner`.
fn record_and_chown(
    host: &Path,
    at: &Path,
    root: &Path,
    owner: (u32, u32),
    out: &mut String,
) -> Result<()> {
    let meta = std::fs::symlink_metadata(at).with_context(|| format!("stat {}", at.display()))?;
    if at != host {
        let rel = at.strip_prefix(host).expect("walk stays under host");
        if let Ok(src) = std::fs::symlink_metadata(root.join(rel)) {
            out.push_str(&format!(
                "{:o} {} {} /{}\n",
                src.mode() & 0o7777,
                src.uid(),
                src.gid(),
                rel.display()
            ));
        }
        chown(at, owner)?;
    }
    if meta.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(at)
            .with_context(|| format!("list {}", at.display()))?
            .flatten()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for e in entries {
            record_and_chown(host, &e, root, owner, out)?;
        }
    }
    Ok(())
}

fn chown(path: &Path, (uid, gid): (u32, u32)) -> Result<()> {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))
        .with_context(|| format!("chown {}", path.display()))
}

// ── SHA256SUMS ──────────────────────────────────────────────────────────────

/// Every regular file under `dir` except `SHA256SUMS`, keyed by relative path.
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

/// Check every file against `SHA256SUMS` and that no file is unlisted.
/// Returns the file count and the SHA-256 of `SHA256SUMS` itself.
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
        calls: std::sync::Mutex<Vec<String>>,
    }

    fn fake(refuse: Vec<&'static str>, empty: Vec<&'static str>) -> FakeApi {
        FakeApi {
            refuse,
            empty,
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
        let out = rt()
            .block_on(capture(
                &api,
                &node(),
                &dest,
                Some(Ok("5 host file(s)".into())),
            ))
            .unwrap();
        let calls = api.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), NODE_READS.len());
        assert!(
            calls.iter().all(|c| c.starts_with("nodes/n1/")),
            "{calls:?}"
        );
        assert_eq!(out["partial"], false);
        assert_eq!(out["warnings"], json!([]));
        assert!(!dest.join("api").join(SKIPPED).exists());
        assert_eq!(verify_sums(&dest).unwrap().0, NODE_READS.len());
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn cluster_slot_reads_cluster_paths_once_and_skips_acl() {
        let dest = scratch("cluster");
        let api = fake(vec![], vec![]);
        rt().block_on(capture(&api, &Scope::Cluster, &dest, None))
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
            .block_on(capture(&api, &Scope::Cluster, &dest, None))
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
        let out = rt()
            .block_on(capture(&api, &node(), &dest, Some(Ok("ok".into()))))
            .unwrap();
        let skipped = std::fs::read_to_string(dest.join("api").join(SKIPPED)).unwrap();
        assert_eq!(skipped.lines().count(), 2);
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
            let err = rt()
                .block_on(capture(&api, &scope, &dest, None))
                .unwrap_err();
            assert!(err.to_string().contains("core read failed"), "{err}");
            assert!(!dest.join(SUMS).exists());
            std::fs::remove_dir_all(&dest).unwrap();
        }
    }

    #[test]
    fn host_capture_failure_and_remote_node_are_partial() {
        let failed = rt().block_on(host_capture("/d", "n1", "n1", |_| async {
            Err(anyhow!("sudo refused, Authorization: Bearer abc123"))
        }));
        let err = failed.clone().unwrap_err();
        assert!(err.contains(OP_CAPTURE) && !err.contains("abc123"), "{err}");
        let remote = rt().block_on(host_capture("/d", "n2", "n1", |_| async {
            panic!("must not run for a remote node")
        }));
        assert!(remote.clone().unwrap_err().contains("n2 is not this host"));
        let ok = rt().block_on(host_capture(
            "/d",
            "n1",
            "n1",
            |op| async move { Ok(op.dest) },
        ));
        assert_eq!(ok.unwrap(), "/d");
        for host in [failed, remote] {
            let dest = scratch("partial");
            let out = rt()
                .block_on(capture(&fake(vec![], vec![]), &node(), &dest, Some(host)))
                .unwrap();
            assert_eq!(out["partial"], true);
            assert!(
                out["warnings"][0]
                    .as_str()
                    .unwrap()
                    .starts_with("host files not captured")
            );
            std::fs::remove_dir_all(&dest).unwrap();
        }
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

    fn fake_root(base: &Path) -> PathBuf {
        let root = base.join("root");
        let ssh = under(&root, "/etc/ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("sshd_config"), "Port 22\n").unwrap();
        std::fs::write(under(&root, "/etc/fstab"), "proc /proc proc 0 0\n").unwrap();
        std::os::unix::fs::symlink("sshd_config", ssh.join("link")).unwrap();
        std::fs::write(ssh.join("ssh_host_ed25519_key"), "host secret").unwrap();
        std::fs::write(ssh.join("ssh_host_ed25519_key.pub"), "ssh-ed25519 AAAA\n").unwrap();
        let rs = under(&root, "/root/.ssh");
        std::fs::create_dir_all(&rs).unwrap();
        std::fs::write(rs.join("id_rsa"), "root secret").unwrap();
        std::fs::write(rs.join("authorized_keys"), "ssh-ed25519 AAAA\n").unwrap();
        let bin = under(&root, "/usr/local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("deploy"), "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        root
    }

    fn unroot(dest: &Path) {
        if std::fs::metadata(dest).unwrap().uid() == 0 {
            std::os::unix::fs::chown(dest, Some(65534), Some(65534)).unwrap();
        }
    }

    #[test]
    fn host_capture_excludes_secrets_and_records_ownership() {
        let base = scratch("host");
        let root = fake_root(&base);
        let dest = base.join("payload");
        std::fs::create_dir_all(&dest).unwrap();
        unroot(&dest);

        let detail = capture_in(&root, &dest).unwrap();
        assert!(
            detail.starts_with("5 host file(s), 3 secret(s) excluded"),
            "{detail}"
        );
        assert!(detail.contains("absent: /etc/sudoers.d"), "{detail}");
        for gone in [
            "host/etc/ssh/ssh_host_ed25519_key",
            "host/root/.ssh/id_rsa",
            "host/usr/local/bin/deploy",
        ] {
            assert!(
                std::fs::symlink_metadata(dest.join(gone)).is_err(),
                "{gone}"
            );
        }
        for kept in [
            "host/etc/ssh/ssh_host_ed25519_key.pub",
            "host/root/.ssh/authorized_keys",
            "host/etc/fstab",
        ] {
            assert!(dest.join(kept).is_file(), "{kept}");
        }
        let ex = std::fs::read_to_string(dest.join(SECRETS_EXCLUDED)).unwrap();
        let host_secret = plugin_toolkit::hash::sha256_hex(b"host secret");
        assert!(
            ex.contains(&format!(
                " 11 {host_secret} /etc/ssh/ssh_host_ed25519_key\n"
            )),
            "{ex}"
        );
        assert!(ex.contains(" /root/.ssh/id_rsa\n"), "{ex}");
        assert!(ex.contains(" /usr/local/bin/deploy\n"), "{ex}");
        assert!(!ex.contains("secret\n"), "{ex}");
        let own = std::fs::read_to_string(dest.join(OWNERSHIP)).unwrap();
        assert!(own.contains(" /etc/ssh/sshd_config\n"), "{own}");

        let api = fake(vec![], vec![]);
        let out = rt()
            .block_on(capture(&api, &node(), &dest, Some(Ok(detail))))
            .unwrap();
        assert!(out["note"].as_str().unwrap().contains("5 host file(s)"));
        verify_sums(&dest).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn host_capture_refuses_a_used_payload_dir() {
        let base = scratch("used");
        let root = fake_root(&base);
        let dest = base.join("payload");
        std::fs::create_dir_all(dest.join(API_DIR)).unwrap();
        unroot(&dest);
        let err = capture_in(&root, &dest).unwrap_err().to_string();
        assert!(err.contains("already holds api"), "{err}");
        assert!(capture_in(&root, Path::new("relative")).is_err());
        std::fs::remove_dir_all(&base).unwrap();
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
