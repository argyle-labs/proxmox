//! `pve-node-state` backup kind: one PVE node's own state, which neither
//! vzdump nor the API-only `pve-config` kind covers.
//!
//! The payload is:
//!
//! * `api/*.json` — every node- and cluster-scoped config read listed in
//!   [`API_CAPTURES`], fetched with the endpoint's API token;
//! * `api/SKIPPED` — each read PVE refused, with its error;
//! * `host/<abs path>` — the root-only host files in [`HOST_PATHS`], which no
//!   PVE API exposes, captured as [`OP_CAPTURE`] through orca's privileged seam
//!   when the admin has granted it and the node is this host;
//! * `OWNERSHIP` — `mode uid gid path` of every captured host entry;
//! * `SECRETS_EXCLUDED` — `mode uid gid size sha256 path` of every secret left
//!   out of the payload;
//! * `SHA256SUMS` — `sha256sum -c` format over every other file.
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

const API_CAPTURES: &[(&str, &str)] = &[
    ("nodes/{node}/config", "node-config.json"),
    ("nodes/{node}/network", "network.json"),
    ("nodes/{node}/dns", "dns.json"),
    ("nodes/{node}/hosts", "hosts.json"),
    ("nodes/{node}/time", "time.json"),
    ("nodes/{node}/apt/repositories", "apt-repositories.json"),
    (
        "nodes/{node}/firewall/options",
        "node-firewall-options.json",
    ),
    ("nodes/{node}/firewall/rules", "node-firewall-rules.json"),
    ("nodes/{node}/certificates/info", "certificates.json"),
    ("nodes/{node}/disks/list", "disks.json"),
    ("cluster/config/nodes", "cluster-nodes.json"),
    ("cluster/config/totem", "cluster-totem.json"),
    ("cluster/options", "cluster-options.json"),
    ("storage", "storage.json"),
    ("pools", "pools.json"),
    ("cluster/backup", "backup-jobs.json"),
    ("cluster/replication", "replication.json"),
    ("cluster/ha/resources", "ha-resources.json"),
    ("cluster/ha/groups", "ha-groups.json"),
    ("cluster/firewall/options", "cluster-firewall-options.json"),
    ("cluster/firewall/rules", "cluster-firewall-rules.json"),
    ("cluster/firewall/groups", "cluster-firewall-groups.json"),
    ("cluster/firewall/aliases", "cluster-firewall-aliases.json"),
    ("cluster/firewall/ipset", "cluster-firewall-ipset.json"),
    ("cluster/sdn/zones", "sdn-zones.json"),
    ("cluster/sdn/vnets", "sdn-vnets.json"),
    ("cluster/mapping/pci", "mapping-pci.json"),
    ("cluster/mapping/usb", "mapping-usb.json"),
    ("cluster/metrics/server", "metrics-servers.json"),
    (
        "cluster/notifications/endpoints",
        "notification-endpoints.json",
    ),
    (
        "cluster/notifications/matchers",
        "notification-matchers.json",
    ),
    ("access/users", "users.json"),
    ("access/groups", "groups.json"),
    ("access/roles", "roles.json"),
    ("access/acl", "acl.json"),
    ("access/domains", "domains.json"),
];

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
    let nodes =
        crate::tools::for_each_enabled_endpoint("node_state.instances", |cfg, _| async move {
            let http = cfg.build_reqwest_client()?;
            let nodes = crate::backup::raw_get_data(&http, &cfg.base_url, "nodes").await?;
            Ok(node_names(&nodes))
        })
        .await;
    nodes
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

pub async fn backup(dir: &str, node: &str) -> Result<Value> {
    let (cfg, _) = crate::backup::resolve_endpoint_for_node(node).await?;
    let api = Endpoint {
        http: cfg.build_reqwest_client()?,
        base_url: cfg.base_url.clone(),
    };
    let host = if node == crate::diagnostics::local_node() {
        match plugin_toolkit::privileged::apply(
            "proxmox",
            OP_CAPTURE,
            Some(&CaptureOp {
                dest: dir.to_string(),
            }),
        )
        .await
        {
            Ok(detail) => detail,
            Err(e) => format!("host files not captured ({OP_CAPTURE}: {e:#})"),
        }
    } else {
        format!("host files not captured ({node} is not this host)")
    };
    capture(&api, node, Path::new(dir), &host).await
}

pub(crate) async fn capture<A: ApiRead>(
    api: &A,
    node: &str,
    dest: &Path,
    host: &str,
) -> Result<Value> {
    let dir = dest.join(API_DIR);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let mut captured = 0;
    let mut skipped = String::new();
    for (path, file) in API_CAPTURES {
        let path = path.replace("{node}", &crate::backup::enc(node));
        match api.get(&path).await {
            Ok(data) => {
                std::fs::write(
                    dir.join(file),
                    plugin_toolkit::serde_json::to_vec_pretty(&data)?,
                )
                .with_context(|| format!("write {file}"))?;
                captured += 1;
            }
            Err(e) => skipped.push_str(&format!("{path}: {e:#}\n")),
        }
    }
    ensure!(
        captured > 0,
        "pve-node-state: every API read failed for {node}:\n{skipped}"
    );
    let skipped_count = skipped.lines().count();
    if skipped_count > 0 {
        std::fs::write(dir.join(SKIPPED), &skipped).context("write SKIPPED")?;
    }
    write_sums(dest)?;
    let (files, digest) = verify_sums(dest)?;
    Ok(json!({
        "checksum": format!("sha256:{digest}"),
        "note": format!(
            "{node}: {host}; {captured} API read(s), {skipped_count} skipped (listed in \
             {API_DIR}/{SKIPPED}); {files} file(s) in SHA256SUMS"
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
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl ApiRead for FakeApi {
        async fn get(&self, path: &str) -> Result<Value> {
            self.calls.lock().unwrap().push(path.to_string());
            if self.refuse.iter().any(|r| path.starts_with(r)) {
                bail!("HTTP 403: permission check failed");
            }
            Ok(json!({ "path": path }))
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn capture_writes_every_api_read_and_sums_verify() {
        let dest = scratch("cap");
        let api = FakeApi {
            refuse: vec![],
            calls: Default::default(),
        };
        let out = rt()
            .block_on(capture(&api, "n1", &dest, "host skipped"))
            .unwrap();
        let calls = api.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), API_CAPTURES.len());
        assert!(calls.contains(&"nodes/n1/network".to_string()));
        assert!(calls.contains(&"cluster/config/totem".to_string()));
        let net: Value = plugin_toolkit::serde_json::from_slice(
            &std::fs::read(dest.join("api/network.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(net["path"], "nodes/n1/network");
        assert!(!dest.join("api").join(SKIPPED).exists());
        let (files, _) = verify_sums(&dest).unwrap();
        assert_eq!(files, API_CAPTURES.len());
        assert!(out["checksum"].as_str().unwrap().starts_with("sha256:"));
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn capture_records_refused_reads() {
        let dest = scratch("skip");
        let api = FakeApi {
            refuse: vec!["access/", "cluster/sdn/"],
            calls: Default::default(),
        };
        let out = rt()
            .block_on(capture(&api, "n1", &dest, "host skipped"))
            .unwrap();
        let skipped = std::fs::read_to_string(dest.join("api").join(SKIPPED)).unwrap();
        assert_eq!(skipped.lines().count(), 7);
        assert!(skipped.contains("access/acl: HTTP 403"), "{skipped}");
        assert!(!dest.join("api/acl.json").exists());
        assert!(out["note"].as_str().unwrap().contains("7 skipped"));
        verify_sums(&dest).unwrap();
        std::fs::remove_dir_all(&dest).unwrap();
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

        let api = FakeApi {
            refuse: vec![],
            calls: Default::default(),
        };
        let out = rt().block_on(capture(&api, "n1", &dest, &detail)).unwrap();
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
    fn capture_fails_when_every_read_is_refused() {
        let dest = scratch("none");
        let api = FakeApi {
            refuse: vec![""],
            calls: Default::default(),
        };
        let err = rt()
            .block_on(capture(&api, "n1", &dest, "host skipped"))
            .unwrap_err();
        assert!(err.to_string().contains("every API read failed"), "{err}");
        assert!(!dest.join(SUMS).exists());
        std::fs::remove_dir_all(&dest).unwrap();
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
