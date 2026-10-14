//! `pve-node-state` backup kind: one PVE node's own state, which neither
//! vzdump nor the API-only `pve-config` kind covers.
//!
//! The payload is:
//!
//! * `config.db` — the pmxcfs database, copied with SQLite's online backup API
//!   (never a plain `cp` of the live file) and checked with `integrity_check`;
//! * `host/<abs path>` — host config files listed in [`HOST_PATHS`];
//! * `OWNERSHIP` — `mode uid gid path` of every captured entry, since the
//!   payload copies are owned by the orca user so the engine can ship them;
//! * `SECRETS_EXCLUDED` — `mode uid gid size sha256 path` of every secret left
//!   out of the payload (see [`is_secret`] and [`scrub_db_secrets`]), so a
//!   restore can detect drift without the orca user ever holding the material;
//! * `api/*.json` — what the PVE API exposes for the node (network, dns, hosts,
//!   apt repositories, cluster node list);
//! * `SHA256SUMS` — `sha256sum -c` format over every other file.
//!
//! `config.db` and most of [`HOST_PATHS`] need root, so the file capture runs
//! as [`OP_CAPTURE`] through orca's `admin plugin-apply` seam.
//!
//! Restore is capture-only: it verifies `SHA256SUMS` and refuses, since
//! writing `config.db` back means stopping pmxcfs on a live cluster member.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use plugin_toolkit::serde_json::{Value, json};
use serde::{Deserialize, Serialize};

pub const OP_CAPTURE: &str = "node_state.capture";

pub const CONFIG_DB: &str = "/var/lib/pve-cluster/config.db";
const SUMS: &str = "SHA256SUMS";
const OWNERSHIP: &str = "OWNERSHIP";
const DB_FILE: &str = "config.db";
const HOST_DIR: &str = "host";
const SECRETS_EXCLUDED: &str = "SECRETS_EXCLUDED";

pub const HOST_PATHS: &[&str] = &[
    "/etc/pve",
    "/etc/network",
    "/etc/corosync",
    "/etc/ssh",
    "/etc/sudoers.d",
    "/etc/cron.d",
    "/etc/fstab",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/root/.ssh",
    "/var/spool/cron/crontabs",
];

/// Node-scoped (`{node}` substituted) and cluster-scoped API reads.
const API_CAPTURES: &[(&str, &str)] = &[
    ("nodes/{node}/network", "network.json"),
    ("nodes/{node}/dns", "dns.json"),
    ("nodes/{node}/hosts", "hosts.json"),
    ("nodes/{node}/apt/repositories", "apt-repositories.json"),
    ("cluster/config/nodes", "cluster-nodes.json"),
];

/// This host's node name, or nothing when it is not a PVE node.
pub fn instances() -> Vec<String> {
    if Path::new(CONFIG_DB).exists() {
        vec![crate::diagnostics::local_node()]
    } else {
        Vec::new()
    }
}

pub async fn backup(dir: &str, instance: &str) -> Result<Value> {
    let node = crate::diagnostics::local_node();
    ensure!(
        instance == node,
        "pve-node-state: instance '{instance}' is not this node ('{node}')"
    );
    let dest = Path::new(dir);
    let detail = plugin_toolkit::privileged::apply(
        "proxmox",
        OP_CAPTURE,
        Some(&CaptureOp {
            dest: dir.to_string(),
        }),
    )
    .await
    .with_context(|| format!("{OP_CAPTURE} via orca's privileged seam"))?;

    let api = api_capture(&node, &dest.join("api")).await;
    write_sums(dest)?;
    let (files, digest) = verify_sums(dest)?;
    Ok(json!({
        "checksum": format!("sha256:{digest}"),
        "note": format!(
            "{node}: {detail}; api: {}; {files} file(s) in SHA256SUMS; \
             secrets excluded (listed in {SECRETS_EXCLUDED}), pending the encrypted-secrets follow-up",
            if api.is_empty() { "none".to_string() } else { api.join(", ") }
        ),
    }))
}

pub fn restore(dir: &str) -> Result<Value> {
    let (files, _) = verify_sums(Path::new(dir))?;
    bail!(
        "pve-node-state is capture-only: {files} file(s) verified against SHA256SUMS in {dir}; \
         restoring config.db needs pmxcfs stopped, so apply it by hand"
    )
}

/// Each read the API refuses is skipped; the file capture is the primary copy.
async fn api_capture(node: &str, dir: &Path) -> Vec<&'static str> {
    let mut captured = Vec::new();
    let (cfg, _) = match crate::backup::resolve_endpoint_for_node(node).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(node, error = %e, "pve-node-state: no endpoint; skipping api capture");
            return captured;
        }
    };
    let http = match cfg.build_reqwest_client() {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(node, error = %e, "pve-node-state: api client; skipping api capture");
            return captured;
        }
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!(error = %e, "pve-node-state: create api dir; skipping api capture");
        return captured;
    }
    for (path, file) in API_CAPTURES {
        let path = path.replace("{node}", &crate::backup::enc(node));
        match crate::backup::raw_get_data(&http, &cfg.base_url, &path).await {
            Ok(data) => match plugin_toolkit::serde_json::to_vec_pretty(&data)
                .map_err(anyhow::Error::from)
                .and_then(|b| Ok(std::fs::write(dir.join(file), b)?))
            {
                Ok(()) => captured.push(*file),
                Err(e) => tracing::warn!(file, error = %e, "pve-node-state: write api capture"),
            },
            Err(e) => {
                tracing::warn!(path, error = %e, "pve-node-state: api capture failed; skipping")
            }
        }
    }
    captured
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

/// Capture `config.db` and [`HOST_PATHS`] under `root` into `dest`, handing the
/// copies to `dest`'s owner. `root` is `/` in production.
pub fn capture_in(root: &Path, dest: &Path) -> Result<String> {
    let owner = check_dest(dest)?;

    let db = dest.join(DB_FILE);
    let mut excluded = sqlite_online_copy(&under(root, CONFIG_DB), &db)?;

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
    chown(&db, owner)?;
    chown(&dest.join(OWNERSHIP), owner)?;
    chown(&dest.join(SECRETS_EXCLUDED), owner)?;

    let mut detail = format!(
        "config.db + {files} host file(s), {} secret(s) excluded",
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
    for name in [DB_FILE, HOST_DIR, OWNERSHIP, SECRETS_EXCLUDED] {
        ensure!(
            std::fs::symlink_metadata(dest.join(name)).is_err(),
            "payload dir {} already holds {name}",
            dest.display()
        );
    }
    Ok((meta.uid(), meta.gid()))
}

/// Short steps with a pause keep each read lock brief so pmxcfs writes are
/// never held up; a write mid-copy makes SQLite restart the copy. Returns the
/// `SECRETS_EXCLUDED` lines for rows scrubbed from the copy.
fn sqlite_online_copy(src: &Path, dst: &Path) -> Result<Vec<String>> {
    use rusqlite::{Connection, OpenFlags, backup::Backup};
    let src_conn = Connection::open_with_flags(
        src,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("open {}", src.display()))?;
    let mut dst_conn =
        Connection::open(dst).with_context(|| format!("create {}", dst.display()))?;
    Backup::new(&src_conn, &mut dst_conn)
        .context("start sqlite online backup")?
        .run_to_completion(64, Duration::from_millis(20), None)
        .context("sqlite online backup")?;
    let excluded = scrub_db_secrets(&dst_conn)?;
    let check: String = dst_conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .context("integrity_check on the copy")?;
    ensure!(
        check == "ok",
        "config.db copy failed integrity_check: {check}"
    );
    // The copy inherits pmxcfs's WAL header; rollback mode leaves no -wal/-shm
    // side files in the payload. pmxcfs sets its own mode when it opens the db.
    let mode: String = dst_conn
        .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))
        .context("set journal_mode on the copy")?;
    ensure!(mode == "delete", "config.db copy kept journal_mode {mode}");
    Ok(excluded)
}

/// pmxcfs stores every `/etc/pve` file as a `tree` row (parent = 0 at the top,
/// inode 0 is the version row), so `priv/` and node TLS keys live in config.db
/// too. Delete them from the copy and VACUUM so the freed pages are gone.
fn scrub_db_secrets(conn: &rusqlite::Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "WITH RECURSIVE p(inode, path) AS (
                 SELECT inode, '/' || name FROM tree WHERE parent = 0 AND inode != 0
                 UNION ALL
                 SELECT t.inode, p.path || '/' || t.name FROM tree t JOIN p ON t.parent = p.inode
             )
             SELECT p.inode, p.path, CAST(t.data AS BLOB) FROM p JOIN tree t ON t.inode = p.inode
             ORDER BY p.path",
        )
        .context("walk config.db tree")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })
        .context("walk config.db tree")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("walk config.db tree")?;
    drop(stmt);
    let mut excluded = Vec::new();
    for (inode, path, data) in rows {
        let name = path.rsplit('/').next().unwrap_or_default();
        let secret = path.starts_with("/priv/")
            || is_secret_name(name)
            || data.as_deref().is_some_and(looks_like_private_key);
        if !secret {
            continue;
        }
        let data = data.unwrap_or_default();
        excluded.push(format!(
            "- - - {} {} {DB_FILE}:{path}\n",
            data.len(),
            plugin_toolkit::hash::sha256_hex(&data)
        ));
        conn.execute("DELETE FROM tree WHERE inode = ?1", [inode])
            .with_context(|| format!("scrub {path} from config.db copy"))?;
    }
    conn.execute_batch("VACUUM")
        .context("VACUUM config.db copy")?;
    Ok(excluded)
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
    if abs.starts_with("/etc/pve/priv") || is_secret_name(&name) {
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

/// SSH host keys, TLS keys (`pve-ssl.key`, `pveproxy-ssl.key`), corosync's
/// `authkey`, ceph keyrings.
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

    fn fake_root(base: &Path) -> PathBuf {
        let root = base.join("root");
        let db = under(&root, CONFIG_DB);
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE tree (inode INTEGER PRIMARY KEY NOT NULL, parent INTEGER NOT NULL,
                 version INTEGER NOT NULL, writer INTEGER NOT NULL, mtime INTEGER NOT NULL,
                 type INTEGER NOT NULL, name TEXT NOT NULL, data BLOB);
             INSERT INTO tree VALUES
                 (0, 0, 9, 0, 0, 8, '__version__', NULL),
                 (1, 0, 1, 0, 0, 8, 'corosync.conf', 'totem {}'),
                 (2, 0, 1, 0, 0, 4, 'priv', NULL),
                 (3, 2, 1, 0, 0, 8, 'authkey.key', 'cluster secret'),
                 (4, 2, 1, 0, 0, 8, 'token.cfg', 'tok'),
                 (5, 0, 1, 0, 0, 4, 'nodes', NULL),
                 (6, 5, 1, 0, 0, 4, 'n1', NULL),
                 (7, 6, 1, 0, 0, 8, 'pve-ssl.key', 'tls secret'),
                 (8, 6, 1, 0, 0, 8, 'pve-ssl.pem', 'cert');",
        )
        .unwrap();
        // Held open: the copy must read a database another connection owns.
        std::mem::forget(c);
        let ssh = under(&root, "/etc/ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("sshd_config"), "Port 22\n").unwrap();
        std::fs::write(under(&root, "/etc/fstab"), "proc /proc proc 0 0\n").unwrap();
        std::os::unix::fs::symlink("sshd_config", ssh.join("link")).unwrap();
        std::fs::write(ssh.join("ssh_host_ed25519_key"), "host secret").unwrap();
        std::fs::write(ssh.join("ssh_host_ed25519_key.pub"), "ssh-ed25519 AAAA\n").unwrap();
        let pv = under(&root, "/etc/pve/priv");
        std::fs::create_dir_all(&pv).unwrap();
        std::fs::write(pv.join("shadow.cfg"), "cluster secret").unwrap();
        let rs = under(&root, "/root/.ssh");
        std::fs::create_dir_all(&rs).unwrap();
        std::fs::write(rs.join("id_rsa"), "root secret").unwrap();
        std::fs::write(rs.join("authorized_keys"), "ssh-ed25519 AAAA\n").unwrap();
        let bin = under(&root, "/usr/local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("deploy"), "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        std::fs::write(under(&root, "/etc/hosts"), "127.0.0.1 localhost\n").unwrap();
        root
    }

    /// `check_dest` refuses a root-owned dest; CI runs tests as root.
    fn unroot(dest: &Path) {
        if std::fs::metadata(dest).unwrap().uid() == 0 {
            std::os::unix::fs::chown(dest, Some(65534), Some(65534)).unwrap();
        }
    }

    #[test]
    fn capture_copies_db_and_host_paths_and_sums_verify() {
        let base = scratch("cap");
        let root = fake_root(&base);
        let dest = base.join("payload");
        std::fs::create_dir_all(&dest).unwrap();
        unroot(&dest);

        let detail = capture_in(&root, &dest).unwrap();
        assert!(
            detail.contains("config.db + 6 host file(s), 7 secret(s) excluded"),
            "{detail}"
        );
        assert!(!detail.contains("/etc/pve"), "{detail}");

        let c = rusqlite::Connection::open(dest.join(DB_FILE)).unwrap();
        let names: Vec<String> = c
            .prepare("SELECT name FROM tree ORDER BY inode")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            names,
            [
                "__version__",
                "corosync.conf",
                "priv",
                "nodes",
                "n1",
                "pve-ssl.pem"
            ]
        );
        let check: String = c
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(check, "ok");
        let raw = std::fs::read(dest.join(DB_FILE)).unwrap();
        assert!(!raw.windows(14).any(|w| w == b"cluster secret"));
        assert!(!raw.windows(10).any(|w| w == b"tls secret"));

        for gone in [
            "host/etc/ssh/ssh_host_ed25519_key",
            "host/etc/pve/priv/shadow.cfg",
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
            "host/etc/hosts",
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
        for path in [
            " /etc/pve/priv/shadow.cfg\n",
            " /root/.ssh/id_rsa\n",
            " /usr/local/bin/deploy\n",
            " config.db:/priv/authkey.key\n",
            " config.db:/priv/token.cfg\n",
            " config.db:/nodes/n1/pve-ssl.key\n",
        ] {
            assert!(ex.contains(path), "{path} missing from {ex}");
        }
        assert!(!ex.contains("secret\n"), "{ex}");
        assert_eq!(
            std::fs::read_to_string(dest.join("host/etc/ssh/sshd_config")).unwrap(),
            "Port 22\n"
        );
        let own = std::fs::read_to_string(dest.join(OWNERSHIP)).unwrap();
        assert!(own.contains(" /etc/ssh/sshd_config\n"), "{own}");
        assert!(own.contains(" /etc/fstab\n"), "{own}");

        write_sums(&dest).unwrap();
        let (files, digest) = verify_sums(&dest).unwrap();
        assert_eq!(files, 8);
        assert_eq!(digest.len(), 64);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn capture_refuses_a_used_payload_dir() {
        let base = scratch("used");
        let root = fake_root(&base);
        let dest = base.join("payload");
        std::fs::create_dir_all(dest.join(HOST_DIR)).unwrap();
        unroot(&dest);
        let err = capture_in(&root, &dest).unwrap_err().to_string();
        assert!(err.contains("already holds host"), "{err}");
        assert!(capture_in(&root, Path::new("relative")).is_err());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn verify_catches_tamper_unlisted_and_missing() {
        let dir = scratch("sums");
        std::fs::create_dir_all(dir.join("api")).unwrap();
        std::fs::write(dir.join("api/a.json"), "{}").unwrap();
        std::fs::write(dir.join(DB_FILE), "db").unwrap();
        write_sums(&dir).unwrap();
        assert_eq!(verify_sums(&dir).unwrap().0, 2);

        std::fs::write(dir.join(DB_FILE), "changed").unwrap();
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
        std::fs::write(dir.join(DB_FILE), "db").unwrap();
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
