//! In-container I/O for LXC guests through orca's privileged seams: `orca admin
//! lxc-exec` (allowlisted argv) and `orca admin lxc-push` (file write).
//!
//! Both seams run `pct` on the node the plugin runs on, so a container is
//! reachable only from the plugin instance on its own node; [`require_local`]
//! turns a remote one into a clear error instead of a confusing `pct` failure.

use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::prelude::*;
use tokio::io::AsyncWriteExt;

use crate::generated::{self, types as gtypes};

/// Mirrors `system::lxc_exec::ALLOWED_COMMANDS` in orca. A command outside it
/// is refused here, before any step of a plan runs, so a verb never applies
/// half its changes and then hits the root-side refusal.
pub const EXEC_ALLOWLIST: &[&str] = &[
    "apt-get",
    "apt",
    "dpkg",
    "dpkg-query",
    "systemctl",
    "true",
    "df",
    "cat",
    "ls",
    "stat",
    "head",
    "tail",
];

/// Entries the guest standard needs on orca's root-side allowlist (orca#769),
/// each with why. Until orca ships them, steps using them are named in the
/// dry-run plan and refused or deferred before anything runs. `/usr/bin/update`
/// is an absolute path because a bare `update` basename would admit any
/// program of that name anywhere in the container.
///
/// `sh` is absent: every step execs its program directly, and `sh -c` would
/// let the exec seam run any command line it is handed.
pub const PROPOSED_ALLOWLIST: &[(&str, &str)] = &[
    (
        "kill",
        "`kill -HUP 1`: busybox init re-reads /etc/inittab only on SIGHUP, so the \
         Alpine console autologin is live without restarting the container",
    ),
    (
        "apk",
        "`apk update` / `apk upgrade`: the Alpine package updater, the apt-get \
         equivalent already allowed",
    ),
    (
        "/usr/bin/update",
        "the app's own updater (community-scripts, or the Gitea \
         and Caddy updaters that validate and roll back), run after orca's backup",
    ),
];

/// `Some("needs allowlist: <cmd>")` when orca's lxc-exec seam would refuse
/// `argv0`.
pub fn needs_allowlist(argv0: &str) -> Option<String> {
    let base = argv0.rsplit('/').next().unwrap_or(argv0);
    (!EXEC_ALLOWLIST.contains(&base)).then(|| format!("needs allowlist: {base}"))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    /// Trimmed by the seam.
    pub stdout: String,
    pub stderr: String,
}

/// The two in-container operations, behind a trait so the verbs are testable
/// without `sudo` or `pct`.
pub trait GuestIo: Sync {
    fn exec<'a>(&'a self, vmid: u32, argv: &'a [&'a str]) -> BoxFuture<'a, Result<ExecResult>>;
    fn write<'a>(
        &'a self,
        vmid: u32,
        path: &'a str,
        contents: &'a [u8],
        mode: Option<&'a str>,
    ) -> BoxFuture<'a, Result<()>>;
}

/// The real seams.
pub struct SeamIo;

impl GuestIo for SeamIo {
    fn exec<'a>(&'a self, vmid: u32, argv: &'a [&'a str]) -> BoxFuture<'a, Result<ExecResult>> {
        Box::pin(async move {
            let argv0 = argv.first().copied().unwrap_or_default();
            if let Some(need) = needs_allowlist(argv0) {
                bail!("{need} (orca's lxc-exec seam refuses it; tracked in orca#769)");
            }
            let r = plugin_toolkit::lxc_exec::lxc_exec(vmid, argv).await?;
            if !r.error.is_empty() {
                if r.error.contains("refused command") {
                    bail!("needs allowlist: {argv0} ({})", r.error);
                }
                bail!("lxc-exec in CT {vmid}: {}", r.error);
            }
            Ok(ExecResult {
                success: r.success,
                exit_code: r.exit_code,
                stdout: r.stdout,
                stderr: r.stderr,
            })
        })
    }

    fn write<'a>(
        &'a self,
        vmid: u32,
        path: &'a str,
        contents: &'a [u8],
        mode: Option<&'a str>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(push(vmid, path, contents, mode))
    }
}

/// `{ok, error}` from `orca admin lxc-push`; mirrors `system::lxc_exec::LxcPushResult`.
#[derive(Deserialize)]
struct PushResult {
    ok: bool,
    #[serde(default)]
    error: String,
}

/// `sudo -n <orca> admin lxc-push` with the op on stdin. The plugin toolkit has
/// no push helper, so this mirrors its `lxc_exec` bridge; the wire shape is
/// `system::lxc_exec::LxcPushOp`.
async fn push(vmid: u32, path: &str, contents: &[u8], mode: Option<&str>) -> Result<()> {
    let orca_bin = std::env::var(plugin_toolkit::lxc_exec::ORCA_BIN_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!("writing into CT {vmid} needs orca's lxc-push seam, but ORCA_BIN is unset (not launched by the orca daemon)")
        })?;
    let payload = serde_json::json!({
        "vmid": vmid,
        "path": path,
        "contents": contents,
        "mode": mode,
        "owner": "root:root",
    })
    .to_string();
    let mut child = tokio::process::Command::new("sudo")
        .arg("-n")
        .arg(&orca_bin)
        .args(["admin", "lxc-push"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow!("spawn `sudo {orca_bin} admin lxc-push`: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| anyhow!("lxc-push: write op: {e}"))?;
        stdin
            .shutdown()
            .await
            .map_err(|e| anyhow!("lxc-push: close stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| anyhow!("wait lxc-push helper: {e}"))?;
    if !out.status.success() {
        bail!(
            "lxc-push privileged helper failed (exit {}): {}. Is the `orca admin lxc-push` sudoers grant installed on this node?",
            out.status.code().map_or("signal".into(), |c| c.to_string()),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let r: PushResult = serde_json::from_slice(&out.stdout).map_err(|e| {
        anyhow!(
            "parse lxc-push result: {e}: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        )
    })?;
    if !r.ok {
        bail!("write {path} into CT {vmid}: {}", r.error);
    }
    Ok(())
}

/// Largest file [`read_file`] returns. Paths are guest-controlled, so a read
/// is bounded by the file's `stat` size before anything is read.
pub const READ_CAP: usize = 64 * 1024;

fn missing(r: &ExecResult) -> bool {
    !r.success && r.stderr.contains("No such file")
}

/// Contents (trimmed by the seam) and on-disk size of a regular file at most
/// [`READ_CAP`] bytes, or `None` when it does not exist. Symlinks are followed:
/// the read runs inside the container, as the container's root.
async fn read_sized(io: &dyn GuestIo, vmid: u32, path: &str) -> Result<Option<(String, usize)>> {
    let st = io
        .exec(vmid, &["stat", "-L", "-c", "%F|%s", "--", path])
        .await?;
    if missing(&st) {
        return Ok(None);
    }
    if !st.success {
        bail!(
            "stat {path} in CT {vmid}: exit {:?}: {}",
            st.exit_code,
            st.stderr
        );
    }
    let (kind, size) = st.stdout.split_once('|').ok_or_else(|| {
        anyhow!(
            "stat {path} in CT {vmid}: unexpected output {:?}",
            st.stdout
        )
    })?;
    if !kind.starts_with("regular") {
        bail!("read {path} in CT {vmid}: it is a {kind}, not a regular file");
    }
    let size: usize = size
        .trim()
        .parse()
        .map_err(|e| anyhow!("stat {path} in CT {vmid}: size {size:?}: {e}"))?;
    if size > READ_CAP {
        bail!("read {path} in CT {vmid}: {size} bytes is larger than {READ_CAP}");
    }
    let cap = READ_CAP.to_string();
    let r = io.exec(vmid, &["head", "-c", &cap, "--", path]).await?;
    if missing(&r) {
        return Ok(None);
    }
    if !r.success {
        bail!(
            "read {path} in CT {vmid}: exit {:?}: {}",
            r.exit_code,
            r.stderr
        );
    }
    // The seam decodes lossily; a replacement character means the bytes were
    // not UTF-8 and the text is not the file.
    if r.stdout.contains('\u{FFFD}') {
        bail!("read {path} in CT {vmid}: not valid UTF-8");
    }
    Ok(Some((r.stdout, size)))
}

/// A file's contents (trimmed, as the seam returns them), or `None` when it
/// does not exist. Refused when larger than [`READ_CAP`], not a regular file,
/// or not UTF-8.
pub async fn read_file(io: &dyn GuestIo, vmid: u32, path: &str) -> Result<Option<String>> {
    Ok(read_sized(io, vmid, path).await?.map(|(s, _)| s))
}

/// [`read_file`], byte for byte: the seam's trim is undone when it removed
/// only a trailing newline, and refused otherwise.
pub async fn read_exact(io: &dyn GuestIo, vmid: u32, path: &str) -> Result<Option<String>> {
    match read_sized(io, vmid, path).await? {
        None => Ok(None),
        Some((s, size)) if s.len() == size => Ok(Some(s)),
        Some((s, size)) if s.len() + 1 == size => Ok(Some(s + "\n")),
        Some((s, size)) => bail!(
            "read {path} in CT {vmid}: {size} bytes on disk but {} read; the exec seam trims \
             whitespace, so it cannot be copied exactly",
            s.len()
        ),
    }
}

/// Refuse a push to `path` unless it is a regular file or absent and every
/// existing parent is a real directory. `lxc-push` writes as root on the host
/// and follows guest symlinks, so a link here would redirect the write onto
/// the host. A swap between this check and the write is closed only by core
/// writing with `O_NOFOLLOW` or from inside the container's user namespace.
pub async fn check_push_target(io: &dyn GuestIo, vmid: u32, path: &str) -> Result<()> {
    let mut paths: Vec<String> = std::path::Path::new(path)
        .ancestors()
        .skip(1)
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| !p.is_empty() && p != "/")
        .collect();
    paths.reverse();
    paths.push(path.to_string());
    let mut argv = vec!["stat", "-c", "%n|%F", "--"];
    argv.extend(paths.iter().map(String::as_str));
    let r = io.exec(vmid, &argv).await?;
    if !r.success && !r.stderr.lines().all(|l| l.contains("No such file")) {
        bail!(
            "check {path} in CT {vmid} before writing: exit {:?}: {}",
            r.exit_code,
            r.stderr
        );
    }
    for line in r.stdout.lines() {
        let Some((name, kind)) = line.split_once('|') else {
            bail!("check {path} in CT {vmid}: unexpected stat output {line:?}");
        };
        if name == path {
            if !kind.starts_with("regular") {
                bail!("refusing to write {path} in CT {vmid}: it is a {kind}, not a regular file");
            }
        } else if kind != "directory" {
            bail!("refusing to write {path} in CT {vmid}: parent {name} is a {kind}");
        }
    }
    Ok(())
}

/// [`GuestIo::write`] after [`check_push_target`].
pub async fn write_checked(
    io: &dyn GuestIo,
    vmid: u32,
    path: &str,
    contents: &[u8],
    mode: Option<&str>,
) -> Result<()> {
    check_push_target(io, vmid, path).await?;
    io.write(vmid, path, contents, mode).await
}

pub async fn exists(io: &dyn GuestIo, vmid: u32, path: &str) -> Result<bool> {
    let r = io.exec(vmid, &["ls", "-d", path]).await?;
    if r.success {
        return Ok(true);
    }
    if r.stderr.contains("No such file") {
        return Ok(false);
    }
    bail!(
        "check {path} in CT {vmid}: exit {:?}: {}",
        r.exit_code,
        r.stderr
    )
}

/// One container as `/cluster/resources` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtRef {
    pub node: String,
    pub vmid: u64,
    pub name: Option<String>,
    pub running: bool,
}

/// Find LXC `vmid` in the cluster; an id that is a VM is an error.
pub async fn find_ct(client: &generated::Client, vmid: u64) -> Result<CtRef> {
    use gtypes::GetResourcesClusterResourcesResponseItemType as Kind;
    let items = client
        .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
        .await
        .map_err(|e| anyhow!("cluster resources: {e}"))?
        .into_inner();
    let item = items
        .into_iter()
        .find(|i| i.vmid == Some(vmid as i64))
        .ok_or_else(|| anyhow!("no guest {vmid} in the cluster"))?;
    if item.type_ != Kind::Lxc {
        bail!("guest {vmid} is not an LXC container; this operation is LXC-only");
    }
    Ok(CtRef {
        node: item
            .node
            .ok_or_else(|| anyhow!("guest {vmid} reports no node"))?,
        vmid,
        name: item.name,
        running: item.status.as_deref() == Some("running"),
    })
}

/// In-container ops run `pct` on this node, so the container must live here.
pub fn require_local(ct: &CtRef, local: &str) -> Result<()> {
    if ct.node != local {
        bail!(
            "CT {} runs on node '{}' but this proxmox plugin runs on '{local}'; in-container \
             reads and writes go through `pct` on the container's own node, so run this on \
             the orca instance on '{}'",
            ct.vmid,
            ct.node,
            ct.node
        );
    }
    if !ct.running {
        bail!(
            "CT {} is not running; in-container reads and writes need it running",
            ct.vmid
        );
    }
    Ok(())
}

/// `/etc/pve/lxc` holds only this node's containers (pmxcfs links it to
/// `nodes/<this node>/lxc`), so a conf there proves the container is local even
/// when the plugin's hostname differs from its PVE node name.
pub const PVE_LXC_CONF_DIR: &str = "/etc/pve/lxc";

pub fn require_local_conf(dir: &std::path::Path, vmid: u64) -> Result<()> {
    let conf = dir.join(format!("{vmid}.conf"));
    if !conf.exists() {
        bail!(
            "CT {vmid}: {} is not on this node, so `pct` here cannot reach it; run this on \
             the orca instance on the container's node",
            conf.display()
        );
    }
    Ok(())
}

/// [`require_local`] by node name, then by the node-local conf, before any
/// in-container exec.
pub fn ensure_local(ct: &CtRef) -> Result<()> {
    require_local(ct, &crate::diagnostics::local_node())?;
    require_local_conf(std::path::Path::new(PVE_LXC_CONF_DIR), ct.vmid)
}

/// Recording fake for tests: answers `exec` from a table keyed by the joined
/// argv, records every write.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct FakeIo {
        pub replies: Vec<(String, ExecResult)>,
        pub execs: Mutex<Vec<String>>,
        pub writes: Mutex<Vec<(String, String, Option<String>)>>,
        pub served: Mutex<std::collections::HashMap<String, usize>>,
    }

    pub fn ok(stdout: &str) -> ExecResult {
        ExecResult {
            success: true,
            exit_code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    pub fn missing(path: &str) -> ExecResult {
        ExecResult {
            success: false,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: format!("cat: {path}: No such file or directory"),
        }
    }

    impl FakeIo {
        pub fn with(replies: &[(&str, ExecResult)]) -> Self {
            Self {
                replies: replies
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect(),
                ..Default::default()
            }
        }
    }

    impl GuestIo for FakeIo {
        fn exec<'a>(
            &'a self,
            _vmid: u32,
            argv: &'a [&'a str],
        ) -> BoxFuture<'a, Result<ExecResult>> {
            Box::pin(async move {
                if let Some(need) = needs_allowlist(argv[0]) {
                    bail!("{need}");
                }
                let key = argv.join(" ");
                self.execs.lock().unwrap().push(key.clone());
                let reply = |k: &str| {
                    self.replies
                        .iter()
                        .find(|(rk, _)| rk == k)
                        .map(|(_, v)| v.clone())
                };
                // A key scripted more than once answers in order, then repeats
                // its last reply.
                let scripted: Vec<&ExecResult> = self
                    .replies
                    .iter()
                    .filter(|(k, _)| *k == key)
                    .map(|(_, v)| v)
                    .collect();
                if !scripted.is_empty() {
                    let mut served = self.served.lock().unwrap();
                    let n = served.entry(key.clone()).or_default();
                    let r = scripted[(*n).min(scripted.len() - 1)].clone();
                    *n += 1;
                    return Ok(r);
                }
                // Unscripted stats answer from the scripted reads: a file with a
                // `head` reply is regular, and a push target's parents are dirs.
                match argv {
                    ["stat", "-L", "-c", "%F|%s", "--", path] => {
                        if let Some(r) = reply(&format!("head -c {READ_CAP} -- {path}")) {
                            return Ok(if r.success {
                                ok(&format!("regular file|{}", r.stdout.len()))
                            } else {
                                r
                            });
                        }
                    }
                    ["stat", "-c", "%n|%F", "--", paths @ ..] => {
                        let (target, parents) = paths.split_last().unwrap();
                        let mut lines: Vec<String> =
                            parents.iter().map(|p| format!("{p}|directory")).collect();
                        lines.push(format!("{target}|regular file"));
                        return Ok(ok(&lines.join("\n")));
                    }
                    _ => {}
                }
                Err(anyhow!("unexpected exec: {key}"))
            })
        }

        fn write<'a>(
            &'a self,
            _vmid: u32,
            path: &'a str,
            contents: &'a [u8],
            mode: Option<&'a str>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.writes.lock().unwrap().push((
                    path.to_string(),
                    String::from_utf8_lossy(contents).into_owned(),
                    mode.map(str::to_string),
                ));
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_check_uses_the_basename() {
        assert_eq!(needs_allowlist("cat"), None);
        assert_eq!(needs_allowlist("/usr/bin/apt-get"), None);
        assert_eq!(
            needs_allowlist("apk").as_deref(),
            Some("needs allowlist: apk")
        );
        assert_eq!(
            needs_allowlist("/bin/kill").as_deref(),
            Some("needs allowlist: kill")
        );
    }

    #[test]
    fn proposed_entries_are_not_already_allowed() {
        for (cmd, why) in PROPOSED_ALLOWLIST {
            assert!(needs_allowlist(cmd).is_some(), "{cmd} is already allowed");
            assert!(!why.is_empty());
        }
    }

    fn ct(node: &str, running: bool) -> CtRef {
        CtRef {
            node: node.into(),
            vmid: 116,
            name: None,
            running,
        }
    }

    #[test]
    fn remote_or_stopped_containers_are_refused() {
        assert!(require_local(&ct("hyp1", true), "hyp1").is_ok());
        let err = require_local(&ct("hyp2", true), "hyp1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("runs on node 'hyp2'"), "{err}");
        let err = require_local(&ct("hyp1", false), "hyp1")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not running"), "{err}");
    }

    #[tokio::test]
    async fn read_file_maps_missing_to_none() {
        let io = fake::FakeIo::with(&[
            ("head -c 65536 -- /a", fake::ok("x")),
            ("head -c 65536 -- /b", fake::missing("/b")),
        ]);
        assert_eq!(read_file(&io, 1, "/a").await.unwrap().as_deref(), Some("x"));
        assert_eq!(read_file(&io, 1, "/b").await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_file_refuses_big_special_or_binary_files() {
        let io = fake::FakeIo::with(&[
            ("stat -L -c %F|%s -- /big", fake::ok("regular file|70000")),
            (
                "stat -L -c %F|%s -- /dev/zero",
                fake::ok("character special file|0"),
            ),
            ("head -c 65536 -- /bin/x", fake::ok("\u{FFFD}ELF")),
        ]);
        for (path, want) in [
            ("/big", "larger than 65536"),
            ("/dev/zero", "not a regular file"),
            ("/bin/x", "not valid UTF-8"),
        ] {
            let err = read_file(&io, 1, path).await.unwrap_err().to_string();
            assert!(err.contains(want), "{path}: {err}");
        }
    }

    #[tokio::test]
    async fn read_exact_restores_a_trimmed_newline_only() {
        let io = fake::FakeIo::with(&[
            ("stat -L -c %F|%s -- /a", fake::ok("regular file|3")),
            ("head -c 65536 -- /a", fake::ok("ab")),
            ("stat -L -c %F|%s -- /b", fake::ok("regular file|5")),
            ("head -c 65536 -- /b", fake::ok("ab")),
        ]);
        assert_eq!(
            read_exact(&io, 1, "/a").await.unwrap().as_deref(),
            Some("ab\n")
        );
        assert!(read_exact(&io, 1, "/b").await.is_err());
    }

    #[tokio::test]
    async fn push_targets_refuse_symlinks_and_non_directory_parents() {
        let io = fake::FakeIo::with(&[
            (
                "stat -c %n|%F -- /etc /etc/inittab",
                fake::ok("/etc|directory\n/etc/inittab|symbolic link"),
            ),
            (
                "stat -c %n|%F -- /usr /usr/local /usr/local/bin /usr/local/bin/update",
                fake::ok("/usr|directory\n/usr/local|symbolic link\n/usr/local/bin|directory"),
            ),
            (
                "stat -c %n|%F -- /run /run/x",
                ExecResult {
                    success: false,
                    exit_code: Some(1),
                    stdout: "/run|directory".into(),
                    stderr: "stat: cannot stat '/run/x': No such file or directory".into(),
                },
            ),
        ]);
        let err = check_push_target(&io, 1, "/etc/inittab")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("it is a symbolic link"), "{err}");
        let err = check_push_target(&io, 1, "/usr/local/bin/update")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("parent /usr/local is a symbolic link"),
            "{err}"
        );
        write_checked(&io, 1, "/run/x", b"y", None).await.unwrap();
        assert_eq!(io.writes.lock().unwrap().len(), 1);
    }

    #[test]
    fn locality_needs_the_node_local_conf() {
        let dir = std::env::temp_dir().join(format!("pve-lxc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("116.conf"), "arch: amd64\n").unwrap();
        assert!(require_local_conf(&dir, 116).is_ok());
        let err = require_local_conf(&dir, 117).unwrap_err().to_string();
        assert!(err.contains("117.conf is not on this node"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
