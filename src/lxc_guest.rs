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
/// dry-run plan and refused or deferred before anything runs.
///
/// `sh` is deliberately absent: every step execs its program directly, and
/// `sh -c` would turn the allowlist into arbitrary root-in-container exec.
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
        "update",
        "`/usr/bin/update`: the app's own updater (community-scripts, or the Gitea \
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

/// A file's contents (trimmed, as the seam returns them), or `None` when it
/// does not exist.
pub async fn read_file(io: &dyn GuestIo, vmid: u32, path: &str) -> Result<Option<String>> {
    let r = io.exec(vmid, &["cat", path]).await?;
    if r.success {
        return Ok(Some(r.stdout));
    }
    if r.stderr.contains("No such file") {
        return Ok(None);
    }
    bail!(
        "read {path} in CT {vmid}: exit {:?}: {}",
        r.exit_code,
        r.stderr
    )
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
                self.replies
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| anyhow!("unexpected exec: {key}"))
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
        let io = fake::FakeIo::with(&[("cat /a", fake::ok("x")), ("cat /b", fake::missing("/b"))]);
        assert_eq!(read_file(&io, 1, "/a").await.unwrap().as_deref(), Some("x"));
        assert_eq!(read_file(&io, 1, "/b").await.unwrap(), None);
    }
}
