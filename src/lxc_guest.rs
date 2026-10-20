use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::prelude::*;

use crate::generated::{self, types as gtypes};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecResult {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

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

pub struct SeamIo;

pub fn unsupported(vmid: u64) -> anyhow::Error {
    anyhow!("CT {vmid}: {UNSUPPORTED}")
}

pub const UNSUPPORTED: &str = "unsupported: needs in-guest orca member (the PVE REST API cannot exec in or write files into an LXC)";

impl GuestIo for SeamIo {
    fn exec<'a>(&'a self, vmid: u32, _argv: &'a [&'a str]) -> BoxFuture<'a, Result<ExecResult>> {
        Box::pin(async move { bail!("CT {vmid}: {UNSUPPORTED}") })
    }

    fn write<'a>(
        &'a self,
        vmid: u32,
        _path: &'a str,
        _contents: &'a [u8],
        _mode: Option<&'a str>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { bail!("CT {vmid}: {UNSUPPORTED}") })
    }
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

/// [`read_file`], byte for byte. The seam trims both ends, so any difference
/// between the on-disk size and what was read means bytes were lost and the
/// file is refused rather than guessed at.
pub async fn read_exact(io: &dyn GuestIo, vmid: u32, path: &str) -> Result<Option<String>> {
    match read_sized(io, vmid, path).await? {
        None => Ok(None),
        Some((s, size)) if s.len() == size => Ok(Some(s)),
        Some((s, size)) => bail!(
            "read {path} in CT {vmid}: {size} bytes on disk but {} read; the exec seam trims \
             leading and trailing whitespace, so it cannot be copied exactly",
            s.len()
        ),
    }
}

/// Refuse a push to `path` unless it is a regular file or absent and every
/// existing parent is a real directory.
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
    let fail = |why: String| -> Result<()> {
        bail!(
            "check {path} in CT {vmid} before writing: {why} (exit {:?}: {})",
            r.exit_code,
            r.stderr
        )
    };
    let mut found: Vec<(&str, &str)> = Vec::new();
    for line in r.stdout.lines() {
        let Some(pair) = line.split_once('|') else {
            return fail(format!("unexpected stat output {line:?}"));
        };
        found.push(pair);
    }
    for &(name, kind) in &found {
        if name == path {
            if !kind.starts_with("regular") {
                bail!("refusing to write {path} in CT {vmid}: it is a {kind}, not a regular file");
            }
        } else if kind != "directory" {
            bail!("refusing to write {path} in CT {vmid}: parent {name} is a {kind}");
        }
    }
    // stat answers each path on stdout or with one "No such file" line on
    // stderr. Absent paths must be a suffix (a missing parent hides all below),
    // and their count must match those lines, so a stat that failed for any
    // other reason is never read as "absent".
    let present = paths
        .iter()
        .take_while(|p| found.iter().any(|(n, _)| n == p))
        .count();
    if found.len() != present {
        return fail("stat answered out of order".into());
    }
    let missing_lines = r
        .stderr
        .lines()
        .filter(|l| l.contains("No such file"))
        .count();
    let absent = paths.len() - present;
    if absent != missing_lines
        || r.stderr.lines().count() != missing_lines
        || (absent > 0) == r.success
    {
        return fail(format!("{absent} path(s) unanswered"));
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
    find_ct_opt(client, vmid)
        .await?
        .ok_or_else(|| anyhow!("no guest {vmid} in the cluster"))
}

/// [`find_ct`], with `None` when the cluster has no guest `vmid`; errors if the
/// token cannot audit that path.
pub async fn find_ct_opt(client: &generated::Client, vmid: u64) -> Result<Option<CtRef>> {
    use gtypes::GetResourcesClusterResourcesResponseItemType as Kind;
    let items = client
        .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
        .await
        .map_err(|e| anyhow!("cluster resources: {e}"))?
        .into_inner();
    let Some(item) = items.into_iter().find(|i| i.vmid == Some(vmid as i64)) else {
        // /cluster/resources silently omits guests the token cannot audit.
        let path = format!("/vms/{vmid}");
        let perms = client
            .get_permissions_access_permissions(Some(&path), None)
            .await
            .map_err(|e| anyhow!("access permissions {path}: {e}"))?
            .into_inner();
        require_audit(vmid, &perms)?;
        return Ok(None);
    };
    if item.type_ != Kind::Lxc {
        bail!("guest {vmid} is not an LXC container; this operation is LXC-only");
    }
    Ok(Some(CtRef {
        node: item
            .node
            .ok_or_else(|| anyhow!("guest {vmid} reports no node"))?,
        vmid,
        name: item.name,
        running: item.status.as_deref() == Some("running"),
    }))
}

/// `perms` is the `/access/permissions?path=/vms/{vmid}` body. A listed
/// privilege is held; its value is the propagate flag, not a grant.
fn require_audit(vmid: u64, perms: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    let path = format!("/vms/{vmid}");
    let audit = perms.get(&path).and_then(|p| p.get("VM.Audit")).is_some();
    if !audit {
        bail!(
            "guest {vmid} not listed and the token lacks VM.Audit on {path}; cannot tell whether \
             it exists"
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
    fn an_empty_listing_is_absent_only_with_vm_audit() {
        let check = |body: &str| require_audit(110, &serde_json::from_str(body).unwrap());
        let err = check(r#"{"/vms/110":{"VM.Console":1}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("lacks VM.Audit"), "{err}");
        assert!(check("{}").is_err());
        assert!(check(r#"{"/vms/110":{"VM.Audit":0}}"#).is_ok());
        assert!(check(r#"{"/vms/110":{"VM.Audit":1}}"#).is_ok());
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
    async fn read_exact_refuses_any_trimmed_byte() {
        let io = fake::FakeIo::with(&[
            ("stat -L -c %F|%s -- /a", fake::ok("regular file|3")),
            ("head -c 65536 -- /a", fake::ok("ab")),
            ("stat -L -c %F|%s -- /b", fake::ok("regular file|5")),
            ("head -c 65536 -- /b", fake::ok("ab")),
        ]);
        assert!(
            read_exact(&io, 1, "/a").await.is_err(),
            "a trimmed byte is never guessed"
        );
        assert!(read_exact(&io, 1, "/b").await.is_err());
        let exact = fake::FakeIo::with(&[("head -c 65536 -- /c", fake::ok("ab"))]);
        assert_eq!(
            read_exact(&exact, 1, "/c").await.unwrap().as_deref(),
            Some("ab")
        );
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

    #[tokio::test]
    async fn a_stat_that_failed_otherwise_is_not_read_as_absent() {
        let failed = |stdout: &str, stderr: &str| ExecResult {
            success: false,
            exit_code: Some(1),
            stdout: stdout.into(),
            stderr: stderr.into(),
        };
        let io = fake::FakeIo::with(&[
            ("stat -c %n|%F -- /run /run/a", failed("", "")),
            (
                "stat -c %n|%F -- /run /run/b",
                failed("", "Failed to exec stat: permission denied"),
            ),
            (
                "stat -c %n|%F -- /run /run/c",
                failed("", "stat: '/run/c': No such file or directory"),
            ),
        ]);
        for p in ["/run/a", "/run/b", "/run/c"] {
            let err = check_push_target(&io, 1, p).await.unwrap_err().to_string();
            assert!(err.contains("unanswered"), "{p}: {err}");
        }
        assert!(io.writes.lock().unwrap().is_empty());
    }
}
