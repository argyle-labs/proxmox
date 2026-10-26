use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::prelude::*;

use crate::responses::{ResourceType, cluster_resources};

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

pub type ToolCall = fn(&str, serde_json::Value) -> Result<serde_json::Value>;

pub const EXEC_TIMEOUT_MS: u64 = 300_000;
pub const UPDATE_TIMEOUT_MS: u64 = 3_600_000;
const LONG_RUNNING: &[&str] = &["/sbin/apk", "apk", "/usr/bin/update"];

pub struct SeamIo {
    pub node: String,
    pub call: ToolCall,
}

pub fn unsupported(vmid: u64) -> anyhow::Error {
    anyhow!("CT {vmid}: {UNSUPPORTED}")
}

pub const UNSUPPORTED: &str = "unsupported: needs in-guest orca member (the PVE REST API cannot exec in or write files into an LXC)";

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct ExecOutput {
    exit_code: Option<i64>,
    stdout: String,
    stderr: String,
    timed_out: bool,
}

fn timeout_ms(argv: &[&str]) -> u64 {
    match argv.first() {
        Some(p) if LONG_RUNNING.contains(p) => UPDATE_TIMEOUT_MS,
        _ => EXEC_TIMEOUT_MS,
    }
}

impl SeamIo {
    pub fn for_ct(endpoint: &str, ctid: u64) -> Result<Self> {
        Ok(Self {
            node: find_ct(endpoint, ctid)?.node,
            call: plugin_toolkit::tool_call::call_json,
        })
    }
}

impl GuestIo for SeamIo {
    fn exec<'a>(&'a self, vmid: u32, argv: &'a [&'a str]) -> BoxFuture<'a, Result<ExecResult>> {
        Box::pin(async move {
            let out = (self.call)(
                "guest.exec",
                json!({
                    "id": vmid.to_string(),
                    "argv": argv,
                    "node": self.node,
                    "timeoutMs": timeout_ms(argv),
                }),
            )
            .with_context(|| format!("guest.exec in CT {vmid} on {}", self.node))?;
            let out: ExecOutput = serde_json::from_value(out)
                .map_err(|e| anyhow!("guest.exec in CT {vmid}: unexpected reply: {e}"))?;
            if out.timed_out {
                bail!(
                    "CT {vmid}: `{}` did not finish within {}s",
                    argv.join(" "),
                    timeout_ms(argv) / 1000
                );
            }
            Ok(ExecResult {
                success: out.exit_code == Some(0),
                exit_code: out.exit_code.and_then(|c| i32::try_from(c).ok()),
                stdout: out.stdout,
                stderr: out.stderr,
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
        Box::pin(async move {
            let contents = std::str::from_utf8(contents)
                .map_err(|_| anyhow!("write {path} in CT {vmid}: contents are not UTF-8"))?;
            (self.call)(
                "guest.write_file",
                json!({
                    "id": vmid.to_string(),
                    "path": path,
                    "contents": contents,
                    "mode": mode,
                    "node": self.node,
                }),
            )
            .with_context(|| format!("guest.write_file {path} in CT {vmid} on {}", self.node))?;
            Ok(())
        })
    }
}

pub const READ_CAP: usize = 64 * 1024;

fn missing(r: &ExecResult) -> bool {
    !r.success && r.stderr.contains("No such file")
}

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
    if r.stdout.contains('\u{FFFD}') {
        bail!("read {path} in CT {vmid}: not valid UTF-8");
    }
    Ok(Some((r.stdout, size)))
}

pub async fn read_file(io: &dyn GuestIo, vmid: u32, path: &str) -> Result<Option<String>> {
    Ok(read_sized(io, vmid, path).await?.map(|(s, _)| s))
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtRef {
    pub node: String,
    pub vmid: u64,
    pub name: Option<String>,
    pub running: bool,
}

pub fn find_ct(endpoint: &str, vmid: u64) -> Result<CtRef> {
    find_ct_opt(endpoint, vmid)?.ok_or_else(|| anyhow!("no guest {vmid} in the cluster"))
}

pub fn find_ct_opt(endpoint: &str, vmid: u64) -> Result<Option<CtRef>> {
    let items = cluster_resources(endpoint, Some("vm"))?;
    let Some(item) = items.into_iter().find(|i| i.vmid == Some(vmid as i64)) else {
        let free = plugin_toolkit::api::call::<serde_json::Value>(
            "proxmox.get_nextid_cluster_nextid",
            endpoint,
            json!({ "vmid": vmid }),
        );
        require_free(vmid, free)?;
        return Ok(None);
    };
    if item.type_ != ResourceType::Lxc {
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

fn require_free(vmid: u64, nextid: Result<serde_json::Value>) -> Result<()> {
    let Err(e) = nextid else { return Ok(()) };
    if format!("{e:#}").contains(&format!("VM {vmid} already exists")) {
        bail!(
            "guest {vmid} not listed but its id is taken ({e:#}); the token lacks VM.Audit on \
             /vms/{vmid}"
        );
    }
    Err(e.context(format!("checking whether guest id {vmid} is free")))
}

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

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    thread_local! {
        static SENT: std::cell::RefCell<Vec<(String, serde_json::Value)>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn record(tool: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        SENT.with(|s| s.borrow_mut().push((tool.to_string(), args)));
        Ok(json!({ "exitCode": 0, "stdout": "ok\n", "stderr": "" }))
    }

    fn sent() -> Vec<(String, serde_json::Value)> {
        SENT.with(|s| s.borrow_mut().drain(..).collect())
    }

    fn seam(call: ToolCall) -> SeamIo {
        SeamIo {
            node: "thor".into(),
            call,
        }
    }

    #[test]
    fn exec_routes_through_guest_exec_on_the_cts_node() {
        let r = rt()
            .block_on(seam(record).exec(120, &["/sbin/apk", "upgrade"]))
            .unwrap();
        assert!(r.success);
        assert_eq!(r.exit_code, Some(0));
        assert_eq!(r.stdout, "ok\n");
        assert_eq!(
            sent(),
            vec![(
                "guest.exec".to_string(),
                json!({
                    "id": "120",
                    "argv": ["/sbin/apk", "upgrade"],
                    "node": "thor",
                    "timeoutMs": UPDATE_TIMEOUT_MS,
                })
            )]
        );
    }

    #[test]
    fn short_commands_keep_the_default_timeout() {
        rt().block_on(seam(record).exec(7, &["stat", "/etc/os-release"]))
            .unwrap();
        assert_eq!(sent()[0].1["timeoutMs"], json!(EXEC_TIMEOUT_MS));
        rt().block_on(seam(record).exec(7, &["/usr/bin/update"]))
            .unwrap();
        assert_eq!(sent()[0].1["timeoutMs"], json!(UPDATE_TIMEOUT_MS));
    }

    #[test]
    fn a_nonzero_exit_is_a_failed_result() {
        fn failed(_: &str, _: serde_json::Value) -> Result<serde_json::Value> {
            Ok(json!({ "exitCode": 1, "stdout": "", "stderr": "No such file" }))
        }
        let r = rt()
            .block_on(seam(failed).exec(7, &["ls", "-d", "/x"]))
            .unwrap();
        assert!(!r.success);
        assert_eq!(r.exit_code, Some(1));
        assert_eq!(r.stderr, "No such file");
    }

    #[test]
    fn a_timeout_is_an_error() {
        fn timed_out(_: &str, _: serde_json::Value) -> Result<serde_json::Value> {
            Ok(json!({ "stdout": "", "stderr": "", "timedOut": true }))
        }
        let err = rt()
            .block_on(seam(timed_out).exec(7, &["/sbin/apk", "upgrade"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not finish within 3600s"), "{err}");
    }

    #[test]
    fn a_refused_call_names_the_ct_and_node() {
        fn refused(_: &str, _: serde_json::Value) -> Result<serde_json::Value> {
            Err(anyhow!("refused command 'curl'"))
        }
        let err = format!(
            "{:#}",
            rt().block_on(seam(refused).exec(7, &["curl"])).unwrap_err()
        );
        assert!(err.contains("CT 7 on thor"), "{err}");
        assert!(err.contains("refused command"), "{err}");
    }

    #[test]
    fn write_routes_through_guest_write_file() {
        rt().block_on(seam(record).write(120, "/run/orca-update-backup.json", b"{}", Some("0644")))
            .unwrap();
        assert_eq!(
            sent(),
            vec![(
                "guest.write_file".to_string(),
                json!({
                    "id": "120",
                    "path": "/run/orca-update-backup.json",
                    "contents": "{}",
                    "mode": "0644",
                    "node": "thor",
                })
            )]
        );
    }

    #[test]
    fn write_refuses_non_utf8_contents() {
        let err = rt()
            .block_on(seam(record).write(7, "/etc/x", &[0xff], None))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not UTF-8"), "{err}");
        assert!(sent().is_empty());
    }

    #[test]
    fn an_unlisted_guest_is_absent_only_when_its_id_is_free() {
        assert!(require_free(110, Ok(serde_json::json!(110))).is_ok());
        let err = require_free(
            110,
            Err(anyhow!(
                "upstream HTTP 400: VM 110 already exists on node 'a'"
            )),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("lacks VM.Audit"), "{err}");
    }

    #[test]
    fn other_nextid_errors_pass_through() {
        for raw in [
            "upstream HTTP 401",
            "upstream HTTP 500",
            "connection refused",
            "upstream HTTP 400: bad param",
        ] {
            let err = format!("{:#}", require_free(110, Err(anyhow!(raw))).unwrap_err());
            assert!(!err.contains("VM.Audit"), "{err}");
            assert!(err.contains(raw), "{err}");
            assert!(err.contains("guest id 110 is free"), "{err}");
        }
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
