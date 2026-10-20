//! Copy a file out of a guest to a host directory (`proxmox.guest.file_pull`).
//!
//! LXC: PVE has no API to read a container file, so the copy runs as root
//! through orca's `admin plugin-apply` seam ([`OP_FILE_PULL`]). The source must
//! sit under [`ALLOWED_GUEST_DIRS`] and is resolved from the container's own
//! root (`/proc/<init pid>/root`, which sees its `mpN` mounts) one component at
//! a time with `O_NOFOLLOW`, so a symlink in the guest can never point the read
//! at a host path. Only regular files on non-pseudo filesystems are opened.
//!
//! The destination directory is walked the same way from `/`, must be owned by
//! the invoking (non-root) user and not group/world-writable, and the file is
//! created there by `openat` as
//! `<dest_name>.partial` (`O_EXCL`), chowned to the directory's owner, hashed
//! while copying, fsynced and renamed into place without replacing. Any failure unlinks the
//! partial.
//!
//! VM: the PVE guest-agent `file-read` returns at most 16 MiB in one JSON
//! string with no offset parameter, so it can neither be chunked nor carry
//! binary data intact; VMs are refused.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use anyhow::ensure;
use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::contract::plan::PlannedChange;
use plugin_toolkit::prelude::*;
use plugin_toolkit::privileged::PrivilegedOps;
use sha2::{Digest, Sha256};

use crate::execute::{self, Change};

/// Privileged-seam op name (`<plugin> --privileged-op`).
pub const OP_FILE_PULL: &str = "guest.file_pull";
const PROVIDER: &str = "proxmox";
const TOOL: &str = "proxmox.guest.file_pull";
const PARTIAL_SUFFIX: &str = ".partial";
const COPY_BUF: usize = 1024 * 1024;
/// Guest directories a pull may read. Fixed in the binary because the payload
/// comes from the unprivileged side of the seam.
const ALLOWED_GUEST_DIRS: &[&str] = &["/var/lib/gitea/backups"];
/// Headroom left free on the destination filesystem after the copy.
const FREE_MARGIN: u64 = 1 << 30;
const COPY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GuestKind {
    Lxc,
    Vm,
}

/// Payload of [`OP_FILE_PULL`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePullOp {
    pub vmid: u64,
    pub kind: GuestKind,
    pub guest_path: String,
    pub dest_dir: String,
    pub dest_name: String,
    pub dry_run: bool,
}

/// What the root side reports: the dry-run sizing, or the pulled file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FilePulled {
    pub path: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Free bytes in `dest_dir`; reported on a dry run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_bytes: Option<u64>,
}

impl FilePullOp {
    fn validate(&self) -> Result<()> {
        ensure!(self.vmid >= 100, "vmid {} is not a guest id", self.vmid);
        if self.kind == GuestKind::Vm {
            bail!(
                "VM {}: the PVE guest-agent file-read returns at most 16 MiB as a JSON string \
                 with no offset, so it cannot copy large or binary files",
                self.vmid
            );
        }
        check_abs("guest_path", &self.guest_path)?;
        check_abs("dest_dir", &self.dest_dir)?;
        ensure!(
            ALLOWED_GUEST_DIRS.iter().any(|d| {
                self.guest_path
                    .strip_prefix(d)
                    .is_some_and(|rest| rest.len() > 1 && rest.starts_with('/'))
            }),
            "guest_path '{}' is outside the readable guest directories {ALLOWED_GUEST_DIRS:?}",
            self.guest_path
        );
        let n = &self.dest_name;
        ensure!(
            !n.is_empty() && n != "." && n != ".." && !n.contains(['/', '\0']),
            "dest_name '{n}' must be a single file name"
        );
        Ok(())
    }

    fn dest_path(&self) -> String {
        format!("{}/{}", self.dest_dir.trim_end_matches('/'), self.dest_name)
    }
}

/// Absolute, normalized (no empty, `.` or `..` components), no NUL.
fn check_abs(what: &str, p: &str) -> Result<()> {
    ensure!(!p.contains('\0'), "{what} contains NUL");
    let rest = p
        .strip_prefix('/')
        .ok_or_else(|| anyhow!("{what} '{p}' is not absolute"))?;
    if rest.is_empty() {
        return Ok(());
    }
    ensure!(
        !rest
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == ".."),
        "{what} '{p}' is not a normalized absolute path"
    );
    Ok(())
}

// ── Tool surface ────────────────────────────────────────────────────────────

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct FilePullArgs {
    /// Guest id; the guest must live on this plugin's node.
    #[arg(long)]
    pub vmid: u64,
    /// `lxc` or `vm`.
    #[arg(long, value_parser = parse_kind)]
    pub kind: GuestKind,
    /// Absolute file path inside the guest.
    #[arg(long)]
    pub guest_path: String,
    /// Absolute host directory, owned by the orca service user.
    #[arg(long)]
    pub dest_dir: String,
    /// File name to create in `dest_dir`; an existing file is refused.
    #[arg(long)]
    pub dest_name: String,
    /// Apply. Omitted, reports the file size and destination free space.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

fn parse_kind(s: &str) -> Result<GuestKind, String> {
    match s {
        "lxc" => Ok(GuestKind::Lxc),
        "vm" => Ok(GuestKind::Vm),
        other => Err(format!("kind '{other}': expected lxc or vm")),
    }
}

impl FilePullArgs {
    fn op(&self, dry_run: bool) -> FilePullOp {
        FilePullOp {
            vmid: self.vmid,
            kind: self.kind,
            guest_path: self.guest_path.clone(),
            dest_dir: self.dest_dir.clone(),
            dest_name: self.dest_name.clone(),
            dry_run,
        }
    }
}

pub async fn file_pull(
    args: &FilePullArgs,
    caller: Option<&CallerIdentity>,
) -> Result<Change<FilePulled>> {
    let op = args.op(!args.execute);
    op.validate()?;
    if !args.execute {
        let sized = privileged(&op).await?;
        let summary = format!(
            "copy {} from CT {} to {} ({} bytes; {} bytes free)",
            op.guest_path,
            op.vmid,
            sized.path,
            sized.size,
            sized.free_bytes.unwrap_or_default()
        );
        let change = PlannedChange::new(&sized.path, "create")
            .with_detail(format!("{} bytes from CT {}", sized.size, op.vmid));
        return Ok(Change::Plan(execute::plan(
            TOOL,
            args,
            summary,
            vec![change],
        )?));
    }
    execute::authorize_execute(TOOL, caller)?;
    Ok(Change::Applied(privileged(&op).await?))
}

async fn privileged(op: &FilePullOp) -> Result<FilePulled> {
    let detail = plugin_toolkit::privileged::apply(PROVIDER, OP_FILE_PULL, Some(op))
        .await
        .with_context(|| format!("{OP_FILE_PULL} via orca's privileged seam"))?;
    plugin_toolkit::serde_json::from_str(&detail)
        .with_context(|| format!("{OP_FILE_PULL}: unexpected reply {detail:?}"))
}

/// [MUTATES STATE] Copy one file out of an LXC guest on this node into a host
/// directory, returning its size and sha256. Without `execute` reports the
/// file size and destination free space, and refuses if it would not fit.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.file_pull",
    role = "admin",
    execute_gated = false,
    reaches = ["privileged.apply"]
)]
async fn proxmox_guest_file_pull(args: FilePullArgs, ctx: &ToolCtx) -> Result<Change<FilePulled>> {
    execute::require_admin(TOOL, ctx.caller().as_ref())?;
    file_pull(&args, ctx.caller().as_ref()).await
}

/// Add [`OP_FILE_PULL`] to the plugin's privileged op set.
pub fn register(ops: PrivilegedOps) -> PrivilegedOps {
    ops.op(OP_FILE_PULL, |op: FilePullOp| async move {
        let caller = plugin_toolkit::privileged::caller_uid()
            .ok_or_else(|| anyhow!("{OP_FILE_PULL}: no caller uid from the seam"))?;
        let root = lxc_root(op.vmid)?;
        let out = root_file_pull(root, &op, caller)?;
        Ok(plugin_toolkit::serde_json::to_string(&out)?)
    })
}

// ── Root side ───────────────────────────────────────────────────────────────

/// Root directory of a running CT on this node, opened through a `/proc/<pid>`
/// dirfd so a recycled pid cannot redirect it.
fn lxc_root(vmid: u64) -> Result<OwnedFd> {
    ensure!(
        Path::new(&format!("/etc/pve/lxc/{vmid}.conf")).exists(),
        "CT {vmid} is not on this node"
    );
    let pid = ct_init_pid(vmid)?;
    let proc_dir = open_path(&format!("/proc/{pid}"), DIR_FLAGS)?;
    let mut cgroup = String::new();
    File::from(openat(
        proc_dir.as_raw_fd(),
        "cgroup",
        libc::O_RDONLY | libc::O_CLOEXEC,
        0,
    )?)
    .read_to_string(&mut cgroup)
    .context("read cgroup")?;
    ensure!(
        cgroup_in_ct(&cgroup, vmid),
        "pid {pid} is not in CT {vmid}'s cgroup"
    );
    let host_mnt = readlink_at(libc::AT_FDCWD, "/proc/1/ns/mnt")?;
    ensure!(
        readlink_at(proc_dir.as_raw_fd(), "ns/mnt")? != host_mnt,
        "pid {pid} shares the host mount namespace"
    );
    openat(
        proc_dir.as_raw_fd(),
        "root",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
    .with_context(|| format!("open CT {vmid} root"))
}

/// Init pid of a running CT from its cgroup v2 tree. PVE 8 places a systemd
/// guest's init in `ns/init.scope`, other guests' in `ns`.
fn ct_init_pid(vmid: u64) -> Result<u32> {
    let base = format!("/sys/fs/cgroup/lxc/{vmid}");
    for dir in [format!("{base}/ns/init.scope"), format!("{base}/ns"), base] {
        let procs = match std::fs::read_to_string(format!("{dir}/cgroup.procs")) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(anyhow!("read {dir}/cgroup.procs: {e}")),
        };
        if let Some(pid) = first_pid(&procs) {
            return Ok(pid);
        }
    }
    bail!("CT {vmid} is not running; start it to pull files")
}

fn first_pid(procs: &str) -> Option<u32> {
    procs.lines().next()?.trim().parse().ok()
}

fn cgroup_in_ct(cgroup: &str, vmid: u64) -> bool {
    let ct = format!("/lxc/{vmid}");
    cgroup.lines().any(|l| {
        l.splitn(3, ':')
            .nth(2)
            .and_then(|p| p.strip_prefix(&ct))
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// Pull `op.guest_path` from the guest tree at `guest_root` into `op.dest_dir`,
/// authorized for `caller` (uid). On a dry run, only sizes.
fn root_file_pull(guest_root: OwnedFd, op: &FilePullOp, caller: u32) -> Result<FilePulled> {
    op.validate()?;
    ensure!(
        caller != 0,
        "{OP_FILE_PULL}: refusing a pull on behalf of root"
    );
    let src = open_beneath(guest_root, &op.guest_path)?;
    let before = fstat(src.as_raw_fd())?;
    let size = u64::try_from(before.st_size)?;

    let dir = open_dest_dir(&op.dest_dir, caller)?;
    let dst = fstat(dir.as_raw_fd())?;
    ensure!(
        dst.st_uid == caller,
        "{} is owned by uid {}, not the caller (uid {caller})",
        op.dest_dir,
        dst.st_uid
    );
    ensure!(
        dst.st_mode & 0o022 == 0,
        "{} is group- or world-writable",
        op.dest_dir
    );
    let free = free_bytes(dir.as_raw_fd())?;
    let path = op.dest_path();
    ensure!(
        size.saturating_add(FREE_MARGIN) <= free,
        "{path}: {size} bytes plus {FREE_MARGIN} bytes headroom needed but {free} bytes free in {}",
        op.dest_dir
    );
    ensure!(
        !exists_at(dir.as_raw_fd(), &op.dest_name)?,
        "{path} already exists"
    );
    if op.dry_run {
        return Ok(FilePulled {
            path,
            size,
            sha256: None,
            free_bytes: Some(free),
        });
    }

    let partial = format!("{}{PARTIAL_SUFFIX}", op.dest_name);
    let result = write_partial(&dir, &partial, src, &before, (dst.st_uid, dst.st_gid)).and_then(
        |(n, sha)| {
            rename_noreplace(dir.as_raw_fd(), &partial, &op.dest_name)?;
            sync_fd(dir.as_raw_fd())?;
            Ok((n, sha))
        },
    );
    match result {
        Ok((size, sha)) => Ok(FilePulled {
            path,
            size,
            sha256: Some(sha),
            free_bytes: None,
        }),
        Err(e) => {
            if let Err(u) = unlink_at(dir.as_raw_fd(), &partial)
                && u.kind() != std::io::ErrorKind::NotFound
            {
                return Err(e.context(format!("and removing {partial} failed: {u}")));
            }
            Err(e)
        }
    }
}

/// Copy the first `before.st_size` bytes of `src` into a fresh `dir/partial`,
/// returning bytes copied and sha256. Fails if the source changed or grew.
fn write_partial(
    dir: &OwnedFd,
    partial: &str,
    src: OwnedFd,
    before: &libc::stat,
    owner: (u32, u32),
) -> Result<(u64, String)> {
    let size = u64::try_from(before.st_size)?;
    // A stale partial from an earlier run is ours to replace; unlinkat never
    // follows a link.
    if let Err(e) = unlink_at(dir.as_raw_fd(), partial)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return Err(anyhow!("remove stale {partial}: {e}"));
    }
    let out = openat(
        dir.as_raw_fd(),
        partial,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .with_context(|| format!("create {partial}"))?;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        // SAFETY: `out` is an open fd owned for the duration of the call.
        if unsafe { libc::fchown(out.as_raw_fd(), owner.0, owner.1) } != 0 {
            bail!("chown {partial}: {}", std::io::Error::last_os_error());
        }
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let shown = partial.to_owned();
    let (before_size, before_mtime, before_mtime_nsec) =
        (before.st_size, before.st_mtime, before.st_mtime_nsec);
    // A read stuck in the kernel never returns to check a deadline, so the
    // caller enforces it; a timed-out thread is abandoned with its fds.
    std::thread::spawn(move || {
        let _ignored = tx.send(copy(File::from(src), File::from(out), size, &shown));
    });
    let (out, n, hash, grew, after) = match rx.recv_timeout(COPY_TIMEOUT) {
        Ok(r) => r?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            bail!("copy exceeded {}s", COPY_TIMEOUT.as_secs())
        }
        Err(e) => bail!("copy thread: {e}"),
    };
    ensure!(
        !grew
            && n == size
            && after.st_size == before_size
            && after.st_mtime == before_mtime
            && after.st_mtime_nsec == before_mtime_nsec,
        "guest file changed while it was copied; retry once it is complete"
    );
    out.sync_all().with_context(|| format!("fsync {partial}"))?;
    Ok((n, hash))
}

/// Copy up to `size` bytes of `src` into `out`, returning `out`, bytes copied,
/// sha256, whether `src` had more, and its stat afterwards.
fn copy(
    mut src: File,
    mut out: File,
    size: u64,
    partial: &str,
) -> Result<(File, u64, String, bool, libc::stat)> {
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; COPY_BUF];
    let mut n: u64 = 0;
    {
        let mut limited = (&mut src).take(size);
        loop {
            let r = limited.read(&mut buf).context("read guest file")?;
            if r == 0 {
                break;
            }
            hash.update(&buf[..r]);
            out.write_all(&buf[..r])
                .with_context(|| format!("write {partial}"))?;
            n += r as u64;
        }
    }
    let grew = src.read(&mut buf[..1]).context("read guest file")? != 0;
    let after = fstat(src.as_raw_fd())?;
    let sha = plugin_toolkit::hash::hex_encode(&hash.finalize());
    Ok((out, n, sha, grew, after))
}

// ── fd helpers ──────────────────────────────────────────────────────────────

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| anyhow!("path {s:?} contains NUL"))
}

fn openat(dir: RawFd, name: &str, flags: libc::c_int, mode: libc::c_uint) -> Result<OwnedFd> {
    let c = cstr(name)?;
    // SAFETY: `c` is a valid NUL-terminated string for the call's duration.
    let fd = unsafe { libc::openat(dir, c.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `fd` was just returned open and is owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_path(path: &str, flags: libc::c_int) -> Result<OwnedFd> {
    openat(libc::AT_FDCWD, path, flags, 0).with_context(|| format!("open {path}"))
}

fn readlink_at(dir: RawFd, name: &str) -> Result<Vec<u8>> {
    let c = cstr(name)?;
    let mut buf = vec![0u8; 256];
    // SAFETY: valid C string and a writable buffer of the given length.
    let n = unsafe { libc::readlinkat(dir, c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        bail!("readlink {name}: {}", std::io::Error::last_os_error());
    }
    buf.truncate(n.unsigned_abs());
    Ok(buf)
}

const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Kernel pseudo-filesystems whose files are not data to copy.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const REFUSED_FS: &[(i64, &str)] = &[
    (0x9fa0, "procfs"),
    (0x6265_6572, "sysfs"),
    (0x6462_6720, "debugfs"),
    (0x7363_6673, "securityfs"),
    (0x0027_e0eb, "cgroup"),
    (0x6367_7270, "cgroup2"),
    (0x7472_6163, "tracefs"),
    (0xcafe_4a11, "bpf"),
    (0x6573_5546, "fuse"),
    (0x6265_6570, "configfs"),
    (0xde5e_81e4, "efivarfs"),
    (0x6165_676c, "pstore"),
];

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn refused_fs(magic: i64) -> Option<&'static str> {
    REFUSED_FS
        .iter()
        .find(|(m, _)| *m == magic)
        .map(|(_, n)| *n)
}

#[cfg(target_os = "linux")]
fn check_fs(fd: RawFd, shown: &str) -> Result<()> {
    let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `st` is writable for one `statfs`; it is read only on success.
    if unsafe { libc::fstatfs(fd, st.as_mut_ptr()) } != 0 {
        bail!("statfs {shown}: {}", std::io::Error::last_os_error());
    }
    // SAFETY: fstatfs succeeded.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { st.assume_init() }.f_type as i64;
    if let Some(name) = refused_fs(magic) {
        bail!("{shown} is on {name}, which is refused");
    }
    Ok(())
}

// The pseudo-filesystems above are Linux-only.
#[cfg(not(target_os = "linux"))]
fn check_fs(_fd: RawFd, _shown: &str) -> Result<()> {
    Ok(())
}

/// Walk `components` beneath `start` refusing any symlink or pseudo-filesystem;
/// `each` sees every directory, `start` included.
fn walk(
    start: OwnedFd,
    components: &[&str],
    shown: &str,
    each: &dyn Fn(&OwnedFd) -> Result<()>,
) -> Result<OwnedFd> {
    check_fs(start.as_raw_fd(), shown)?;
    each(&start)?;
    let mut cur = start;
    for c in components {
        cur = openat(cur.as_raw_fd(), c, DIR_FLAGS, 0)
            .with_context(|| format!("open directory '{c}' of {shown} (symlinks are refused)"))?;
        check_fs(cur.as_raw_fd(), shown)?;
        each(&cur)?;
    }
    Ok(cur)
}

fn components(p: &str) -> Vec<&str> {
    p.split('/').filter(|c| !c.is_empty()).collect()
}

/// Open directory `p` from `/` with no symlink on the path and every
/// component searchable by `caller`. Searchability counts owner and world bits
/// only; group membership is not resolved, so a group-only path is refused.
fn open_dest_dir(p: &str, caller: u32) -> Result<OwnedFd> {
    let root = open_path("/", DIR_FLAGS)?;
    walk(root, &components(p), p, &|fd| {
        let st = fstat(fd.as_raw_fd())?;
        let searchable = if st.st_uid == caller {
            st.st_mode & 0o100 != 0
        } else {
            st.st_mode & 0o001 != 0
        };
        ensure!(
            searchable,
            "a directory on {p} is not searchable by uid {caller}"
        );
        Ok(())
    })
}

/// Open regular file `p` beneath `root` with no symlink at or below it.
fn open_beneath(root: OwnedFd, p: &str) -> Result<OwnedFd> {
    let parts = components(p);
    let (name, dirs) = parts
        .split_last()
        .ok_or_else(|| anyhow!("guest_path '{p}' names no file"))?;
    let dir = walk(root, dirs, p, &|_| Ok(()))?;
    let f = open_regular(&dir, name, p)?;
    check_fs(f.as_raw_fd(), p)?;
    Ok(f)
}

/// Open `name` for reading only once it is known to be a regular file, so a
/// device or FIFO is never opened.
#[cfg(target_os = "linux")]
fn open_regular(dir: &OwnedFd, name: &str, shown: &str) -> Result<OwnedFd> {
    let handle = openat(
        dir.as_raw_fd(),
        name,
        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .with_context(|| format!("open {shown} (symlinks are refused)"))?;
    let st = fstat(handle.as_raw_fd())?;
    ensure!(is_reg(&st), "{shown} is not a regular file");
    let f = open_path(
        &format!("/proc/self/fd/{}", handle.as_raw_fd()),
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
    )?;
    same_inode(&st, &fstat(f.as_raw_fd())?, shown)?;
    Ok(f)
}

// No O_PATH: stat first, then open non-blocking and confirm the inode. A swap
// between the two can still open a device; only tests run this path.
#[cfg(not(target_os = "linux"))]
fn open_regular(dir: &OwnedFd, name: &str, shown: &str) -> Result<OwnedFd> {
    let c = cstr(name)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid C string and a writable `stat` buffer.
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        bail!("stat {shown}: {}", std::io::Error::last_os_error());
    }
    // SAFETY: fstatat succeeded.
    let st = unsafe { st.assume_init() };
    ensure!(is_reg(&st), "{shown} is not a regular file");
    let f = openat(
        dir.as_raw_fd(),
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )
    .with_context(|| format!("open {shown} (symlinks are refused)"))?;
    same_inode(&st, &fstat(f.as_raw_fd())?, shown)?;
    Ok(f)
}

fn same_inode(a: &libc::stat, b: &libc::stat, shown: &str) -> Result<()> {
    ensure!(
        a.st_dev == b.st_dev && a.st_ino == b.st_ino,
        "{shown} was replaced while it was opened"
    );
    Ok(())
}

fn fstat(fd: RawFd) -> Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is writable for one `stat`; it is read only on success.
    if unsafe { libc::fstat(fd, st.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fstat succeeded, so `st` is initialized.
    Ok(unsafe { st.assume_init() })
}

fn is_reg(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFREG
}

fn exists_at(dir: RawFd, name: &str) -> Result<bool> {
    let c = cstr(name)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid C string and a writable `stat` buffer.
    if unsafe { libc::fstatat(dir, c.as_ptr(), st.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(anyhow!("stat {name}: {e}"))
    }
}

// statvfs field widths differ by platform (u32 on macOS, u64 on Linux).
#[allow(clippy::useless_conversion)]
fn free_bytes(fd: RawFd) -> Result<u64> {
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `st` is writable for one `statvfs`; it is read only on success.
    if unsafe { libc::fstatvfs(fd, st.as_mut_ptr()) } != 0 {
        return Err(anyhow!("statvfs: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: fstatvfs succeeded.
    let st = unsafe { st.assume_init() };
    Ok(u64::from(st.f_bavail).saturating_mul(u64::from(st.f_frsize)))
}

/// Rename within `dir`, failing if `to` exists.
fn rename_noreplace(dir: RawFd, from: &str, to: &str) -> Result<()> {
    let (f, t) = (cstr(from)?, cstr(to)?);
    // Raw syscall: musl's libc binding has no renameat2.
    #[cfg(target_os = "linux")]
    // SAFETY: valid C strings for the call's duration.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            dir,
            f.as_ptr(),
            dir,
            t.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(not(target_os = "linux"))]
    // SAFETY: valid C strings for the call's duration.
    let rc = unsafe { libc::renameatx_np(dir, f.as_ptr(), dir, t.as_ptr(), libc::RENAME_EXCL) };
    if rc != 0 {
        bail!("rename {from} -> {to}: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn unlink_at(dir: RawFd, name: &str) -> std::io::Result<()> {
    let c = CString::new(name).map_err(std::io::Error::other)?;
    // SAFETY: valid C string for the call's duration.
    if unsafe { libc::unlinkat(dir, c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn sync_fd(fd: RawFd) -> Result<()> {
    // SAFETY: `fd` is open for the call's duration.
    if unsafe { libc::fsync(fd) } != 0 {
        bail!("fsync directory: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(std::path::PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ignored = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp(tag: &str) -> Tmp {
        // World-searchable, so a walk on behalf of another uid reaches the
        // ownership check (macOS's per-user temp_dir is 0700).
        let base = Path::new("/tmp").canonicalize().unwrap();
        let d = base.join(format!(
            "proxmox-file-pull-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ignored = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }

    /// Non-root caller uid: the current user, or a fixed uid when the tests
    /// run as root (CI), since the guard refuses pulls on behalf of root.
    fn uid() -> u32 {
        // SAFETY: getuid has no preconditions.
        match unsafe { libc::getuid() } {
            0 => 4242,
            u => u,
        }
    }

    /// Guest tree at `<t>/guest` holding `/var/lib/gitea/backups/dump.zip`,
    /// destination `<t>/dest`.
    fn setup(t: &Tmp) -> (String, FilePullOp) {
        std::fs::set_permissions(&t.0, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let g = t.0.join("guest/var/lib/gitea/backups");
        std::fs::create_dir_all(&g).unwrap();
        std::fs::write(g.join("dump.zip"), b"gitea dump bytes").unwrap();
        std::fs::create_dir_all(t.0.join("dest")).unwrap();
        std::os::unix::fs::chown(t.0.join("dest"), Some(uid()), None).unwrap();
        let op = FilePullOp {
            vmid: 105,
            kind: GuestKind::Lxc,
            guest_path: "/var/lib/gitea/backups/dump.zip".into(),
            dest_dir: t.0.join("dest").to_string_lossy().into_owned(),
            dest_name: "gitea-dump.zip".into(),
            dry_run: false,
        };
        (t.0.join("guest").to_string_lossy().into_owned(), op)
    }

    fn groot(p: &str) -> OwnedFd {
        open_path(p, DIR_FLAGS).unwrap()
    }

    #[test]
    fn pulls_file_with_hash_and_no_partial() {
        let t = tmp("ok");
        let (root, op) = setup(&t);
        let out = root_file_pull(groot(&root), &op, uid()).unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(out.size, 16);
        assert_eq!(
            out.sha256.as_deref(),
            Some(plugin_toolkit::hash::sha256_hex(b"gitea dump bytes").as_str())
        );
        assert_eq!(std::fs::read(&out.path).unwrap(), b"gitea dump bytes");
        assert!(!t.0.join("dest/gitea-dump.zip.partial").exists());
    }

    #[test]
    fn dry_run_sizes_and_writes_nothing() {
        let t = tmp("dry");
        let (root, mut op) = setup(&t);
        op.dry_run = true;
        let out = root_file_pull(groot(&root), &op, uid()).unwrap_or_else(|e| panic!("{e:#}"));
        assert_eq!(out.size, 16);
        assert!(out.free_bytes.unwrap() > 0 && out.sha256.is_none());
        assert!(
            std::fs::read_dir(t.0.join("dest"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn refuses_existing_destination() {
        let t = tmp("exists");
        let (root, op) = setup(&t);
        std::fs::write(t.0.join("dest/gitea-dump.zip"), b"keep").unwrap();
        let e = root_file_pull(groot(&root), &op, uid()).unwrap_err();
        assert!(format!("{e:#}").contains("already exists"), "{e:#}");
        assert_eq!(
            std::fs::read(t.0.join("dest/gitea-dump.zip")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn refuses_destination_owned_by_someone_else() {
        let t = tmp("owner");
        let (root, op) = setup(&t);
        let e = root_file_pull(groot(&root), &op, uid() + 1).unwrap_err();
        assert!(format!("{e:#}").contains("not the caller"), "{e:#}");
    }

    #[test]
    fn refuses_root_caller() {
        let t = tmp("root");
        let (root, op) = setup(&t);
        let e = root_file_pull(groot(&root), &op, 0).unwrap_err();
        assert!(format!("{e:#}").contains("on behalf of root"), "{e:#}");
    }

    #[test]
    fn refuses_group_writable_dest() {
        let t = tmp("gw");
        let (root, op) = setup(&t);
        std::fs::set_permissions(
            t.0.join("dest"),
            std::os::unix::fs::PermissionsExt::from_mode(0o775),
        )
        .unwrap();
        let e = root_file_pull(groot(&root), &op, uid()).unwrap_err();
        assert!(format!("{e:#}").contains("writable"), "{e:#}");
    }

    #[test]
    fn refuses_fifo_without_blocking() {
        let t = tmp("fifo");
        let (root, mut op) = setup(&t);
        let f = cstr(
            &t.0.join("guest/var/lib/gitea/backups/pipe")
                .to_string_lossy(),
        )
        .unwrap();
        // SAFETY: valid C string.
        assert_eq!(unsafe { libc::mkfifo(f.as_ptr(), 0o600) }, 0);
        op.guest_path = "/var/lib/gitea/backups/pipe".into();
        let e = root_file_pull(groot(&root), &op, uid()).unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
    }

    #[test]
    fn refuses_device() {
        let dev = groot("/dev");
        let e = open_regular(&dev, "null", "/dev/null").unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rename_noreplace_keeps_existing_target() {
        let t = tmp("noreplace");
        std::fs::write(t.0.join("a"), b"new").unwrap();
        std::fs::write(t.0.join("b"), b"old").unwrap();
        let dir = groot(&t.0.to_string_lossy());
        let e = rename_noreplace(dir.as_raw_fd(), "a", "b").unwrap_err();
        assert!(format!("{e:#}").contains("rename a -> b"), "{e:#}");
        assert_eq!(std::fs::read(t.0.join("b")).unwrap(), b"old");
        assert_eq!(std::fs::read(t.0.join("a")).unwrap(), b"new");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reopen_through_proc_fd_is_same_inode() {
        use std::os::unix::fs::MetadataExt;
        let t = tmp("reopen");
        std::fs::write(t.0.join("f"), b"x").unwrap();
        let dir = groot(&t.0.to_string_lossy());
        let f = open_regular(&dir, "f", "f").unwrap();
        let st = fstat(f.as_raw_fd()).unwrap();
        let m = std::fs::metadata(t.0.join("f")).unwrap();
        assert_eq!((st.st_dev as u64, st.st_ino as u64), (m.dev(), m.ino()));
    }

    #[test]
    fn first_pid_reads_the_first_line() {
        assert_eq!(first_pid("4242\n4300\n"), Some(4242));
        assert_eq!(first_pid(""), None);
    }

    #[test]
    fn refuses_pseudo_filesystems() {
        assert_eq!(refused_fs(0x6573_5546), Some("fuse"));
        assert_eq!(refused_fs(0x1373), None);
        assert_eq!(refused_fs(0x9fa0), Some("procfs"));
        assert_eq!(refused_fs(0x6367_7270), Some("cgroup2"));
        assert_eq!(refused_fs(0xef53), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refuses_procfs_path() {
        let e = open_beneath(groot("/proc"), "/self/status").unwrap_err();
        assert!(format!("{e:#}").contains("procfs"), "{e:#}");
    }

    #[test]
    fn refuses_growth_during_copy() {
        let t = tmp("grow");
        let (_, _) = setup(&t);
        let src = t.0.join("guest/var/lib/gitea/backups/dump.zip");
        let f = open_path(&src.to_string_lossy(), libc::O_RDONLY | libc::O_CLOEXEC).unwrap();
        let before = fstat(f.as_raw_fd()).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&src)
            .unwrap()
            .write_all(b" and more")
            .unwrap();
        let dir = groot(&t.0.join("dest").to_string_lossy());
        let e = write_partial(&dir, "x.partial", f, &before, (uid(), 0)).unwrap_err();
        assert!(
            format!("{e:#}").contains("changed while it was copied"),
            "{e:#}"
        );
    }

    #[test]
    fn cgroup_matches_only_its_ct() {
        assert!(cgroup_in_ct("0::/lxc/105/ns/init.scope\n", 105));
        assert!(cgroup_in_ct("0::/lxc/105\n", 105));
        assert!(!cgroup_in_ct("0::/lxc/1050/ns\n", 105));
        assert!(!cgroup_in_ct("0::/system.slice/x.service\n", 105));
    }

    #[test]
    fn refuses_symlink_in_guest_path() {
        let t = tmp("glink");
        let (root, op) = setup(&t);
        let b = t.0.join("guest/var/lib/gitea/backups");
        std::fs::remove_file(b.join("dump.zip")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", b.join("dump.zip")).unwrap();
        let e = root_file_pull(groot(&root), &op, uid()).unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
        let gitea = t.0.join("guest/var/lib/gitea");
        std::fs::rename(&gitea, t.0.join("guest/var/lib/real")).unwrap();
        std::os::unix::fs::symlink(t.0.join("guest/var/lib/real"), &gitea).unwrap();
        let e = root_file_pull(groot(&root), &op, uid()).unwrap_err();
        assert!(format!("{e:#}").contains("symlinks are refused"), "{e:#}");
    }

    #[test]
    fn refuses_symlink_in_dest_dir() {
        let t = tmp("dlink");
        let (root, mut op) = setup(&t);
        std::os::unix::fs::symlink(t.0.join("dest"), t.0.join("link")).unwrap();
        op.dest_dir = t.0.join("link").to_string_lossy().into_owned();
        let e = root_file_pull(groot(&root), &op, uid()).unwrap_err();
        assert!(format!("{e:#}").contains("symlinks are refused"), "{e:#}");
        assert!(
            std::fs::read_dir(t.0.join("dest"))
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn replaces_stale_partial_and_leaves_none() {
        let t = tmp("stale");
        let (root, op) = setup(&t);
        std::fs::write(t.0.join("dest/gitea-dump.zip.partial"), b"old").unwrap();
        root_file_pull(groot(&root), &op, uid()).unwrap_or_else(|e| panic!("{e:#}"));
        assert!(!t.0.join("dest/gitea-dump.zip.partial").exists());
    }

    #[test]
    fn refuses_non_regular_source() {
        let t = tmp("dir");
        let (root, mut op) = setup(&t);
        std::fs::create_dir(t.0.join("guest/var/lib/gitea/backups/sub")).unwrap();
        op.guest_path = "/var/lib/gitea/backups/sub".into();
        let e = root_file_pull(groot(&root), &op, uid()).unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
    }

    #[test]
    fn validate_rejects_bad_payloads() {
        let t = tmp("validate");
        let (_, base) = setup(&t);
        let bad = |f: &dyn Fn(&mut FilePullOp)| {
            let mut op = base.clone();
            f(&mut op);
            op.validate().is_err()
        };
        assert!(base.validate().is_ok());
        assert!(bad(&|o| o.vmid = 7));
        assert!(bad(&|o| o.kind = GuestKind::Vm));
        assert!(bad(&|o| o.guest_path = "var/lib/gitea/backups/x".into()));
        assert!(bad(
            &|o| o.guest_path = "/var/lib/gitea/backups/../../etc/shadow".into()
        ));
        assert!(bad(&|o| o.guest_path = "/var/lib/gitea/backupsX/x".into()));
        assert!(bad(&|o| o.guest_path = "/var/lib/gitea/backups".into()));
        assert!(bad(&|o| o.guest_path = "/etc/shadow".into()));
        assert!(bad(&|o| o.guest_path = "/var/lib/gitea/backups/".into()));
        assert!(bad(&|o| o.dest_dir = "relative".into()));
        assert!(bad(&|o| o.dest_name = "a/b".into()));
        assert!(bad(&|o| o.dest_name = "..".into()));
    }
}
