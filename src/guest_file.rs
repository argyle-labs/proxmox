//! Copy a file out of a guest to a host directory (`proxmox.guest.file_pull`).
//!
//! VM: the PVE guest-agent `file-read` returns at most 16 MiB in one JSON
//! string with no offset parameter, so it can neither be chunked nor carry
//! binary data intact; VMs are refused.

use anyhow::ensure;
use plugin_toolkit::prelude::*;

use crate::execute::{self, Change};

const TOOL: &str = "proxmox.guest.file_pull";
const ALLOWED_GUEST_DIRS: &[&str] = &["/var/lib/gitea/backups"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum GuestKind {
    Lxc,
    Vm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePullOp {
    pub vmid: u64,
    pub kind: GuestKind,
    pub guest_path: String,
    pub dest_dir: String,
    pub dest_name: String,
}

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
    fn op(&self) -> FilePullOp {
        FilePullOp {
            vmid: self.vmid,
            kind: self.kind,
            guest_path: self.guest_path.clone(),
            dest_dir: self.dest_dir.clone(),
            dest_name: self.dest_name.clone(),
        }
    }
}

pub fn file_pull(args: &FilePullArgs) -> Result<Change<FilePulled>> {
    let op = args.op();
    op.validate()?;
    bail!("CT {}: {TOOL}: {}", op.vmid, crate::lxc_guest::UNSUPPORTED)
}

/// [MUTATES STATE] Copy one file out of a guest into a host directory.
/// Unsupported for LXC (no PVE API reads a container file) and refused for VMs.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.file_pull",
    role = "admin",
    execute_gated = false
)]
async fn proxmox_guest_file_pull(args: FilePullArgs, ctx: &ToolCtx) -> Result<Change<FilePulled>> {
    execute::require_admin(TOOL, ctx.caller().as_ref())?;
    file_pull(&args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_bad_payloads() {
        let base = FilePullOp {
            vmid: 105,
            kind: GuestKind::Lxc,
            guest_path: "/var/lib/gitea/backups/dump.zip".into(),
            dest_dir: "/srv/dest".into(),
            dest_name: "dump.zip".into(),
        };
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
