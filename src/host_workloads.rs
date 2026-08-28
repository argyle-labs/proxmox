//! Detect non-hypervisor workloads running **directly on the bare-metal PVE
//! host** instead of inside a guest (LXC/VM).
//!
//! A Proxmox node should run only the hypervisor + base-OS stack (pve*, qemu,
//! corosync, zfs, sshd, systemd, …). Anything else — a `minio`, an
//! `act_runner`, an app daemon — running on the node itself violates the "the
//! host stays clean and disposable" principle: it can't be backed up, migrated,
//! or rebuilt as a unit, and it competes with guests for the node's resources.
//!
//! Detection is **node-local** (like [`crate::diagnostics::diagnose_lxc_shm_traps`]):
//! it scans `/proc` on the box the plugin runs on and yields nothing when that
//! box isn't a PVE node. It reads three things per process:
//!   * `/proc/<pid>/cmdline` — empty ⇒ a kernel thread (skip).
//!   * `/proc/<pid>/cgroup`  — a cgroup path under `/lxc/<vmid>` ⇒ the process
//!     lives *inside* a container guest (skip); the systemd `*.service` unit
//!     name (untruncated, unlike `comm`) when it runs under `system.slice`.
//!   * `/proc/<pid>/comm`    — the 15-char-truncated process name, the fallback
//!     label + allowlist key.
//!
//! The classifier is pure and unit-tested; the `/proc` walk is the only impure
//! part and degrades to an empty result off a PVE node.

/// One process's minimal identity, as read from `/proc/<pid>`.
pub struct ProcInfo {
    /// `/proc/<pid>/comm` (kernel-truncated to 15 chars).
    pub comm: String,
    /// `/proc/<pid>/cgroup` contents (cgroup v2: a single `0::<path>` line).
    pub cgroup: String,
    /// True when `/proc/<pid>/cmdline` is empty — the mark of a kernel thread.
    pub cmdline_empty: bool,
}

/// Hypervisor + base-OS process/unit name families that legitimately run on a
/// PVE node. Matched as a **prefix** (case-insensitive) against both the
/// systemd unit name (from cgroup, untruncated) and the `comm`, so truncated
/// comms like `qemu-system-x86` and `systemd-journal` still match.
const ALLOWED_PREFIXES: &[&str] = &[
    // Proxmox VE stack
    "pve",
    "pmxcfs",
    "pvefw",
    "spiceproxy",
    "qmeventd",
    "pvescheduler",
    // virtualization: the qemu/kvm process IS the hypervisor running a VM
    "qemu",
    "kvm",
    // clustering / cluster fs
    "corosync",
    "pmxcfs",
    "cfs",
    // containers runtime on the node (not guest payload — that's filtered by cgroup)
    "lxc",
    "lxcfs",
    // storage: ZFS + Ceph
    "zed",
    "zfs",
    "spl",
    "z_",
    "arc_",
    "txg",
    "ceph",
    // systemd + base init/session plumbing
    "systemd",
    "init",
    "user@",
    "user-",
    "session-",
    "(sd-",
    "dbus",
    "polkit",
    "logind",
    // base OS daemons
    "sshd",
    "ssh-agent",
    "cron",
    "crond",
    "rsyslog",
    "syslog",
    "chrony",
    "ntpd",
    "ntp",
    "smartd",
    "irqbalance",
    "rpcbind",
    "rpc.",
    "rpc_",
    "watchdog",
    "ksm",
    "apparmor",
    "auditd",
    "getty",
    "agetty",
    "login",
    "master",
    "qmgr",
    "pickup",
    "tlsmgr",
    "postfix",
    "dhclient",
    "ifup",
    "ifupdown",
    "networkd",
    "resolved",
    "unattended",
    "packagekit",
    "uuidd",
    "gpg-agent",
    // interactive admin sessions on the host are fine
    "bash",
    "-bash",
    "sh",
    "zsh",
    "dash",
    "sudo",
    "su",
    "tmux",
    "screen",
    "nano",
    "vim",
    "less",
    "sleep",
    "top",
    "htop",
    "watch",
    "tail",
    "journalctl",
    "scp",
    "rsync",
    // orca's own management plane
    "orca",
];

/// Extract a systemd `*.service` unit name (without the `.service` suffix) from
/// a cgroup path, e.g. `0::/system.slice/minio.service` → `minio`,
/// `.../system-getty.slice/getty@tty1.service` → `getty@tty1`. Returns `None`
/// for scopes/slices that aren't a `.service` (user scopes, qemu scopes, …).
fn systemd_unit(cgroup: &str) -> Option<String> {
    cgroup
        .split('/')
        .rev()
        .find_map(|seg| seg.strip_suffix(".service"))
        .filter(|u| !u.is_empty())
        .map(|u| u.to_string())
}

/// True when the cgroup path shows the process lives inside a container guest
/// (PVE puts LXC payload under `/lxc/<vmid>`), so it is NOT a host workload.
fn in_container_guest(cgroup: &str) -> bool {
    cgroup.contains("/lxc/") || cgroup.contains("/lxc.payload")
}

/// Case-insensitive prefix match against [`ALLOWED_PREFIXES`].
fn is_allowed(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return true; // nothing to flag
    }
    ALLOWED_PREFIXES.iter().any(|p| n.starts_with(p))
}

/// Pure classifier: given one process, return the workload label to flag, or
/// `None` when it's a kernel thread, a guest-container process, or part of the
/// allowed hypervisor/base-OS stack.
///
/// The label prefers the systemd unit name (untruncated) over `comm`.
pub fn classify(p: &ProcInfo) -> Option<String> {
    if p.cmdline_empty {
        return None; // kernel thread
    }
    if in_container_guest(&p.cgroup) {
        return None; // runs inside an LXC guest, not on the host
    }
    let unit = systemd_unit(&p.cgroup);
    // Allowed if EITHER the unit or the comm is on the allowlist — a rogue unit
    // (minio.service) whose comm is also unknown (minio) fails both and flags.
    if is_allowed(&p.comm) || unit.as_deref().map(is_allowed).unwrap_or(false) {
        return None;
    }
    // Prefer the full unit name as the human label; fall back to comm.
    Some(unit.unwrap_or_else(|| p.comm.trim().to_string()))
}

/// Scan `/proc` and return the sorted, de-duplicated set of non-hypervisor
/// workload labels running directly on this host. Empty off a PVE node (or if
/// `/proc` can't be read).
pub fn scan_host_workloads() -> Vec<String> {
    // Only meaningful on a PVE node — gate on the PVE cluster fs, same signal
    // the shm-trap sweep uses. Keeps this a no-op on non-Proxmox hosts.
    if !std::path::Path::new("/etc/pve").exists() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut labels = std::collections::BTreeSet::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue; // not a pid dir
        };
        let base = format!("/proc/{pid}");
        // cmdline: empty ⇒ kernel thread.
        let cmdline_empty = std::fs::read(format!("{base}/cmdline"))
            .map(|b| b.iter().all(|&c| c == 0))
            .unwrap_or(true);
        let comm = std::fs::read_to_string(format!("{base}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let cgroup = std::fs::read_to_string(format!("{base}/cgroup")).unwrap_or_default();
        if let Some(label) = classify(&ProcInfo {
            comm,
            cgroup,
            cmdline_empty,
        }) {
            labels.insert(label);
        }
    }
    labels.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(comm: &str, cgroup: &str, cmdline_empty: bool) -> ProcInfo {
        ProcInfo {
            comm: comm.into(),
            cgroup: cgroup.into(),
            cmdline_empty,
        }
    }

    #[test]
    fn flags_rogue_service_by_unit_name() {
        // minio started as a systemd unit on the host → flagged, labelled by unit.
        assert_eq!(
            classify(&info("minio", "0::/system.slice/minio.service", false)).as_deref(),
            Some("minio")
        );
        // act_runner likewise (comm may be truncated; unit is authoritative).
        assert_eq!(
            classify(&info(
                "act_runner",
                "0::/system.slice/gitea-runner.service",
                false
            ))
            .as_deref(),
            Some("gitea-runner")
        );
    }

    #[test]
    fn flags_rogue_process_with_no_systemd_unit_by_comm() {
        // launched from a shell, cgroup is a user session scope, no .service.
        assert_eq!(
            classify(&info(
                "act_runner",
                "0::/user.slice/user-0.slice/session-3.scope",
                false
            ))
            .as_deref(),
            Some("act_runner")
        );
    }

    #[test]
    fn allows_hypervisor_and_base_stack() {
        for (comm, cg) in [
            ("pvedaemon", "0::/system.slice/pvedaemon.service"),
            ("pveproxy", "0::/system.slice/pveproxy.service"),
            ("qemu-system-x86", "0::/qemu.slice/100.scope"), // truncated comm
            ("corosync", "0::/system.slice/corosync.service"),
            (
                "systemd-journal",
                "0::/system.slice/systemd-journald.service",
            ), // truncated
            ("sshd", "0::/system.slice/ssh.service"),
            ("zed", "0::/system.slice/zfs-zed.service"),
            ("pmxcfs", "0::/system.slice/pve-cluster.service"),
            ("orca", "0::/system.slice/orca.service"),
        ] {
            assert_eq!(
                classify(&info(comm, cg, false)),
                None,
                "should allow {comm}"
            );
        }
    }

    #[test]
    fn ignores_kernel_threads() {
        // kernel threads have empty cmdline; comm often has no cgroup or root.
        assert_eq!(classify(&info("kworker/0:1", "0::/", true)), None);
        assert_eq!(classify(&info("z_wr_iss", "0::/", true)), None);
    }

    #[test]
    fn ignores_processes_inside_lxc_guests() {
        // A minio running INSIDE an LXC guest is that guest's business, not a
        // host workload — the cgroup shows the /lxc/<vmid> payload path.
        assert_eq!(
            classify(&info(
                "minio",
                "0::/lxc/116/ns/system.slice/minio.service",
                false
            )),
            None
        );
        assert_eq!(
            classify(&info(
                "node",
                "0::/lxc.payload.108/system.slice/app.service",
                false
            )),
            None
        );
    }

    #[test]
    fn interactive_admin_shells_are_not_flagged() {
        assert_eq!(
            classify(&info(
                "bash",
                "0::/user.slice/user-0.slice/session-1.scope",
                false
            )),
            None
        );
    }

    #[test]
    fn systemd_unit_parses_service_leaf() {
        assert_eq!(
            systemd_unit("0::/system.slice/minio.service").as_deref(),
            Some("minio")
        );
        assert_eq!(
            systemd_unit("0::/system.slice/system-getty.slice/getty@tty1.service").as_deref(),
            Some("getty@tty1")
        );
        assert_eq!(systemd_unit("0::/qemu.slice/100.scope"), None);
        assert_eq!(systemd_unit("0::/"), None);
    }
}
