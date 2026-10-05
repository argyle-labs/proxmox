//! Guest standard for LXC containers: a root console that logs in without a
//! password, and a one-word `update` that only runs after an orca backup.
//!
//! * [`probe`] reads the facts through allowlisted `stat`/`head`/`ls`/`systemctl show`,
//!   feeding `UnitFacts::has_root_console` / `has_update_command`.
//! * `proxmox.guest.standard.audit` (read) reports them per container, checked
//!   against [`standard_guard`].
//! * `proxmox.guest.standard.apply` (admin, dry-run by default) installs the
//!   console autologin (Debian: a `container-getty@` drop-in; Alpine: an
//!   inittab `getty -n -l` wrapper) and the `update` gate script.
//! * `proxmox.guest.update` (admin, dry-run by default) and the unit action
//!   `update` (dry-run unless its payload sets `execute`) take a vzdump backup
//!   through the PVE API, record it in the container, then run the updater.
//!
//! The `update` gate replaces the hand-rolled forced-command ssh key
//! ([`LEGACY_BACKUP_KEY`] → the host's `orca-guest-backup`): orca takes the
//! backup through the PVE API, so the guest holds no credential to its host.
//! The probe reports a leftover key so it can be retired. The gate is a safety
//! interlock against updating without a restore point, not a security control:
//! root in the container can always run the updater directly.
//!
//! Every in-container command goes through orca's lxc-exec allowlist. A step
//! outside it ([`lxc_guest::PROPOSED_ALLOWLIST`]) is named in the plan as
//! `needs allowlist: X` and refused before anything runs, except the Alpine
//! inittab reload, which is deferred to the container's next start.

use std::time::Duration;

use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::contract::{BackupRef, BoxFuture, CallerIdentity, UnitFacts, UnitGuard};
use plugin_toolkit::prelude::*;

use crate::execute::{self, Change};
use crate::lxc_guest::{self, CtRef, GuestIo, needs_allowlist};
use crate::tools::resolve_config;

pub const DEBIAN_AUTOLOGIN: &str = "/etc/systemd/system/container-getty@.service.d/autologin.conf";
/// The unit PVE starts for the first console. Its effective `ExecStart`, after
/// every drop-in and reset, shows autologin from any layout (ours,
/// community-scripts' per-tty override).
const DEBIAN_CONSOLE_UNIT: &str = "container-getty@1.service";
pub const ALPINE_AUTOLOGIN: &str = "/usr/local/sbin/autologin";
pub const INITTAB: &str = "/etc/inittab";
/// PVE's Alpine setup regenerates every `ttyN::…getty` line in `/etc/inittab`
/// on each container start unless this file exists.
pub const PVE_IGNORE_INITTAB: &str = "/etc/.pve-ignore.inittab";
pub const UPDATE_GATE: &str = "/usr/local/bin/update";
/// Where `apply` keeps a non-orca gate it replaces.
pub const REPLACED_GATE: &str = "/usr/local/bin/update.orca-replaced";
/// community-scripts' per-app updater.
pub const COMMUNITY_UPDATER: &str = "/usr/bin/update";
/// Written after a successful pre-update backup; the gate script runs the
/// updater only while it is younger than [`GATE_WINDOW_SECS`].
pub const BACKUP_MARKER: &str = "/run/orca-update-backup.json";
/// Private key of the hand-rolled gate, authorised on the host only for
/// `orca-guest-backup <vmid>`.
pub const LEGACY_BACKUP_KEY: &str = "/root/.orca/host_backup_key";
pub const GATE_WINDOW_SECS: u64 = 3600;
const GATE_MARKER: &str = "# orca-update-gate v1";

/// systemd guests run the updater as this unit so the seam's 5-minute exec
/// timeout can never kill dpkg mid-upgrade.
pub const UPDATE_UNIT: &str = "orca-guest-update.service";
pub const UPDATE_UNIT_PATH: &str = "/run/systemd/system/orca-guest-update.service";
const UPDATE_START_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(30)
} else {
    Duration::from_secs(60)
};
const UPDATE_DEADLINE: Duration = Duration::from_secs(2 * 3600);
const UPDATE_POLL: Duration = if cfg!(test) {
    Duration::from_millis(1)
} else {
    Duration::from_secs(5)
};
/// Bounds the whole probe; `unit.detail` runs it for any caller.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub const DEBIAN_AUTOLOGIN_CONF: &str = "[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear --keep-baud tty%I 115200,38400,9600 $TERM
";
pub const ALPINE_AUTOLOGIN_SH: &str = "#!/bin/sh
exec login -f root
";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    Debian,
    Alpine,
    Other,
}

pub fn os_from_release(release: &str) -> Os {
    let field = |k: &str| {
        release.lines().find_map(|l| {
            l.strip_prefix(k)
                .and_then(|v| v.strip_prefix('='))
                .map(|v| v.trim_matches('"').to_ascii_lowercase())
        })
    };
    let ids: Vec<String> = [field("ID"), field("ID_LIKE")]
        .into_iter()
        .flatten()
        .flat_map(|v| v.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .collect();
    if ids.iter().any(|i| i == "alpine") {
        Os::Alpine
    } else if ids.iter().any(|i| i == "debian" || i == "ubuntu") {
        Os::Debian
    } else {
        Os::Other
    }
}

/// Probed state of one container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StandardFacts {
    pub os: Os,
    pub has_root_console: bool,
    /// The orca `update` gate is installed.
    pub has_update_command: bool,
    /// community-scripts' `/usr/bin/update` is present.
    pub community_updater: bool,
    /// The hand-rolled gate's ssh key is still in the container.
    #[serde(default)]
    pub legacy_backup_key: bool,
    /// A `/usr/local/bin/update` exists that is not orca's gate.
    #[serde(default)]
    pub foreign_gate: bool,
    /// inittab getty lines that already set another login program.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub console_drift: Vec<String>,
}

fn live_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with('#'))
}

fn autologin_root(argv: &[&str]) -> bool {
    argv.windows(2)
        .any(|w| matches!(w[0], "--autologin" | "-a") && w[1] == "root")
        || argv
            .iter()
            .any(|a| matches!(*a, "--autologin=root" | "-aroot"))
}

/// The effective `ExecStart=` value in `systemctl cat` output: the last
/// assignment, where an empty one resets everything before it.
fn effective_exec_start(cat: &str) -> Option<&str> {
    let mut cur = None;
    for l in live_lines(cat) {
        if let Some(v) = l.trim().strip_prefix("ExecStart=") {
            cur = Some(v.trim()).filter(|v| !v.is_empty());
        }
    }
    cur
}

/// Autologin needs both views. `show` (`{ path=… ; argv[]=… ; … }`) is the
/// effective command after drop-ins and resets, but joins argv without
/// quoting; `cat` shows the literal line, so a quoted `"--autologin root"`
/// (one argument to agetty) is not mistaken for the two it would need.
fn debian_console_ok(show: &str, cat: &str) -> bool {
    let show_ok = show.split("argv[]=").skip(1).any(|rest| {
        let argv: Vec<&str> = rest
            .split(" ; ")
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        autologin_root(&argv)
    });
    show_ok
        && effective_exec_start(cat)
            .is_some_and(|l| autologin_root(&l.split_whitespace().collect::<Vec<_>>()))
}

/// Seam output is unbounded core-side; anything larger than a file read is
/// refused rather than parsed.
fn capped(what: &str, out: String) -> Result<String> {
    if out.len() > lxc_guest::READ_CAP {
        bail!("{what}: output larger than {} bytes", lxc_guest::READ_CAP);
    }
    Ok(out)
}

/// `systemctl show -p <props> UNIT` as `(key, value)` pairs.
async fn unit_show(
    io: &dyn GuestIo,
    vmid: u32,
    unit: &str,
    props: &[&str],
) -> Result<std::collections::HashMap<String, String>> {
    let mut argv = vec!["systemctl", "show"];
    for p in props {
        argv.extend(["-p", p]);
    }
    argv.push(unit);
    let out = capped("systemctl show", run_exec(io, vmid, &argv).await?)?;
    Ok(out
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

/// The inittab id (`tty1`, `console`, …) of a line.
fn inittab_id(line: &str) -> &str {
    line.trim_start().split(':').next().unwrap_or_default()
}

/// Ids the autologin rewrite touches: the virtual consoles and `console`.
fn console_id(id: &str) -> bool {
    id == "console"
        || id
            .strip_prefix("tty")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A live getty line already passing `-l <program>`.
fn sets_login_program(line: &str) -> bool {
    line.split_once("/sbin/getty ")
        .is_some_and(|(_, args)| args.split_whitespace().any(|a| a == "-l"))
}

fn uses_autologin(line: &str) -> bool {
    line.contains(&format!("-l {ALPINE_AUTOLOGIN} "))
}

/// The PVE console attaches to tty1, so that line decides the fact.
fn tty1_uses_autologin(inittab: &str) -> bool {
    live_lines(inittab).any(|l| inittab_id(l) == "tty1" && uses_autologin(l))
}

/// Getty lines left alone because they already set another login program.
fn inittab_drift(inittab: &str) -> Vec<String> {
    live_lines(inittab)
        .filter(|l| console_id(inittab_id(l)) && sets_login_program(l) && !uses_autologin(l))
        .map(|l| format!("{INITTAB}: `{l}` already sets a login program; left unchanged"))
        .collect()
}

/// Read-only, bounded by [`PROBE_TIMEOUT`].
pub async fn probe(io: &dyn GuestIo, vmid: u32) -> Result<StandardFacts> {
    probe_within(io, vmid, PROBE_TIMEOUT).await
}

async fn probe_within(io: &dyn GuestIo, vmid: u32, limit: Duration) -> Result<StandardFacts> {
    tokio::time::timeout(limit, probe_inner(io, vmid))
        .await
        .map_err(|_| anyhow!("CT {vmid}: probe timed out after {limit:?}"))?
}

async fn probe_inner(io: &dyn GuestIo, vmid: u32) -> Result<StandardFacts> {
    let release = lxc_guest::read_file(io, vmid, "/etc/os-release")
        .await?
        .unwrap_or_default();
    let os = os_from_release(&release);
    let mut console_drift = Vec::new();
    let has_root_console = match os {
        Os::Debian => {
            let show = io
                .exec(
                    vmid,
                    &[
                        "systemctl",
                        "show",
                        "-p",
                        "ExecStart",
                        "--value",
                        DEBIAN_CONSOLE_UNIT,
                    ],
                )
                .await?;
            let cat = io
                .exec(vmid, &["systemctl", "cat", DEBIAN_CONSOLE_UNIT])
                .await?;
            show.success
                && cat.success
                && debian_console_ok(
                    &capped("systemctl show ExecStart", show.stdout)?,
                    &capped("systemctl cat", cat.stdout)?,
                )
        }
        Os::Alpine => {
            let inittab = lxc_guest::read_file(io, vmid, INITTAB)
                .await?
                .unwrap_or_default();
            console_drift = inittab_drift(&inittab);
            let wrapper = lxc_guest::read_file(io, vmid, ALPINE_AUTOLOGIN).await?;
            tty1_uses_autologin(&inittab)
                && wrapper.is_some_and(|w| w.contains("login -f root"))
                && lxc_guest::exists(io, vmid, PVE_IGNORE_INITTAB).await?
        }
        Os::Other => false,
    };
    let gate = lxc_guest::read_file(io, vmid, UPDATE_GATE).await?;
    let has_update_command = gate.as_deref().is_some_and(|g| g.contains(GATE_MARKER));
    let foreign_gate = gate.is_some() && !has_update_command;
    let community_updater = lxc_guest::exists(io, vmid, COMMUNITY_UPDATER).await?;
    let legacy_backup_key = lxc_guest::exists(io, vmid, LEGACY_BACKUP_KEY).await?;
    Ok(StandardFacts {
        os,
        has_root_console,
        has_update_command,
        community_updater,
        legacy_backup_key,
        foreign_gate,
        console_drift,
    })
}

/// Facts for the guard: `cpu`/`mem` from the resource row, console and update
/// command from a probe when one was possible.
pub fn unit_facts(
    cpu: Option<u32>,
    mem_mb: Option<u64>,
    probed: Option<&StandardFacts>,
) -> UnitFacts {
    UnitFacts {
        cpu,
        mem_mb,
        has_root_console: probed.is_some_and(|f| f.has_root_console),
        has_update_command: probed.is_some_and(|f| f.has_update_command),
    }
}

/// The LXC floor plus the console and update-command requirements. Applied only
/// to a probed container: a freshly provisioned guest cannot have either yet,
/// and an unprobed one would fail closed on facts nobody read.
pub fn standard_guard(base: UnitGuard) -> UnitGuard {
    UnitGuard {
        require_root_console: true,
        require_update_command: true,
        ..base
    }
}

/// Alpine inittab with each live `ttyN` / `console` getty logging in through
/// the autologin wrapper. Lines already using it, or already setting another
/// login program, are left alone.
pub fn alpine_inittab(current: &str) -> String {
    let mut out: Vec<String> = current
        .lines()
        .map(|l| {
            let live = !l.trim_start().starts_with('#');
            match l.find("/sbin/getty ") {
                Some(i) if live && console_id(inittab_id(l)) && !sets_login_program(l) => {
                    let at = i + "/sbin/getty ".len();
                    format!("{}-n -l {ALPINE_AUTOLOGIN} {}", &l[..at], &l[at..])
                }
                _ => l.to_string(),
            }
        })
        .collect();
    out.push(String::new());
    out.join("\n")
}

/// The endpoint is interpolated into a root shell script, so it must be inert.
fn shell_safe(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub fn gate_script(endpoint: &str, ctid: u64) -> Result<String> {
    if !shell_safe(endpoint) {
        bail!("endpoint '{endpoint}' must be [A-Za-z0-9._-] to be named in the gate script");
    }
    Ok(format!(
        r#"#!/bin/sh
{GATE_MARKER}
# A safety interlock, not a security control: runs the updater only after orca
# has backed this container up.
marker={BACKUP_MARKER}
if [ ! -f "$marker" ] || [ $(( $(date +%s) - $(stat -c %Y "$marker") )) -gt {GATE_WINDOW_SECS} ]; then
  echo "update: no orca backup of CT {ctid} in the last hour." >&2
  echo "Run it through orca (backs up first): proxmox.guest.update --endpoint {endpoint} --ctid {ctid} --execute" >&2
  exit 1
fi
if [ -x {COMMUNITY_UPDATER} ]; then
  exec {COMMUNITY_UPDATER} "$@"
elif command -v apt-get >/dev/null 2>&1; then
  apt-get update || exit 1
  exec apt-get -y dist-upgrade
elif command -v apk >/dev/null 2>&1; then
  apk update || exit 1
  exec apk upgrade
fi
echo "update: no updater found (no {COMMUNITY_UPDATER}, apt-get or apk)" >&2
exit 1
"#
    ))
}

/// One step of an apply or update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Write {
        path: String,
        contents: String,
        mode: &'static str,
        before: Option<String>,
    },
    Exec {
        argv: Vec<String>,
        why: &'static str,
        /// Activates config already written; when the seam refuses it, the
        /// change takes effect at the container's next start instead.
        deferrable: bool,
    },
    /// Require that systemd loaded [`UPDATE_UNIT`] from orca's file alone.
    VerifyUnit,
    /// Start [`UPDATE_UNIT`] and wait for this run of it to finish.
    RunUnit,
    /// A change apply will not make; stops the whole run.
    Refuse { target: String, reason: String },
}

impl Step {
    fn exec(argv: &[&str], why: &'static str) -> Self {
        Step::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            why,
            deferrable: false,
        }
    }

    fn reload(argv: &[&str], why: &'static str) -> Self {
        Step::Exec {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            why,
            deferrable: true,
        }
    }

    fn refused(&self) -> Option<String> {
        match self {
            Step::Exec { argv, why, .. } => {
                needs_allowlist(&argv[0]).map(|n| format!("{n} ({why}: `{}`)", argv.join(" ")))
            }
            Step::Refuse { target, reason } => Some(format!("{target}: {reason}")),
            _ => None,
        }
    }

    /// A refused step that stops the run.
    fn blocker(&self) -> Option<String> {
        match self {
            Step::Exec {
                deferrable: true, ..
            } => None,
            _ => self.refused(),
        }
    }

    /// A refused step left to the container's next start.
    fn deferred(&self) -> Option<String> {
        match self {
            Step::Exec {
                deferrable: true, ..
            } => self
                .refused()
                .map(|r| format!("deferred to the container's next start: {r}")),
            _ => None,
        }
    }

    fn to_change(&self, ctid: u64) -> PlannedChange {
        match self {
            Step::Write {
                path,
                contents,
                mode,
                before,
            } => match before {
                Some(b) => PlannedChange::new(format!("ct/{ctid}:{path}"), "overwrite")
                    .with_detail(format!(
                        "mode {mode}; {}",
                        crate::backup_jobs::line_diff(b, contents)
                    )),
                None => PlannedChange::new(format!("ct/{ctid}:{path}"), "create")
                    .with_detail(format!("mode {mode}")),
            },
            Step::Exec { argv, why, .. } => {
                let (action, detail) = match (self.blocker(), self.deferred()) {
                    (Some(b), _) => ("exec", format!("{why}; {b}")),
                    (None, Some(d)) => ("deferred", d),
                    (None, None) => ("exec", why.to_string()),
                };
                PlannedChange::new(format!("ct/{ctid}: {}", argv.join(" ")), action)
                    .with_detail(detail)
            }
            Step::VerifyUnit => PlannedChange::new(format!("ct/{ctid}: {UPDATE_UNIT}"), "verify")
                .with_detail(format!(
                    "`systemctl show -p FragmentPath -p DropInPaths`: loaded from \
                     {UPDATE_UNIT_PATH} with no drop-ins"
                )),
            Step::RunUnit => PlannedChange::new(format!("ct/{ctid}: {UPDATE_UNIT}"), "run")
                .with_detail(format!(
                    "refuse if activating; `systemctl stop --job-mode=fail` an earlier finished \
                     run; `systemctl start --no-block --job-mode=fail {UPDATE_UNIT}`; a new \
                     InvocationID within {}s (else its queued start is stopped), then poll \
                     `systemctl show` every {}s for up to {}h until ActiveState=active \
                     Result=success; output from `systemctl status --lines=40`",
                    UPDATE_START_TIMEOUT.as_secs(),
                    UPDATE_POLL.as_secs(),
                    UPDATE_DEADLINE.as_secs() / 3600
                )),
            Step::Refuse { target, reason } => {
                PlannedChange::new(format!("ct/{ctid}:{target}"), "refused").with_detail(reason)
            }
        }
    }
}

fn write_if_changed(
    path: &str,
    want: String,
    mode: &'static str,
    current: Option<String>,
) -> Option<Step> {
    (current.as_deref().map(str::trim) != Some(want.trim())).then_some(Step::Write {
        path: path.to_string(),
        contents: want,
        mode,
        before: current,
    })
}

/// Read what `apply` would change and return its steps, with drift notes.
/// Reads only.
pub async fn plan_apply(
    io: &dyn GuestIo,
    args: &StandardApplyArgs,
) -> Result<(Vec<Step>, Vec<String>)> {
    let ctid = args.ctid;
    let vmid = ctid as u32;
    let facts = probe(io, vmid).await?;
    let mut steps = Vec::new();
    let notes = facts.console_drift.clone();
    if args.console {
        match facts.os {
            Os::Debian if facts.has_root_console => {}
            Os::Debian => {
                let cur = lxc_guest::read_file(io, vmid, DEBIAN_AUTOLOGIN).await?;
                steps.extend(write_if_changed(
                    DEBIAN_AUTOLOGIN,
                    DEBIAN_AUTOLOGIN_CONF.into(),
                    "0644",
                    cur,
                ));
                steps.push(Step::exec(
                    &["systemctl", "daemon-reload"],
                    "load the getty drop-in",
                ));
                // Restarting the getty ends an open console session on it.
                steps.push(Step::exec(
                    &[
                        "systemctl",
                        "try-restart",
                        "container-getty@1.service",
                        "container-getty@2.service",
                    ],
                    "restart running gettys with autologin",
                ));
            }
            Os::Alpine => {
                if !lxc_guest::exists(io, vmid, PVE_IGNORE_INITTAB).await? {
                    steps.push(Step::Write {
                        path: PVE_IGNORE_INITTAB.into(),
                        contents: String::new(),
                        mode: "0644",
                        before: None,
                    });
                }
                let wrapper = lxc_guest::read_file(io, vmid, ALPINE_AUTOLOGIN).await?;
                steps.extend(write_if_changed(
                    ALPINE_AUTOLOGIN,
                    ALPINE_AUTOLOGIN_SH.into(),
                    "0755",
                    wrapper,
                ));
                let inittab = lxc_guest::read_file(io, vmid, INITTAB)
                    .await?
                    .ok_or_else(|| anyhow!("CT {ctid} has no {INITTAB}"))?;
                if let Some(s) =
                    write_if_changed(INITTAB, alpine_inittab(&inittab), "0644", Some(inittab))
                {
                    steps.push(s);
                    steps.push(Step::reload(
                        &["kill", "-HUP", "1"],
                        "busybox init re-reads /etc/inittab on SIGHUP",
                    ));
                }
            }
            Os::Other => bail!(
                "CT {ctid}: console autologin is implemented for Debian/Ubuntu and Alpine only"
            ),
        }
    }
    if args.update_gate {
        steps.extend(plan_gate(io, args, &facts).await?);
    }
    Ok((steps, notes))
}

async fn plan_gate(
    io: &dyn GuestIo,
    args: &StandardApplyArgs,
    facts: &StandardFacts,
) -> Result<Vec<Step>> {
    let vmid = args.ctid as u32;
    let refuse = |reason: String| {
        Ok(vec![Step::Refuse {
            target: UPDATE_GATE.into(),
            reason,
        }])
    };
    // A gate whose updater orca cannot run would never open.
    let updater_blocked = match updater_commands(Updater::Auto, facts) {
        Ok(cmds) => blockers(&cmds),
        Err(e) => vec![e.to_string()],
    };
    if !updater_blocked.is_empty() {
        return refuse(format!(
            "the gate could never open: its updater is refused ({})",
            updater_blocked.join("; ")
        ));
    }
    let want = gate_script(&args.endpoint, args.ctid)?;
    let cur = lxc_guest::read_file(io, vmid, UPDATE_GATE).await?;
    match cur {
        Some(c) if !c.contains(GATE_MARKER) => {
            if !args.replace_gate {
                return refuse(format!(
                    "is not orca's gate; pass replace_gate to replace it (kept as {REPLACED_GATE})"
                ));
            }
            let mut steps = Vec::new();
            match lxc_guest::read_file(io, vmid, REPLACED_GATE).await? {
                Some(kept) if kept.trim() != c.trim() => {
                    return refuse(format!(
                        "{REPLACED_GATE} already holds a different script; move it aside \
                         before replacing this gate, so neither is lost"
                    ));
                }
                Some(_) => {}
                // No `cp` on the seam, so the copy round-trips; `read_exact`
                // refuses anything it cannot reproduce byte for byte.
                None => steps.push(Step::Write {
                    path: REPLACED_GATE.into(),
                    contents: lxc_guest::read_exact(io, vmid, UPDATE_GATE)
                        .await?
                        .ok_or_else(|| anyhow!("{UPDATE_GATE} vanished while planning"))?,
                    mode: "0755",
                    before: None,
                }),
            }
            steps.push(Step::Write {
                path: UPDATE_GATE.into(),
                contents: want,
                mode: "0755",
                before: Some(c),
            });
            Ok(steps)
        }
        cur => Ok(write_if_changed(UPDATE_GATE, want, "0755", cur)
            .into_iter()
            .collect()),
    }
}

fn blockers(steps: &[Step]) -> Vec<String> {
    steps.iter().filter_map(Step::blocker).collect()
}

/// Blockers then deferrals, for a dry-run summary.
fn plan_notes(steps: &[Step]) -> Vec<String> {
    blockers(steps)
        .into_iter()
        .chain(steps.iter().filter_map(Step::deferred))
        .collect()
}

/// Refuse up front so a plan never half-applies and then hits the allowlist.
fn refuse_blocked(tool: &str, steps: &[Step]) -> Result<()> {
    let b = blockers(steps);
    if !b.is_empty() {
        bail!(
            "{tool}: refusing to execute: {}; nothing was changed",
            b.join("; ")
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StepOutcome {
    pub target: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

fn exec_failure(r: lxc_guest::ExecResult) -> anyhow::Error {
    anyhow!(
        "exit {:?}: {}",
        r.exit_code,
        if r.stderr.is_empty() {
            r.stdout
        } else {
            r.stderr
        }
    )
}

async fn run_exec(io: &dyn GuestIo, vmid: u32, argv: &[&str]) -> Result<String> {
    let r = io.exec(vmid, argv).await?;
    if r.success {
        Ok(r.stdout)
    } else {
        Err(exec_failure(r))
    }
}

/// The unit's status and last journal lines; output only, never an error.
async fn unit_output(io: &dyn GuestIo, vmid: u32) -> String {
    match io
        .exec(
            vmid,
            &[
                "systemctl",
                "status",
                "--no-pager",
                "--lines=40",
                UPDATE_UNIT,
            ],
        )
        .await
    {
        Ok(r) => {
            let mut out = r.stdout;
            if out.len() > lxc_guest::READ_CAP {
                let mut end = lxc_guest::READ_CAP;
                while !out.is_char_boundary(end) {
                    end -= 1;
                }
                out.truncate(end);
            }
            out
        }
        Err(e) => format!("(could not read `systemctl status {UPDATE_UNIT}`: {e})"),
    }
}

const UNIT_PROPS: &[&str] = &[
    "ActiveState",
    "Result",
    "InvocationID",
    "FragmentPath",
    "DropInPaths",
];

type UnitState = std::collections::HashMap<String, String>;

async fn unit_state(io: &dyn GuestIo, vmid: u32) -> Result<UnitState> {
    unit_show(io, vmid, UPDATE_UNIT, UNIT_PROPS).await
}

fn prop<'a>(st: &'a UnitState, key: &str) -> &'a str {
    st.get(key).map(String::as_str).unwrap_or_default()
}

fn unit_running(st: &UnitState) -> bool {
    matches!(
        prop(st, "ActiveState"),
        "activating" | "deactivating" | "reloading"
    )
}

/// An `/etc` unit of the same name or any drop-in would replace or extend the
/// commands orca wrote.
fn require_own_unit(st: &UnitState, loaded: bool) -> Result<()> {
    let fragment = prop(st, "FragmentPath");
    if (loaded || !fragment.is_empty()) && fragment != UPDATE_UNIT_PATH {
        bail!(
            "{UPDATE_UNIT} loads from {fragment:?}, not {UPDATE_UNIT_PATH}; remove the other unit file"
        );
    }
    let dropins = prop(st, "DropInPaths");
    if !dropins.is_empty() {
        bail!("{UPDATE_UNIT} has drop-ins ({dropins}); remove them");
    }
    Ok(())
}

/// Start [`UPDATE_UNIT`] and wait for that run: a new `InvocationID` proves
/// the result read is this run's, not a previous one's.
///
/// Never `restart`, which would kill a run someone else started. Per
/// systemctl(1), `--job-mode=fail` fails a request that would reverse a pending
/// start job into a stop (or the reverse), so orca's stop and start never cancel
/// another caller's queued job. It does not refuse a start that merges into a
/// pending start; the `ActiveState` checks before each call do that.
async fn run_unit(io: &dyn GuestIo, vmid: u32) -> Result<String> {
    let mut st = unit_state(io, vmid).await?;
    if unit_running(&st) {
        bail!("{UPDATE_UNIT} was started by someone else; not starting it again");
    }
    // `active` is an earlier finished run held by RemainAfterExit; `start` is a
    // no-op until it is stopped.
    if prop(&st, "ActiveState") == "active" {
        run_exec(
            io,
            vmid,
            &["systemctl", "stop", "--job-mode=fail", UPDATE_UNIT],
        )
        .await?;
        st = unit_state(io, vmid).await?;
    }
    if !matches!(prop(&st, "ActiveState"), "inactive" | "failed") {
        bail!(
            "{UPDATE_UNIT} is {}; not starting it",
            prop(&st, "ActiveState")
        );
    }
    let prev = prop(&st, "InvocationID").to_string();
    run_exec(
        io,
        vmid,
        &[
            "systemctl",
            "start",
            "--no-block",
            "--job-mode=fail",
            UPDATE_UNIT,
        ],
    )
    .await?;
    let started = tokio::time::Instant::now();
    let mut ours = false;
    loop {
        let st = unit_state(io, vmid).await?;
        let id = prop(&st, "InvocationID");
        ours = ours || (!id.is_empty() && id != prev);
        if ours && !unit_running(&st) {
            let out = unit_output(io, vmid).await;
            if prop(&st, "ActiveState") == "active" && prop(&st, "Result") == "success" {
                return Ok(out);
            }
            bail!(
                "{UPDATE_UNIT} finished with ActiveState={} Result={}; status:\n{out}",
                prop(&st, "ActiveState"),
                prop(&st, "Result")
            );
        }
        if !ours && started.elapsed() >= UPDATE_START_TIMEOUT {
            let cancel =
                match run_exec(io, vmid, &["systemctl", "stop", "--no-block", UPDATE_UNIT]).await {
                    Ok(_) => "its queued start was cancelled with `systemctl stop --no-block`"
                        .to_string(),
                    Err(e) => format!(
                        "cancelling its queued start with `systemctl stop --no-block` failed: {e:#}"
                    ),
                };
            bail!(
                "{UPDATE_UNIT} did not start within {}s (InvocationID unchanged); {cancel}",
                UPDATE_START_TIMEOUT.as_secs()
            );
        }
        if started.elapsed() >= UPDATE_DEADLINE {
            bail!(
                "{UPDATE_UNIT} is still running after {}h; it keeps running in the container \
                 (check `systemctl status {UPDATE_UNIT}`)",
                UPDATE_DEADLINE.as_secs() / 3600
            );
        }
        tokio::time::sleep(UPDATE_POLL).await;
    }
}

/// Run `steps`. A failing step stops the run with what already ran named, so a
/// partial apply never reads as success.
pub async fn run_steps(io: &dyn GuestIo, ctid: u64, steps: &[Step]) -> Result<Vec<StepOutcome>> {
    let vmid = ctid as u32;
    let mut done: Vec<StepOutcome> = Vec::new();
    for s in steps {
        let outcome = match s {
            Step::Write {
                path,
                contents,
                mode,
                ..
            } => lxc_guest::write_checked(io, vmid, path, contents.as_bytes(), Some(mode))
                .await
                .map(|_| StepOutcome {
                    target: path.clone(),
                    action: "write".into(),
                    output: None,
                }),
            Step::Exec { argv, .. } if s.deferred().is_some() => Ok(StepOutcome {
                target: argv.join(" "),
                action: "deferred".into(),
                output: s.deferred(),
            }),
            Step::Exec { argv, .. } => {
                let args: Vec<&str> = argv.iter().map(String::as_str).collect();
                run_exec(io, vmid, &args).await.map(|out| StepOutcome {
                    target: argv.join(" "),
                    action: "exec".into(),
                    output: (!out.is_empty()).then_some(out),
                })
            }
            Step::VerifyUnit => unit_state(io, vmid)
                .await
                .and_then(|st| require_own_unit(&st, true))
                .map(|_| StepOutcome {
                    target: UPDATE_UNIT.into(),
                    action: "verify".into(),
                    output: None,
                }),
            Step::RunUnit => run_unit(io, vmid).await.map(|out| StepOutcome {
                target: UPDATE_UNIT.into(),
                action: "run".into(),
                output: (!out.is_empty()).then_some(out),
            }),
            Step::Refuse { .. } => Err(anyhow!("{}", s.refused().unwrap_or_default())),
        };
        match outcome {
            Ok(o) => done.push(o),
            Err(e) => {
                let ran: Vec<String> = done
                    .iter()
                    .map(|o| format!("{} {}", o.action, o.target))
                    .collect();
                bail!(
                    "CT {ctid}: step {} failed: {e:#}. Already applied: [{}]",
                    s.to_change(ctid).target,
                    ran.join("; ")
                );
            }
        }
    }
    Ok(done)
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GuestApplied {
    pub ctid: u64,
    pub steps: Vec<StepOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupRef>,
}

// ── update ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Updater {
    /// community-scripts' updater when present, else the OS package manager.
    #[default]
    Auto,
    Community,
    Apt,
    Apk,
}

impl std::str::FromStr for Updater {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "auto" => Ok(Updater::Auto),
            "community" => Ok(Updater::Community),
            "apt" => Ok(Updater::Apt),
            "apk" => Ok(Updater::Apk),
            other => bail!("updater '{other}' must be auto | community | apt | apk"),
        }
    }
}

/// Payload of the unit `update` action on an LXC.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct GuestUpdatePayload {
    #[serde(default)]
    pub updater: Updater,
    /// Backup storage for the pre-update vzdump; default: the node's first
    /// backup storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    /// Back up and update. Omitted, returns the plan and touches nothing.
    #[serde(default)]
    pub execute: bool,
}

/// The updater's commands, refused for an OS / updater pair that cannot work.
pub fn updater_commands(updater: Updater, facts: &StandardFacts) -> Result<Vec<Step>> {
    let resolved = match (updater, &facts.os) {
        (Updater::Auto, _) if facts.community_updater => Updater::Community,
        (Updater::Auto, Os::Alpine) => Updater::Apk,
        (Updater::Auto, Os::Debian) => Updater::Apt,
        (Updater::Auto, Os::Other) => {
            bail!("no updater for this OS: no {COMMUNITY_UPDATER}, and not Debian or Alpine")
        }
        (Updater::Community, _) if !facts.community_updater => {
            bail!("updater 'community' needs {COMMUNITY_UPDATER}, which is not present")
        }
        (Updater::Apt, os) if *os != Os::Debian => bail!("updater 'apt' needs Debian/Ubuntu"),
        (Updater::Apk, os) if *os != Os::Alpine => bail!("updater 'apk' needs Alpine"),
        (u, _) => u,
    };
    Ok(match resolved {
        Updater::Community => vec![Step::exec(&[COMMUNITY_UPDATER], "the app's own updater")],
        Updater::Apk => vec![
            Step::exec(&["/sbin/apk", "update"], "refresh package index"),
            Step::exec(&["/sbin/apk", "upgrade"], "upgrade packages"),
        ],
        _ => vec![
            Step::exec(&["/usr/bin/apt-get", "update"], "refresh package index"),
            Step::exec(
                &[
                    "/usr/bin/apt-get",
                    "-y",
                    "-o",
                    "Dpkg::Options::=--force-confdef",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                    "dist-upgrade",
                ],
                "upgrade packages, keeping changed config files",
            ),
        ],
    })
}

/// `RemainAfterExit` keeps a finished run `active` with its `InvocationID` and
/// `Result`, where a plain oneshot could be garbage-collected back to defaults
/// before orca reads them.
pub fn update_unit(commands: &[Step]) -> String {
    let mut unit = String::from(
        "[Unit]
Description=orca guest update (runs after an orca backup)

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=DEBIAN_FRONTEND=noninteractive
StandardOutput=journal
StandardError=journal
",
    );
    for c in commands {
        if let Step::Exec { argv, .. } = c {
            unit.push_str(&format!("ExecStart={}\n", argv.join(" ")));
        }
    }
    unit
}

/// The steps that run `commands`: on systemd guests as [`UPDATE_UNIT`], polled
/// to completion; elsewhere directly through the seam.
pub fn updater_steps(commands: Vec<Step>, os: &Os) -> Vec<Step> {
    if *os != Os::Debian {
        return commands;
    }
    vec![
        Step::Write {
            path: UPDATE_UNIT_PATH.into(),
            contents: update_unit(&commands),
            mode: "0644",
            before: None,
        },
        Step::exec(
            &["systemctl", "daemon-reload"],
            "load the transient update unit",
        ),
        Step::VerifyUnit,
        Step::RunUnit,
    ]
}

/// Takes the pre-update backup; the real one is the unit `backup` action.
pub trait PreUpdateBackup: Sync {
    fn backup<'a>(
        &'a self,
        ctid: u64,
        storage: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BackupRef>>;
}

/// How to get back to `backup`, for an error after it was taken.
fn restore_hint(ctid: u64, backup: &BackupRef) -> String {
    let payload = serde_json::json!({ "from": backup }).to_string();
    format!(
        "Restore point: {}. Restore with unit.update on lxc {ctid} (manager {}), \
         action=restore, payload {payload}",
        backup.locator, backup.manager
    )
}

static UPDATING: std::sync::Mutex<std::collections::BTreeSet<u64>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// One update per CT in this plugin process, so two concurrent calls never
/// both back up or attach to each other's unit run. Another orca instance is
/// not covered, and a caller that drops the future releases the lock while the
/// unit keeps running in the container; the unit's running check is the
/// backstop for both.
struct UpdateLock(u64);

impl UpdateLock {
    fn take(ctid: u64) -> Result<Self> {
        let mut held = UPDATING.lock().unwrap_or_else(|e| e.into_inner());
        if !held.insert(ctid) {
            bail!("an update of CT {ctid} is already in progress; nothing was changed");
        }
        Ok(Self(ctid))
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        UPDATING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

/// Back up, record the backup in [`BACKUP_MARKER`], then run the updater.
/// Everything that can refuse does so before the backup.
pub async fn run_update(
    io: &dyn GuestIo,
    backup: &dyn PreUpdateBackup,
    ctid: u64,
    payload: &GuestUpdatePayload,
) -> Result<GuestApplied> {
    const TOOL: &str = "proxmox.guest.update";
    let vmid = ctid as u32;
    let _lock = UpdateLock::take(ctid)?;
    let facts = probe(io, vmid).await?;
    let commands = updater_commands(payload.updater, &facts)?;
    refuse_blocked(TOOL, &commands)?;
    if facts.os == Os::Debian {
        let st = unit_state(io, vmid).await?;
        if unit_running(&st) {
            bail!("{TOOL}: {UPDATE_UNIT} is already running in CT {ctid}; nothing was changed");
        }
        require_own_unit(&st, false).map_err(|e| anyhow!("{TOOL}: {e}; nothing was changed"))?;
    }
    let backup_ref = backup.backup(ctid, payload.storage.as_deref()).await?;
    let marker = Step::Write {
        path: BACKUP_MARKER.to_string(),
        contents: serde_json::to_string(&backup_ref)?,
        mode: "0644",
        before: None,
    };
    let mut all = vec![marker];
    all.extend(updater_steps(commands, &facts.os));
    let outcomes = run_steps(io, ctid, &all)
        .await
        .map_err(|e| anyhow!("{e:#}. {}", restore_hint(ctid, &backup_ref)))?;
    Ok(GuestApplied {
        ctid,
        steps: outcomes,
        backup: Some(backup_ref),
    })
}

/// The plan for an update. With `facts` (a probe), the exact steps; without
/// (the unit action's dry run, which touches nothing), how they are chosen.
pub fn plan_update<A: Serialize>(
    tool: &str,
    inputs: &A,
    ctid: u64,
    payload: &GuestUpdatePayload,
    facts: Option<&StandardFacts>,
) -> Result<ExecutionPlan> {
    let mut changes = vec![
        PlannedChange::new(format!("lxc/{ctid}"), "backup").with_detail(format!(
            "vzdump snapshot to {}, waited on; a failed backup aborts the update",
            payload
                .storage
                .as_deref()
                .unwrap_or("the node's first backup storage")
        )),
        PlannedChange::new(format!("ct/{ctid}:{BACKUP_MARKER}"), "create")
            .with_detail("the backup reference; opens the in-guest `update` gate for an hour"),
    ];
    let mut summary = format!("back up then update CT {ctid}");
    match facts {
        Some(f) => {
            let commands = updater_commands(payload.updater, f)?;
            for b in blockers(&commands) {
                summary.push_str("; ");
                summary.push_str(&b);
            }
            changes.extend(
                updater_steps(commands, &f.os)
                    .iter()
                    .map(|s| s.to_change(ctid)),
            );
        }
        None => changes.push(
            PlannedChange::new(format!("ct/{ctid}: updater"), "exec").with_detail(format!(
                "{:?}, resolved from a probe at execute: {COMMUNITY_UPDATER} when present, else \
                 apt-get (Debian/Ubuntu, as {UPDATE_UNIT}) or apk (Alpine)",
                payload.updater
            )),
        ),
    }
    execute::plan(tool, inputs, summary, changes)
}

/// The unit provider's `backup` action for one LXC.
pub struct UnitBackup {
    pub endpoint: String,
}

impl PreUpdateBackup for UnitBackup {
    fn backup<'a>(
        &'a self,
        ctid: u64,
        storage: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BackupRef>> {
        Box::pin(async move {
            crate::unit_provider::ProxmoxUnitProvider::new()
                .backup_lxc(&self.endpoint, ctid, storage)
                .await
        })
    }
}

// ── verbs ───────────────────────────────────────────────────────────────────

async fn local_ct(endpoint: &str, ctid: u64) -> Result<CtRef> {
    let client = resolve_config(endpoint).await?.build_generated_client()?;
    let ct = lxc_guest::find_ct(&client, ctid).await?;
    lxc_guest::ensure_local(&ct)?;
    Ok(ct)
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct StandardAuditArgs {
    #[arg(long)]
    pub endpoint: String,
    /// LXC container id.
    #[arg(long)]
    pub ctid: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StandardAudit {
    pub ctid: u64,
    pub facts: StandardFacts,
    /// Guard violations under the guest standard (empty = compliant).
    pub violations: Vec<String>,
    /// What stands in the way of the standard, or that it replaces, which
    /// `apply` will not change on its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drift: Vec<String>,
}

/// Probe one container's guest standard: OS, root console autologin, the orca
/// `update` gate, and community-scripts' updater. Read-only; the container must
/// run on this plugin's node.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.standard.audit",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_guest_standard_audit(
    args: StandardAuditArgs,
    _ctx: &ToolCtx,
) -> Result<StandardAudit> {
    let ct = local_ct(&args.endpoint, args.ctid).await?;
    let facts = probe(&lxc_guest::SeamIo, ct.vmid as u32).await?;
    // Resource floors are checked from the cluster row by `unit.detail`; this
    // reports only what the probe reads.
    let guard = UnitGuard {
        kind: "lxc".into(),
        require_root_console: true,
        require_update_command: true,
        ..Default::default()
    };
    let violations = guard
        .check(&unit_facts(None, None, Some(&facts)))
        .iter()
        .map(|v| v.reason())
        .collect();
    let drift = audit_drift(&facts);
    Ok(StandardAudit {
        ctid: args.ctid,
        facts,
        violations,
        drift,
    })
}

fn audit_drift(f: &StandardFacts) -> Vec<String> {
    let mut drift = f.console_drift.clone();
    if f.foreign_gate {
        drift.push(format!(
            "{UPDATE_GATE} is not orca's gate; `apply` replaces it only with replace_gate \
             (kept as {REPLACED_GATE})"
        ));
    }
    if f.legacy_backup_key {
        drift.push(format!(
            "{LEGACY_BACKUP_KEY} is still present: the forced-command key the orca \
             backup replaces; remove it and its `orca-guest-backup` line in the host's \
             /etc/pve/priv/authorized_keys"
        ));
    }
    drift
}

fn default_true() -> bool {
    true
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct StandardApplyArgs {
    #[arg(long)]
    pub endpoint: String,
    /// LXC container id.
    #[arg(long)]
    pub ctid: u64,
    /// Install root console autologin.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    #[serde(default = "default_true")]
    pub console: bool,
    /// Install the `update` gate at /usr/local/bin/update.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    #[serde(default = "default_true")]
    pub update_gate: bool,
    /// Replace an existing /usr/local/bin/update that is not orca's gate,
    /// keeping it as /usr/local/bin/update.orca-replaced.
    #[arg(long)]
    #[serde(default)]
    pub replace_gate: bool,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

pub async fn apply(
    io: &dyn GuestIo,
    args: &StandardApplyArgs,
    caller: Option<&CallerIdentity>,
) -> Result<Change<GuestApplied>> {
    const TOOL: &str = "proxmox.guest.standard.apply";
    let (steps, drift) = plan_apply(io, args).await?;
    if !args.execute {
        let mut summary = format!("apply the guest standard to CT {}", args.ctid);
        for n in plan_notes(&steps).into_iter().chain(drift) {
            summary.push_str("; ");
            summary.push_str(&n);
        }
        return Ok(Change::Plan(execute::plan(
            TOOL,
            args,
            summary,
            steps.iter().map(|s| s.to_change(args.ctid)).collect(),
        )?));
    }
    execute::authorize_execute(TOOL, caller)?;
    refuse_blocked(TOOL, &steps)?;
    Ok(Change::Applied(GuestApplied {
        ctid: args.ctid,
        steps: run_steps(io, args.ctid, &steps).await?,
        backup: None,
    }))
}

/// [MUTATES STATE] Install the guest standard in an LXC: root console
/// autologin (Debian getty drop-in / Alpine inittab wrapper) and the `update`
/// gate. The container must run on this plugin's node. Without `execute`
/// returns the plan, naming any step orca's lxc-exec allowlist would refuse.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.standard.apply",
    role = "admin",
    execute_gated = false
)]
async fn proxmox_guest_standard_apply(
    args: StandardApplyArgs,
    ctx: &ToolCtx,
) -> Result<Change<GuestApplied>> {
    execute::guard("proxmox.guest.standard.apply", args.execute, ctx)?;
    local_ct(&args.endpoint, args.ctid).await?;
    apply(&lxc_guest::SeamIo, &args, ctx.caller().as_ref()).await
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GuestUpdateArgs {
    #[arg(long)]
    pub endpoint: String,
    /// LXC container id.
    #[arg(long)]
    pub ctid: u64,
    /// `auto` | `community` | `apt` | `apk`.
    #[arg(long, default_value = "auto")]
    #[serde(default)]
    pub updater: Updater,
    /// Backup storage for the pre-update vzdump.
    #[arg(long)]
    #[serde(default)]
    pub storage: Option<String>,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// [MUTATES STATE] Back an LXC up through the PVE API (vzdump, waited on),
/// record the backup in the container so its `update` gate opens for an hour,
/// then run the updater. Refused before the backup if the updater needs a
/// command outside orca's lxc-exec allowlist.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.update",
    role = "admin",
    execute_gated = false
)]
async fn proxmox_guest_update(
    args: GuestUpdateArgs,
    ctx: &ToolCtx,
) -> Result<Change<GuestApplied>> {
    const TOOL: &str = "proxmox.guest.update";
    execute::guard(TOOL, args.execute, ctx)?;
    local_ct(&args.endpoint, args.ctid).await?;
    let io = lxc_guest::SeamIo;
    let payload = GuestUpdatePayload {
        updater: args.updater,
        storage: args.storage.clone(),
        execute: args.execute,
    };
    if !args.execute {
        let facts = probe(&io, args.ctid as u32).await?;
        return Ok(Change::Plan(plan_update(
            TOOL,
            &args,
            args.ctid,
            &payload,
            Some(&facts),
        )?));
    }
    execute::authorize_execute(TOOL, ctx.caller().as_ref())?;
    let backup = UnitBackup {
        endpoint: args.endpoint.clone(),
    };
    Ok(Change::Applied(
        run_update(&io, &backup, args.ctid, &payload).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lxc_guest::fake::{self, FakeIo};

    const DEBIAN: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian";
    const ALPINE: &str = "NAME=\"Alpine Linux\"\nID=alpine";
    const ALPINE_INITTAB: &str = "::sysinit:/sbin/openrc sysinit
tty1::respawn:/sbin/getty 38400 tty1
tty2::respawn:/sbin/getty 38400 tty2
# tty3::respawn:/sbin/getty 38400 tty3
ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100
console::respawn:/sbin/getty 38400 console";
    const GETTY_UNIT: &str = "{ path=/sbin/agetty ; argv[]=/sbin/agetty -o -p -- \\u --noclear --keep-baud pts/%I 115200,38400,9600 $TERM ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
    const GETTY_CAT: &str = "# /lib/systemd/system/container-getty@.service
[Service]
ExecStart=-/sbin/agetty -o '-p -- \\\\u' --noclear --keep-baud pts/%I 115200,38400,9600 $TERM";
    const AUTOLOGIN_CAT: &str = "# /lib/systemd/system/container-getty@.service
[Service]
ExecStart=-/sbin/agetty -o '-p -- \\\\u' --noclear --keep-baud pts/%I 115200,38400,9600 $TERM

# /etc/systemd/system/container-getty@1.service.d/override.conf
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear --keep-baud tty%I 115200,38400,9600 $TERM";
    const AUTOLOGIN_UNIT: &str = "{ path=/sbin/agetty ; argv[]=/sbin/agetty --autologin root --noclear --keep-baud tty%I 115200,38400,9600 $TERM ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn admin() -> CallerIdentity {
        CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: "admin".into(),
            can_mutate: true,
        }
    }

    fn read(path: &str) -> String {
        format!("head -c 65536 -- {path}")
    }

    fn ls(path: &str) -> String {
        format!("ls -d {path}")
    }

    fn facts(os: Os) -> StandardFacts {
        StandardFacts {
            os,
            has_root_console: false,
            has_update_command: false,
            community_updater: false,
            legacy_backup_key: false,
            foreign_gate: false,
            console_drift: Vec::new(),
        }
    }

    /// Probe replies for a Debian CT: console from `systemctl show ExecStart`, gate
    /// content, whether `/usr/bin/update` exists.
    fn debian(
        console: &str,
        gate: Option<&str>,
        community: bool,
    ) -> Vec<(String, lxc_guest::ExecResult)> {
        vec![
            (read("/etc/os-release"), fake::ok(DEBIAN)),
            (
                format!("systemctl show -p ExecStart --value {DEBIAN_CONSOLE_UNIT}"),
                fake::ok(console),
            ),
            (
                format!("systemctl cat {DEBIAN_CONSOLE_UNIT}"),
                fake::ok(if console.contains("--autologin root") {
                    AUTOLOGIN_CAT
                } else {
                    GETTY_CAT
                }),
            ),
            (
                read(UPDATE_GATE),
                gate.map_or_else(|| fake::missing(UPDATE_GATE), fake::ok),
            ),
            (
                ls(COMMUNITY_UPDATER),
                if community {
                    fake::ok(COMMUNITY_UPDATER)
                } else {
                    fake::missing(COMMUNITY_UPDATER)
                },
            ),
            (ls(LEGACY_BACKUP_KEY), fake::missing(LEGACY_BACKUP_KEY)),
        ]
    }

    fn io_of(replies: Vec<(String, lxc_guest::ExecResult)>) -> FakeIo {
        FakeIo {
            replies,
            ..Default::default()
        }
    }

    fn apply_args(ctid: u64) -> StandardApplyArgs {
        StandardApplyArgs {
            endpoint: "pve".into(),
            ctid,
            console: true,
            update_gate: true,
            replace_gate: false,
            execute: false,
        }
    }

    #[test]
    fn os_detection_reads_id_and_id_like() {
        assert_eq!(os_from_release(DEBIAN), Os::Debian);
        assert_eq!(os_from_release("ID=ubuntu\nID_LIKE=debian"), Os::Debian);
        assert_eq!(os_from_release(ALPINE), Os::Alpine);
        assert_eq!(os_from_release("ID=fedora"), Os::Other);
    }

    #[test]
    fn alpine_inittab_rewrites_tty_and_console_gettys_only() {
        let with_foreign =
            format!("{ALPINE_INITTAB}\ntty4::respawn:/sbin/getty -l /bin/other 38400 tty4");
        let out = alpine_inittab(&with_foreign);
        assert!(
            out.contains("tty1::respawn:/sbin/getty -n -l /usr/local/sbin/autologin 38400 tty1")
        );
        assert!(out.contains(
            "console::respawn:/sbin/getty -n -l /usr/local/sbin/autologin 38400 console"
        ));
        assert!(out.contains("ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100"));
        assert!(out.contains("# tty3::respawn:/sbin/getty 38400 tty3"));
        assert!(out.contains("tty4::respawn:/sbin/getty -l /bin/other 38400 tty4"));
        assert_eq!(inittab_drift(&out).len(), 1, "{:?}", inittab_drift(&out));
        assert!(tty1_uses_autologin(&out));
        assert_eq!(alpine_inittab(&out).trim(), out.trim(), "idempotent");
    }

    #[test]
    fn console_alone_using_autologin_is_not_a_root_console() {
        let only_console = ALPINE_INITTAB.replace(
            "console::respawn:/sbin/getty 38400",
            "console::respawn:/sbin/getty -n -l /usr/local/sbin/autologin 38400",
        );
        assert!(!tty1_uses_autologin(&only_console));
    }

    #[test]
    fn debian_console_reads_the_effective_exec_start() {
        assert!(!debian_console_ok(GETTY_UNIT, GETTY_CAT));
        assert!(debian_console_ok(AUTOLOGIN_UNIT, AUTOLOGIN_CAT));
        for alt in ["-a root", "--autologin=root", "-aroot"] {
            assert!(
                debian_console_ok(
                    &AUTOLOGIN_UNIT.replace("--autologin root", alt),
                    &AUTOLOGIN_CAT.replace("--autologin root", alt)
                ),
                "{alt}"
            );
        }
        assert!(!debian_console_ok(
            "{ path=/sbin/agetty ; argv[]=/sbin/agetty --noclear tty1 ; ignore_errors=no ; x=--autologin root }",
            AUTOLOGIN_CAT
        ));
        // `show` cannot tell `"--autologin root"` (one argument) from two.
        let quoted = AUTOLOGIN_CAT.replace("--autologin root", "\"--autologin root\"");
        assert!(!debian_console_ok(AUTOLOGIN_UNIT, &quoted));
        // A later reset without autologin wins over an earlier drop-in.
        let reset =
            format!("{AUTOLOGIN_CAT}\n[Service]\nExecStart=\nExecStart=-/sbin/agetty tty%I");
        assert!(!debian_console_ok(AUTOLOGIN_UNIT, &reset));
        assert_eq!(effective_exec_start("ExecStart=a\nExecStart="), None);
    }

    #[test]
    fn probe_debian_with_standard_installed() {
        let gate = gate_script("pve", 116).unwrap();
        let io = io_of(debian(AUTOLOGIN_UNIT, Some(&gate), true));
        let f = rt().block_on(probe(&io, 116)).unwrap();
        assert_eq!(
            f,
            StandardFacts {
                os: Os::Debian,
                has_root_console: true,
                has_update_command: true,
                community_updater: true,
                ..facts(Os::Debian)
            }
        );
        assert!(
            io.execs
                .lock()
                .unwrap()
                .iter()
                .all(|e| e.starts_with("head ")
                    || e.starts_with("stat -L ")
                    || e.starts_with("ls ")
                    || e.starts_with("systemctl show ")
                    || e.starts_with("systemctl cat "))
        );
    }

    fn alpine_probe(inittab: &str, ignore: bool) -> Vec<(String, lxc_guest::ExecResult)> {
        vec![
            (read("/etc/os-release"), fake::ok(ALPINE)),
            (read(INITTAB), fake::ok(inittab)),
            (read(ALPINE_AUTOLOGIN), fake::ok(ALPINE_AUTOLOGIN_SH.trim())),
            (
                ls(PVE_IGNORE_INITTAB),
                if ignore {
                    fake::ok(PVE_IGNORE_INITTAB)
                } else {
                    fake::missing(PVE_IGNORE_INITTAB)
                },
            ),
            (
                read(UPDATE_GATE),
                fake::ok("#!/bin/sh\nssh host orca-guest-backup"),
            ),
            (ls(COMMUNITY_UPDATER), fake::missing(COMMUNITY_UPDATER)),
            (ls(LEGACY_BACKUP_KEY), fake::ok(LEGACY_BACKUP_KEY)),
        ]
    }

    #[test]
    fn alpine_console_needs_the_pve_ignore_marker() {
        let rewritten = alpine_inittab(ALPINE_INITTAB);
        let f = rt()
            .block_on(probe(&io_of(alpine_probe(&rewritten, false)), 120))
            .unwrap();
        assert!(
            !f.has_root_console,
            "PVE would regenerate tty1 on next start"
        );
        assert!(f.foreign_gate && f.legacy_backup_key && !f.has_update_command);
        let drift = audit_drift(&f);
        assert!(
            drift.iter().any(|d| d.contains("replace_gate")),
            "{drift:?}"
        );
        assert!(
            drift.iter().any(|d| d.contains("authorized_keys")),
            "{drift:?}"
        );

        let f = rt()
            .block_on(probe(&io_of(alpine_probe(&rewritten, true)), 120))
            .unwrap();
        assert!(f.has_root_console);
    }

    #[test]
    fn probe_is_bounded() {
        struct Hang;
        impl GuestIo for Hang {
            fn exec<'a>(
                &'a self,
                _vmid: u32,
                _argv: &'a [&'a str],
            ) -> BoxFuture<'a, Result<lxc_guest::ExecResult>> {
                Box::pin(std::future::pending())
            }
            fn write<'a>(
                &'a self,
                _vmid: u32,
                _path: &'a str,
                _contents: &'a [u8],
                _mode: Option<&'a str>,
            ) -> BoxFuture<'a, Result<()>> {
                Box::pin(async { Ok(()) })
            }
        }
        let err = rt()
            .block_on(probe_within(&Hang, 1, Duration::from_millis(20)))
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"), "{err}");
    }

    #[test]
    fn guard_requires_console_and_update_only_when_probed() {
        let base = UnitGuard::min_resources("lxc", 1, 512);
        let g = standard_guard(base.clone());
        let none = unit_facts(Some(1), Some(1024), None);
        assert_eq!(g.check(&none).len(), 2);
        let ok = StandardFacts {
            has_root_console: true,
            has_update_command: true,
            ..facts(Os::Debian)
        };
        assert!(g.is_satisfied(&unit_facts(Some(1), Some(1024), Some(&ok))));
        assert!(
            base.is_satisfied(&none),
            "the provisioning guard is unchanged"
        );
    }

    #[test]
    fn debian_apply_plans_dropin_reload_and_gate_then_runs_them() {
        let mut replies = debian(GETTY_UNIT, None, false);
        replies.push((read(DEBIAN_AUTOLOGIN), fake::missing(DEBIAN_AUTOLOGIN)));
        replies.push(("systemctl daemon-reload".into(), fake::ok("")));
        replies.push((
            "systemctl try-restart container-getty@1.service container-getty@2.service".into(),
            fake::ok(""),
        ));
        let io = io_of(replies);
        let mut args = apply_args(116);
        let Change::Plan(p) = rt().block_on(apply(&io, &args, None)).unwrap() else {
            panic!()
        };
        assert_eq!(p.changes.len(), 4, "{:?}", p.changes);
        assert!(io.writes.lock().unwrap().is_empty());

        args.execute = true;
        let Change::Applied(a) = rt().block_on(apply(&io, &args, Some(&admin()))).unwrap() else {
            panic!()
        };
        assert_eq!(a.steps.len(), 4);
        let writes = io.writes.lock().unwrap();
        assert_eq!(writes[0].0, DEBIAN_AUTOLOGIN);
        assert!(writes[0].1.contains("--autologin root"));
        assert_eq!(
            writes[1],
            (
                UPDATE_GATE.into(),
                gate_script("pve", 116).unwrap(),
                Some("0755".into())
            )
        );
    }

    #[test]
    fn existing_community_autologin_is_left_alone() {
        let gate = gate_script("pve", 116).unwrap();
        let io = io_of(debian(AUTOLOGIN_UNIT, Some(&gate), false));
        let Change::Plan(p) = rt().block_on(apply(&io, &apply_args(116), None)).unwrap() else {
            panic!()
        };
        assert!(p.changes.is_empty(), "{:?}", p.changes);
        assert!(p.summary.ends_with("nothing to change"));
    }

    /// PVE's `Alpine::setup_init` drops and regenerates every line this matches
    /// unless `/etc/.pve-ignore.inittab` exists.
    fn pve_regenerates(line: &str) -> bool {
        regex::Regex::new(r"^\s*tty\d+:\d*:[^:]*:.*getty")
            .unwrap()
            .is_match(line)
    }

    #[test]
    fn alpine_apply_writes_the_pve_ignore_marker_and_defers_the_reload() {
        let mut replies = alpine_probe(ALPINE_INITTAB, false);
        replies.retain(|(k, _)| *k != read(ALPINE_AUTOLOGIN));
        replies.push((read(ALPINE_AUTOLOGIN), fake::missing(ALPINE_AUTOLOGIN)));
        let io = io_of(replies);
        let mut args = StandardApplyArgs {
            update_gate: false,
            ..apply_args(120)
        };
        let Change::Plan(p) = rt().block_on(apply(&io, &args, None)).unwrap() else {
            panic!()
        };
        assert_eq!(p.changes.len(), 4, "{:?}", p.changes);
        assert_eq!(p.changes[3].action, "deferred");
        assert!(
            p.summary.contains("deferred to the container's next start")
                && p.summary.contains("needs allowlist: kill"),
            "{}",
            p.summary
        );
        assert!(io.writes.lock().unwrap().is_empty());

        args.execute = true;
        let Change::Applied(a) = rt().block_on(apply(&io, &args, Some(&admin()))).unwrap() else {
            panic!()
        };
        assert_eq!(a.steps[3].action, "deferred");
        let writes = io.writes.lock().unwrap();
        assert_eq!(
            writes[0],
            (
                PVE_IGNORE_INITTAB.into(),
                String::new(),
                Some("0644".into())
            )
        );
        assert_eq!(
            writes[1],
            (
                ALPINE_AUTOLOGIN.into(),
                ALPINE_AUTOLOGIN_SH.into(),
                Some("0755".into())
            )
        );
        assert_eq!(writes[2].0, INITTAB);
        let rewritten = &writes[2].1;
        assert!(tty1_uses_autologin(rewritten));
        assert!(
            rewritten.lines().any(pve_regenerates),
            "the rewritten tty lines are ones PVE regenerates, hence the marker"
        );
        assert!(
            !io.execs
                .lock()
                .unwrap()
                .iter()
                .any(|e| e.starts_with("kill")),
            "the refused reload never reaches the seam"
        );
    }

    #[test]
    fn gate_is_refused_when_its_updater_cannot_run() {
        let io = io_of(debian(GETTY_UNIT, None, true));
        let args = StandardApplyArgs {
            console: false,
            ..apply_args(116)
        };
        let Change::Plan(p) = rt().block_on(apply(&io, &args, None)).unwrap() else {
            panic!()
        };
        assert_eq!(p.changes[0].action, "refused");
        assert!(
            p.summary.contains("needs allowlist: update"),
            "{}",
            p.summary
        );
        let err = rt()
            .block_on(apply(
                &io,
                &StandardApplyArgs {
                    execute: true,
                    ..args
                },
                Some(&admin()),
            ))
            .unwrap_err()
            .to_string();
        assert!(err.contains("could never open"), "{err}");
        assert!(io.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn a_foreign_gate_is_replaced_only_on_request_and_kept() {
        let old = "#!/bin/sh\nssh -i /root/.orca/host_backup_key host\nexec /usr/bin/update";
        let mut replies = debian(GETTY_UNIT, Some(old), false);
        replies.push((read(REPLACED_GATE), fake::missing(REPLACED_GATE)));
        let io = io_of(replies);
        let args = StandardApplyArgs {
            console: false,
            ..apply_args(116)
        };
        let Change::Plan(p) = rt().block_on(apply(&io, &args, None)).unwrap() else {
            panic!()
        };
        assert_eq!(p.changes[0].action, "refused");
        assert!(p.summary.contains("replace_gate"), "{}", p.summary);

        let args = StandardApplyArgs {
            replace_gate: true,
            ..args
        };
        let Change::Plan(p) = rt().block_on(apply(&io, &args, None)).unwrap() else {
            panic!()
        };
        assert_eq!(p.changes[0].target, format!("ct/116:{REPLACED_GATE}"));
        assert_eq!(p.changes[1].action, "overwrite");
        let diff = p.changes[1].detail.as_deref().unwrap_or_default();
        assert!(
            diff.contains("-ssh -i") && diff.contains("+# orca-update-gate v1"),
            "{diff}"
        );

        let args = StandardApplyArgs {
            execute: true,
            ..args
        };
        rt().block_on(apply(&io, &args, Some(&admin()))).unwrap();
        let writes = io.writes.lock().unwrap();
        assert_eq!(
            writes[0],
            (REPLACED_GATE.into(), old.into(), Some("0755".into()))
        );
        assert_eq!(writes[1].0, UPDATE_GATE);
    }

    #[test]
    fn replace_gate_never_overwrites_a_different_kept_gate() {
        let old = "#!/bin/sh\nssh host orca-guest-backup";
        let mut replies = debian(GETTY_UNIT, Some(old), false);
        replies.push((read(REPLACED_GATE), fake::ok("#!/bin/sh\nan older gate")));
        let args = StandardApplyArgs {
            console: false,
            replace_gate: true,
            ..apply_args(116)
        };
        let Change::Plan(p) = rt().block_on(apply(&io_of(replies), &args, None)).unwrap() else {
            panic!()
        };
        assert_eq!(p.changes[0].action, "refused");
        assert!(
            p.summary.contains("already holds a different script"),
            "{}",
            p.summary
        );
    }

    #[test]
    fn a_symlinked_write_target_is_refused_before_the_write() {
        let io = io_of(vec![(
            format!("stat -c %n|%F -- /run {BACKUP_MARKER}"),
            fake::ok(&format!("/run|directory\n{BACKUP_MARKER}|symbolic link")),
        )]);
        let steps = vec![Step::Write {
            path: BACKUP_MARKER.into(),
            contents: "{}".into(),
            mode: "0644",
            before: None,
        }];
        let err = rt()
            .block_on(run_steps(&io, 1, &steps))
            .unwrap_err()
            .to_string();
        assert!(err.contains("symbolic link"), "{err}");
        assert!(io.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn gate_script_names_endpoint_and_refuses_unsafe_ones() {
        let s = gate_script("pve-1", 116).unwrap();
        assert!(s.starts_with("#!/bin/sh\n# orca-update-gate v1"));
        assert!(s.contains(BACKUP_MARKER) && s.contains("-gt 3600"));
        assert!(s.contains("--endpoint pve-1 --ctid 116"));
        assert!(s.contains("apt-get update || exit 1"));
        assert!(gate_script("pve\"; rm -rf /", 116).is_err());
        assert!(gate_script("$(id)", 116).is_err());
    }

    struct FakeBackup(std::sync::Mutex<u32>);

    impl PreUpdateBackup for FakeBackup {
        fn backup<'a>(
            &'a self,
            ctid: u64,
            _s: Option<&'a str>,
        ) -> BoxFuture<'a, Result<BackupRef>> {
            Box::pin(async move {
                *self.0.lock().unwrap() += 1;
                Ok(BackupRef {
                    locator: format!("/mnt/pve/backup/dump/vzdump-lxc-{ctid}.tar.zst"),
                    manager: "proxmox@pve".into(),
                    timestamp: 1,
                    checksum: None,
                })
            })
        }
    }

    fn start_key() -> String {
        format!("systemctl start --no-block --job-mode=fail {UPDATE_UNIT}")
    }

    fn unit_key() -> String {
        format!(
            "systemctl show -p ActiveState -p Result -p InvocationID -p FragmentPath -p DropInPaths {UPDATE_UNIT}"
        )
    }

    fn unit(
        active: &str,
        result: &str,
        id: &str,
        fragment: &str,
        dropins: &str,
    ) -> lxc_guest::ExecResult {
        fake::ok(&format!(
            "ActiveState={active}\nResult={result}\nInvocationID={id}\nFragmentPath={fragment}\nDropInPaths={dropins}"
        ))
    }

    /// An apt update whose unit run ends `active`/`failed` with `result`.
    fn apt_update_replies(result: &str) -> Vec<(String, lxc_guest::ExecResult)> {
        let mut r = debian(GETTY_UNIT, None, false);
        let fresh = unit("inactive", "success", "", UPDATE_UNIT_PATH, "");
        r.push((unit_key(), unit("inactive", "success", "", "", "")));
        r.push((unit_key(), fresh.clone()));
        r.push((unit_key(), fresh));
        r.push((
            unit_key(),
            unit("activating", "success", "a1", UPDATE_UNIT_PATH, ""),
        ));
        let end = if result == "success" {
            "active"
        } else {
            "failed"
        };
        r.push((unit_key(), unit(end, result, "a1", UPDATE_UNIT_PATH, "")));
        r.push(("systemctl daemon-reload".into(), fake::ok("")));
        r.push((start_key(), fake::ok("")));
        r.push((
            format!("systemctl status --no-pager --lines=40 {UPDATE_UNIT}"),
            fake::ok("0 upgraded"),
        ));
        r
    }

    #[test]
    fn update_backs_up_marks_then_runs_apt_as_a_unit() {
        let io = io_of(apt_update_replies("success"));
        let backup = FakeBackup(Default::default());
        let out = rt()
            .block_on(run_update(
                &io,
                &backup,
                201,
                &GuestUpdatePayload::default(),
            ))
            .unwrap();
        assert_eq!(*backup.0.lock().unwrap(), 1);
        assert_eq!(
            out.steps.last().unwrap().output.as_deref(),
            Some("0 upgraded")
        );
        let writes = io.writes.lock().unwrap();
        assert_eq!(writes[0].0, BACKUP_MARKER);
        assert!(writes[0].1.contains("vzdump-lxc-201"));
        assert_eq!(writes[1].0, UPDATE_UNIT_PATH);
        assert!(writes[1].1.contains("RemainAfterExit=yes\nEnvironment"));
        assert!(writes[1].1.contains("StandardOutput=journal"));
        assert!(
            writes[1]
                .1
                .contains("Environment=DEBIAN_FRONTEND=noninteractive")
        );
        assert!(writes[1].1.contains("ExecStart=/usr/bin/apt-get update\n"));
        assert!(writes[1].1.contains("--force-confold dist-upgrade\n"));
    }

    #[test]
    fn a_failed_update_names_the_restore_point() {
        let io = io_of(apt_update_replies("exit-code"));
        let err = rt()
            .block_on(run_update(
                &io,
                &FakeBackup(Default::default()),
                202,
                &GuestUpdatePayload::default(),
            ))
            .unwrap_err()
            .to_string();
        assert!(err.contains("Result=exit-code"), "{err}");
        assert!(
            err.contains("action=restore") && err.contains("vzdump-lxc-202.tar.zst"),
            "{err}"
        );
    }

    #[test]
    fn a_running_update_is_refused_before_the_backup() {
        let refused = |state: lxc_guest::ExecResult, ctid: u64| {
            let mut replies = debian(GETTY_UNIT, None, false);
            replies.push((unit_key(), state));
            let backup = FakeBackup(Default::default());
            let err = rt()
                .block_on(run_update(
                    &io_of(replies),
                    &backup,
                    ctid,
                    &GuestUpdatePayload::default(),
                ))
                .unwrap_err()
                .to_string();
            assert_eq!(*backup.0.lock().unwrap(), 0, "{err}");
            err
        };
        let running = unit("activating", "success", "a1", UPDATE_UNIT_PATH, "");
        assert!(refused(running, 203).contains("already running"));
        let etc = unit(
            "inactive",
            "success",
            "",
            "/etc/systemd/system/orca-guest-update.service",
            "",
        );
        assert!(refused(etc, 204).contains("loads from"));
        let dropin = unit(
            "inactive",
            "success",
            "",
            UPDATE_UNIT_PATH,
            "/etc/systemd/system/orca-guest-update.service.d/x.conf",
        );
        assert!(refused(dropin, 205).contains("has drop-ins"));
    }

    #[test]
    fn a_unit_that_never_starts_is_an_error_not_a_stale_result() {
        let mut replies = debian(GETTY_UNIT, None, false);
        let held = unit("active", "success", "old", UPDATE_UNIT_PATH, "");
        // Before the backup, after daemon-reload, before start: an earlier run
        // held active by RemainAfterExit. Stopped, it keeps its old id.
        for _ in 0..3 {
            replies.push((unit_key(), held.clone()));
        }
        replies.push((
            unit_key(),
            unit("inactive", "success", "old", UPDATE_UNIT_PATH, ""),
        ));
        replies.push(("systemctl daemon-reload".into(), fake::ok("")));
        replies.push((
            format!("systemctl stop --job-mode=fail {UPDATE_UNIT}"),
            fake::ok(""),
        ));
        replies.push((start_key(), fake::ok("")));
        replies.push((
            format!("systemctl stop --no-block {UPDATE_UNIT}"),
            fake::ok(""),
        ));
        let io = io_of(replies);
        let err = rt()
            .block_on(run_update(
                &io,
                &FakeBackup(Default::default()),
                206,
                &GuestUpdatePayload::default(),
            ))
            .unwrap_err()
            .to_string();
        assert!(err.contains("did not start"), "{err}");
        assert!(err.contains("queued start was cancelled"), "{err}");
        assert!(err.contains("action=restore"), "{err}");
        let execs = io.execs.lock().unwrap();
        assert!(!execs.iter().any(|e| e.contains("restart")), "{execs:?}");
    }

    #[test]
    fn a_run_started_after_the_backup_is_never_restarted_or_joined() {
        let mut replies = debian(GETTY_UNIT, None, false);
        let fresh = unit("inactive", "success", "", UPDATE_UNIT_PATH, "");
        replies.push((unit_key(), fresh.clone()));
        replies.push((unit_key(), fresh));
        replies.push((
            unit_key(),
            unit("activating", "success", "theirs", UPDATE_UNIT_PATH, ""),
        ));
        replies.push(("systemctl daemon-reload".into(), fake::ok("")));
        let io = io_of(replies);
        let err = rt()
            .block_on(run_update(
                &io,
                &FakeBackup(Default::default()),
                209,
                &GuestUpdatePayload::default(),
            ))
            .unwrap_err()
            .to_string();
        assert!(err.contains("started by someone else"), "{err}");
        let execs = io.execs.lock().unwrap();
        assert!(
            !execs
                .iter()
                .any(|e| e.starts_with("systemctl start") || e.starts_with("systemctl stop")),
            "{execs:?}"
        );
    }

    #[test]
    fn one_update_per_ct_at_a_time() {
        let held = UpdateLock::take(207).unwrap();
        let err = UpdateLock::take(207).err().unwrap().to_string();
        assert!(err.contains("already in progress"), "{err}");
        drop(held);
        UpdateLock::take(207).unwrap();
    }

    #[test]
    fn community_updater_is_refused_before_the_backup() {
        let io = io_of(debian(GETTY_UNIT, None, true));
        let backup = FakeBackup(Default::default());
        let err = rt()
            .block_on(run_update(
                &io,
                &backup,
                208,
                &GuestUpdatePayload::default(),
            ))
            .unwrap_err()
            .to_string();
        assert!(err.contains("needs allowlist: update"), "{err}");
        assert_eq!(
            *backup.0.lock().unwrap(),
            0,
            "no backup for an update that cannot run"
        );
        assert!(io.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn unsupported_os_updater_pairs_are_refused() {
        let alpine = facts(Os::Alpine);
        let b = blockers(&updater_commands(Updater::Auto, &alpine).unwrap());
        assert!(b[0].starts_with("needs allowlist: apk"), "{b:?}");
        assert!(updater_commands(Updater::Apt, &alpine).is_err());
        assert!(updater_commands(Updater::Apk, &facts(Os::Debian)).is_err());
        assert!(updater_commands(Updater::Community, &facts(Os::Debian)).is_err());
        assert!(updater_commands(Updater::Auto, &facts(Os::Other)).is_err());
    }

    #[test]
    fn plan_without_a_probe_names_how_the_updater_is_chosen() {
        let p = plan_update(
            "unit.update",
            &serde_json::json!({}),
            116,
            &GuestUpdatePayload::default(),
            None,
        )
        .unwrap();
        assert!(p.dry_run);
        assert_eq!(p.changes.len(), 3);
        assert_eq!(p.changes[0].action, "backup");
    }

    #[test]
    fn failed_step_names_what_already_ran() {
        let io = io_of(vec![(
            "systemctl daemon-reload".into(),
            lxc_guest::ExecResult {
                success: false,
                exit_code: Some(1),
                stdout: String::new(),
                stderr: "boom".into(),
            },
        )]);
        let steps = vec![
            Step::Write {
                path: "/a".into(),
                contents: "x".into(),
                mode: "0644",
                before: None,
            },
            Step::exec(&["systemctl", "daemon-reload"], "reload"),
        ];
        let err = rt()
            .block_on(run_steps(&io, 1, &steps))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("boom") && err.contains("Already applied: [write /a]"),
            "{err}"
        );
    }
}
