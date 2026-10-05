//! Guest standard for LXC containers: a root console that logs in without a
//! password, and a one-word `update` that only runs after an orca backup.
//!
//! * [`probe`] reads the facts through allowlisted `cat`/`ls`, feeding
//!   `UnitFacts::has_root_console` / `has_update_command`.
//! * `proxmox.guest.standard.audit` (read) reports them per container, checked
//!   against [`standard_guard`].
//! * `proxmox.guest.standard.apply` (admin, dry-run by default) installs the
//!   console autologin (Debian: a `container-getty@` drop-in; Alpine: an
//!   inittab `getty -n -l` wrapper) and the `update` gate script.
//! * `proxmox.guest.update` (admin, dry-run by default) and the unit action
//!   `update` take a vzdump backup through the PVE API, record it in the
//!   container, then run the updater.
//!
//! The backup is the same `unit.update action=backup` path core's
//! `dispatch_guarded` (orca#767) will call before a mutation. Once that is
//! wired, core passes the [`BackupRef`] it took in [`GuestUpdatePayload::backup`]
//! and the update skips its own.
//!
//! The `update` gate replaces the hand-rolled forced-command ssh key
//! ([`LEGACY_BACKUP_KEY`] → the host's `orca-guest-backup`): orca takes the
//! backup through the PVE API, so the guest holds no credential to its host.
//! The probe reports a leftover key so it can be retired.
//!
//! Every in-container command goes through orca's lxc-exec allowlist. A step
//! outside it ([`lxc_guest::PROPOSED_ALLOWLIST`]) is named in the plan as
//! `needs allowlist: X` and refused before anything runs, except the Alpine
//! inittab reload, which is deferred to the container's next start.

use plugin_toolkit::contract::plan::PlannedChange;
use plugin_toolkit::contract::{BackupRef, BoxFuture, CallerIdentity, UnitFacts, UnitGuard};
use plugin_toolkit::prelude::*;

use crate::execute::{self, Change};
use crate::lxc_guest::{self, CtRef, GuestIo, needs_allowlist};
use crate::tools::resolve_config;

pub const DEBIAN_AUTOLOGIN: &str = "/etc/systemd/system/container-getty@.service.d/autologin.conf";
pub const ALPINE_AUTOLOGIN: &str = "/usr/local/sbin/autologin";
pub const INITTAB: &str = "/etc/inittab";
pub const UPDATE_GATE: &str = "/usr/local/bin/update";
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
}

fn debian_console_ok(conf: Option<&str>) -> bool {
    conf.is_some_and(|c| c.contains("--autologin root"))
}

fn inittab_uses_autologin(inittab: &str) -> bool {
    inittab
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| l.contains("getty") && l.contains(&format!("-l {ALPINE_AUTOLOGIN}")))
}

/// Read-only: `cat` and `ls` only.
pub async fn probe(io: &dyn GuestIo, vmid: u32) -> Result<StandardFacts> {
    let release = lxc_guest::read_file(io, vmid, "/etc/os-release")
        .await?
        .unwrap_or_default();
    let os = os_from_release(&release);
    let has_root_console = match os {
        Os::Debian => debian_console_ok(
            lxc_guest::read_file(io, vmid, DEBIAN_AUTOLOGIN)
                .await?
                .as_deref(),
        ),
        Os::Alpine => {
            let inittab = lxc_guest::read_file(io, vmid, INITTAB)
                .await?
                .unwrap_or_default();
            let wrapper = lxc_guest::read_file(io, vmid, ALPINE_AUTOLOGIN).await?;
            inittab_uses_autologin(&inittab) && wrapper.is_some_and(|w| w.contains("login -f root"))
        }
        Os::Other => false,
    };
    let has_update_command = lxc_guest::read_file(io, vmid, UPDATE_GATE)
        .await?
        .is_some_and(|g| g.contains(GATE_MARKER));
    let community_updater = lxc_guest::exists(io, vmid, COMMUNITY_UPDATER).await?;
    let legacy_backup_key = lxc_guest::exists(io, vmid, LEGACY_BACKUP_KEY).await?;
    Ok(StandardFacts {
        os,
        has_root_console,
        has_update_command,
        community_updater,
        legacy_backup_key,
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

/// Alpine inittab with every getty line logging in through the autologin
/// wrapper. Lines already using it are left alone.
pub fn alpine_inittab(current: &str) -> String {
    let mut out: Vec<String> = current
        .lines()
        .map(|l| {
            let live = !l.trim_start().starts_with('#');
            match l.find("/sbin/getty ") {
                Some(i) if live && !l.contains(&format!("-l {ALPINE_AUTOLOGIN}")) => {
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

pub fn gate_script(ctid: u64) -> String {
    format!(
        r#"#!/bin/sh
{GATE_MARKER}
# Runs the updater only after orca has backed this container up.
marker={BACKUP_MARKER}
if [ ! -f "$marker" ] || [ $(( $(date +%s) - $(stat -c %Y "$marker") )) -gt {GATE_WINDOW_SECS} ]; then
  echo "update: no orca backup of CT {ctid} in the last hour." >&2
  echo "Run it through orca (backs up first): proxmox.guest.update --ctid {ctid} --execute" >&2
  exit 1
fi
if [ -x {COMMUNITY_UPDATER} ]; then exec {COMMUNITY_UPDATER} "$@"; fi
if command -v apt-get >/dev/null 2>&1; then apt-get update && exec apt-get -y dist-upgrade; fi
if command -v apk >/dev/null 2>&1; then apk update && exec apk upgrade; fi
echo "update: no updater found" >&2
exit 1
"#
    )
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
            Step::Write { .. } => None,
        }
    }

    /// A refused step that stops the run.
    fn blocker(&self) -> Option<String> {
        match self {
            Step::Exec {
                deferrable: false, ..
            } => self.refused(),
            _ => None,
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
                path, mode, before, ..
            } => PlannedChange::new(
                format!("ct/{ctid}:{path}"),
                if before.is_some() {
                    "overwrite"
                } else {
                    "create"
                },
            )
            .with_detail(format!("mode {mode}")),
            Step::Exec { argv, why, .. } => {
                let (action, detail) = match (self.blocker(), self.deferred()) {
                    (Some(b), _) => ("exec", format!("{why}; {b}")),
                    (None, Some(d)) => ("deferred", d),
                    (None, None) => ("exec", why.to_string()),
                };
                PlannedChange::new(format!("ct/{ctid}: {}", argv.join(" ")), action)
                    .with_detail(detail)
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

/// Read what `apply` would change and return its steps. Reads only.
pub async fn plan_apply(
    io: &dyn GuestIo,
    ctid: u64,
    console: bool,
    update_gate: bool,
) -> Result<Vec<Step>> {
    let vmid = ctid as u32;
    let release = lxc_guest::read_file(io, vmid, "/etc/os-release")
        .await?
        .unwrap_or_default();
    let os = os_from_release(&release);
    let mut steps = Vec::new();
    if console {
        match os {
            Os::Debian => {
                let cur = lxc_guest::read_file(io, vmid, DEBIAN_AUTOLOGIN).await?;
                if let Some(s) =
                    write_if_changed(DEBIAN_AUTOLOGIN, DEBIAN_AUTOLOGIN_CONF.into(), "0644", cur)
                {
                    steps.push(s);
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
            }
            Os::Alpine => {
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
    if update_gate {
        let cur = lxc_guest::read_file(io, vmid, UPDATE_GATE).await?;
        steps.extend(write_if_changed(
            UPDATE_GATE,
            gate_script(ctid),
            "0755",
            cur,
        ));
    }
    Ok(steps)
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

/// Run `steps`. An exec that exits non-zero stops the run with what already
/// ran named, so a partial apply never reads as success.
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
            } => io
                .write(vmid, path, contents.as_bytes(), Some(mode))
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
                match io.exec(vmid, &args).await {
                    Ok(r) if r.success => Ok(StepOutcome {
                        target: argv.join(" "),
                        action: "exec".into(),
                        output: (!r.stdout.is_empty()).then_some(r.stdout),
                    }),
                    Ok(r) => Err(anyhow!(
                        "exit {:?}: {}",
                        r.exit_code,
                        if r.stderr.is_empty() {
                            r.stdout
                        } else {
                            r.stderr
                        }
                    )),
                    Err(e) => Err(e),
                }
            }
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
#[serde(rename_all = "camelCase")]
pub struct GuestApplied {
    /// Always `false`: changes were applied.
    pub dry_run: bool,
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
    /// A backup already taken by the caller (core's pre-mutation guard). When
    /// set, no second backup is taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupRef>,
}

pub fn updater_steps(updater: Updater, facts: &StandardFacts) -> Vec<Step> {
    let resolved = match updater {
        Updater::Auto if facts.community_updater => Updater::Community,
        Updater::Auto if facts.os == Os::Alpine => Updater::Apk,
        Updater::Auto => Updater::Apt,
        u => u,
    };
    match resolved {
        Updater::Community => vec![Step::exec(
            &[COMMUNITY_UPDATER],
            "community-scripts app updater",
        )],
        Updater::Apk => vec![
            Step::exec(&["apk", "update"], "refresh package index"),
            Step::exec(&["apk", "upgrade"], "upgrade packages"),
        ],
        _ => vec![
            Step::exec(&["apt-get", "update"], "refresh package index"),
            Step::exec(
                &[
                    "apt-get",
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
    }
}

/// Takes the pre-update backup; the real one is the unit `backup` action.
pub trait PreUpdateBackup: Sync {
    fn backup<'a>(
        &'a self,
        ctid: u64,
        storage: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BackupRef>>;
}

/// Back up (unless `payload.backup` already carries one), record the backup in
/// [`BACKUP_MARKER`], then run the updater. Refuses before the backup when an
/// updater step is outside the allowlist.
pub async fn run_update(
    io: &dyn GuestIo,
    backup: &dyn PreUpdateBackup,
    ctid: u64,
    payload: &GuestUpdatePayload,
) -> Result<GuestApplied> {
    const TOOL: &str = "proxmox.guest.update";
    let facts = probe(io, ctid as u32).await?;
    let steps = updater_steps(payload.updater, &facts);
    refuse_blocked(TOOL, &steps)?;
    let backup_ref = match &payload.backup {
        Some(b) => b.clone(),
        None => backup.backup(ctid, payload.storage.as_deref()).await?,
    };
    let marker = Step::Write {
        path: BACKUP_MARKER.to_string(),
        contents: serde_json::to_string(&backup_ref)?,
        mode: "0644",
        before: None,
    };
    let mut all = vec![marker];
    all.extend(steps);
    let outcomes = run_steps(io, ctid, &all).await?;
    Ok(GuestApplied {
        dry_run: false,
        ctid,
        steps: outcomes,
        backup: Some(backup_ref),
    })
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
    lxc_guest::require_local(&ct, &crate::diagnostics::local_node())?;
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
    /// Leftovers the standard replaces, which `apply` cannot remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drift: Vec<String>,
}

/// Probe one container's guest standard: OS, root console autologin, the orca
/// `update` gate, and community-scripts' updater. Read-only (`cat`/`ls`); the
/// container must run on this plugin's node.
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
    let mut drift = Vec::new();
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
    let steps = plan_apply(io, args.ctid, args.console, args.update_gate).await?;
    if !args.execute {
        let mut summary = format!("apply the guest standard to CT {}", args.ctid);
        for b in plan_notes(&steps) {
            summary.push_str("; ");
            summary.push_str(&b);
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
        dry_run: false,
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
    if !args.execute {
        let facts = probe(&io, args.ctid as u32).await?;
        return Ok(Change::Plan(plan_update(&args, &facts)?));
    }
    execute::authorize_execute(TOOL, ctx.caller().as_ref())?;
    let payload = GuestUpdatePayload {
        updater: args.updater,
        storage: args.storage.clone(),
        backup: None,
    };
    let backup = UnitBackup {
        endpoint: args.endpoint.clone(),
    };
    Ok(Change::Applied(
        run_update(&io, &backup, args.ctid, &payload).await?,
    ))
}

pub fn plan_update(
    args: &GuestUpdateArgs,
    facts: &StandardFacts,
) -> Result<plugin_toolkit::contract::plan::ExecutionPlan> {
    let steps = updater_steps(args.updater, facts);
    let mut changes = vec![
        PlannedChange::new(format!("lxc/{}", args.ctid), "backup").with_detail(format!(
            "vzdump snapshot to {}, waited on",
            args.storage
                .as_deref()
                .unwrap_or("the node's first backup storage")
        )),
        PlannedChange::new(format!("ct/{}:{BACKUP_MARKER}", args.ctid), "write")
            .with_detail("the backup reference; opens the in-guest `update` gate for an hour"),
    ];
    changes.extend(steps.iter().map(|s| s.to_change(args.ctid)));
    let mut summary = format!("back up then update CT {}", args.ctid);
    for b in blockers(&steps) {
        summary.push_str("; ");
        summary.push_str(&b);
    }
    execute::plan("proxmox.guest.update", args, summary, changes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lxc_guest::fake::{self, FakeIo};

    const DEBIAN: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian";
    const ALPINE: &str = "NAME=\"Alpine Linux\"\nID=alpine";
    const ALPINE_INITTAB: &str = "::sysinit:/sbin/openrc sysinit
tty1::respawn:/sbin/getty 38400 tty1
# tty2::respawn:/sbin/getty 38400 tty2
console::respawn:/sbin/getty 38400 console";

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
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

    #[test]
    fn os_detection_reads_id_and_id_like() {
        assert_eq!(os_from_release(DEBIAN), Os::Debian);
        assert_eq!(os_from_release("ID=ubuntu\nID_LIKE=debian"), Os::Debian);
        assert_eq!(os_from_release(ALPINE), Os::Alpine);
        assert_eq!(os_from_release("ID=fedora"), Os::Other);
    }

    #[test]
    fn alpine_inittab_rewrites_live_gettys_only() {
        let out = alpine_inittab(ALPINE_INITTAB);
        assert!(
            out.contains("tty1::respawn:/sbin/getty -n -l /usr/local/sbin/autologin 38400 tty1")
        );
        assert!(out.contains(
            "console::respawn:/sbin/getty -n -l /usr/local/sbin/autologin 38400 console"
        ));
        assert!(
            out.contains("# tty2::respawn:/sbin/getty 38400 tty2"),
            "comments untouched"
        );
        assert!(inittab_uses_autologin(&out));
        assert_eq!(alpine_inittab(&out).trim(), out.trim(), "idempotent");
    }

    #[test]
    fn probe_debian_with_standard_installed() {
        let gate = gate_script(116);
        let io = FakeIo::with(&[
            ("cat /etc/os-release", fake::ok(DEBIAN)),
            (
                format!("cat {DEBIAN_AUTOLOGIN}").as_str(),
                fake::ok(DEBIAN_AUTOLOGIN_CONF),
            ),
            (format!("cat {UPDATE_GATE}").as_str(), fake::ok(&gate)),
            (
                format!("ls -d {COMMUNITY_UPDATER}").as_str(),
                fake::ok(COMMUNITY_UPDATER),
            ),
            (
                format!("ls -d {LEGACY_BACKUP_KEY}").as_str(),
                fake::missing(LEGACY_BACKUP_KEY),
            ),
        ]);
        let f = rt().block_on(probe(&io, 116)).unwrap();
        assert_eq!(
            f,
            StandardFacts {
                os: Os::Debian,
                has_root_console: true,
                has_update_command: true,
                community_updater: true,
                legacy_backup_key: false,
            }
        );
        assert!(
            io.execs
                .lock()
                .unwrap()
                .iter()
                .all(|e| e.starts_with("cat ") || e.starts_with("ls "))
        );
    }

    #[test]
    fn probe_alpine_missing_everything() {
        let io = FakeIo::with(&[
            ("cat /etc/os-release", fake::ok(ALPINE)),
            ("cat /etc/inittab", fake::ok(ALPINE_INITTAB)),
            (
                format!("cat {ALPINE_AUTOLOGIN}").as_str(),
                fake::missing(ALPINE_AUTOLOGIN),
            ),
            (
                format!("cat {UPDATE_GATE}").as_str(),
                fake::missing(UPDATE_GATE),
            ),
            (
                format!("ls -d {COMMUNITY_UPDATER}").as_str(),
                fake::missing(COMMUNITY_UPDATER),
            ),
            (
                format!("ls -d {LEGACY_BACKUP_KEY}").as_str(),
                fake::ok(LEGACY_BACKUP_KEY),
            ),
        ]);
        let f = rt().block_on(probe(&io, 120)).unwrap();
        assert_eq!(f.os, Os::Alpine);
        assert!(!f.has_root_console && !f.has_update_command && !f.community_updater);
        assert!(f.legacy_backup_key);
        assert!(audit_drift(&f)[0].contains("authorized_keys"));
    }

    #[test]
    fn guard_requires_console_and_update_only_when_probed() {
        let base = UnitGuard::min_resources("lxc", 1, 512);
        let g = standard_guard(base.clone());
        let none = unit_facts(Some(1), Some(1024), None);
        assert_eq!(g.check(&none).len(), 2);
        let ok = StandardFacts {
            os: Os::Debian,
            has_root_console: true,
            has_update_command: true,
            community_updater: false,
            legacy_backup_key: false,
        };
        assert!(g.is_satisfied(&unit_facts(Some(1), Some(1024), Some(&ok))));
        assert!(
            base.is_satisfied(&none),
            "the provisioning guard is unchanged"
        );
    }

    #[test]
    fn debian_apply_plans_dropin_reload_and_gate_then_runs_them() {
        let io = FakeIo::with(&[
            ("cat /etc/os-release", fake::ok(DEBIAN)),
            (
                format!("cat {DEBIAN_AUTOLOGIN}").as_str(),
                fake::missing(DEBIAN_AUTOLOGIN),
            ),
            (
                format!("cat {UPDATE_GATE}").as_str(),
                fake::missing(UPDATE_GATE),
            ),
            ("systemctl daemon-reload", fake::ok("")),
            (
                "systemctl try-restart container-getty@1.service container-getty@2.service",
                fake::ok(""),
            ),
        ]);
        let mut args = StandardApplyArgs {
            endpoint: "pve".into(),
            ctid: 116,
            console: true,
            update_gate: true,
            execute: false,
        };
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
            (UPDATE_GATE.into(), gate_script(116), Some("0755".into()))
        );
    }

    #[test]
    fn alpine_apply_writes_and_defers_the_reload_the_seam_refuses() {
        let io = FakeIo::with(&[
            ("cat /etc/os-release", fake::ok(ALPINE)),
            (
                format!("cat {ALPINE_AUTOLOGIN}").as_str(),
                fake::missing(ALPINE_AUTOLOGIN),
            ),
            ("cat /etc/inittab", fake::ok(ALPINE_INITTAB)),
        ]);
        let mut args = StandardApplyArgs {
            endpoint: "pve".into(),
            ctid: 120,
            console: true,
            update_gate: false,
            execute: false,
        };
        let Change::Plan(p) = rt().block_on(apply(&io, &args, None)).unwrap() else {
            panic!()
        };
        assert_eq!(p.changes.len(), 3, "{:?}", p.changes);
        assert_eq!(p.changes[2].action, "deferred");
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
        assert_eq!(a.steps[2].action, "deferred");
        let writes = io.writes.lock().unwrap();
        assert_eq!(
            writes[0],
            (
                ALPINE_AUTOLOGIN.into(),
                ALPINE_AUTOLOGIN_SH.into(),
                Some("0755".into())
            )
        );
        assert_eq!(writes[1].0, INITTAB);
        assert!(inittab_uses_autologin(&writes[1].1));
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
    fn apply_with_everything_in_place_changes_nothing() {
        let io = FakeIo::with(&[
            ("cat /etc/os-release", fake::ok(DEBIAN)),
            (
                format!("cat {DEBIAN_AUTOLOGIN}").as_str(),
                fake::ok(DEBIAN_AUTOLOGIN_CONF.trim()),
            ),
            (
                format!("cat {UPDATE_GATE}").as_str(),
                fake::ok(gate_script(116).trim()),
            ),
        ]);
        let args = StandardApplyArgs {
            endpoint: "pve".into(),
            ctid: 116,
            console: true,
            update_gate: true,
            execute: false,
        };
        let Change::Plan(p) = rt().block_on(apply(&io, &args, None)).unwrap() else {
            panic!()
        };
        assert!(p.changes.is_empty());
        assert!(p.summary.ends_with("nothing to change"));
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

    fn debian_probe_replies(community: bool) -> Vec<(String, lxc_guest::ExecResult)> {
        vec![
            ("cat /etc/os-release".into(), fake::ok(DEBIAN)),
            (
                format!("cat {DEBIAN_AUTOLOGIN}"),
                fake::missing(DEBIAN_AUTOLOGIN),
            ),
            (format!("cat {UPDATE_GATE}"), fake::missing(UPDATE_GATE)),
            (
                format!("ls -d {COMMUNITY_UPDATER}"),
                if community {
                    fake::ok(COMMUNITY_UPDATER)
                } else {
                    fake::missing(COMMUNITY_UPDATER)
                },
            ),
            (
                format!("ls -d {LEGACY_BACKUP_KEY}"),
                fake::missing(LEGACY_BACKUP_KEY),
            ),
        ]
    }

    #[test]
    fn update_backs_up_marks_then_runs_apt() {
        let mut io = FakeIo {
            replies: debian_probe_replies(false),
            ..Default::default()
        };
        io.replies.push(("apt-get update".into(), fake::ok("")));
        io.replies.push((
            "apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade"
                .into(),
            fake::ok("0 upgraded"),
        ));
        let backup = FakeBackup(Default::default());
        let out = rt()
            .block_on(run_update(
                &io,
                &backup,
                116,
                &GuestUpdatePayload::default(),
            ))
            .unwrap();
        assert_eq!(*backup.0.lock().unwrap(), 1);
        assert_eq!(out.steps.len(), 3);
        let writes = io.writes.lock().unwrap();
        assert_eq!(writes[0].0, BACKUP_MARKER);
        assert!(writes[0].1.contains("vzdump-lxc-116"));
    }

    #[test]
    fn update_with_a_guard_backup_skips_its_own() {
        let mut io = FakeIo {
            replies: debian_probe_replies(false),
            ..Default::default()
        };
        io.replies.push(("apt-get update".into(), fake::ok("")));
        io.replies.push((
            "apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade"
                .into(),
            fake::ok(""),
        ));
        let backup = FakeBackup(Default::default());
        let payload = GuestUpdatePayload {
            backup: Some(BackupRef {
                locator: "/x".into(),
                manager: "proxmox@pve".into(),
                timestamp: 2,
                checksum: None,
            }),
            ..Default::default()
        };
        rt().block_on(run_update(&io, &backup, 116, &payload))
            .unwrap();
        assert_eq!(*backup.0.lock().unwrap(), 0);
    }

    #[test]
    fn community_updater_is_refused_before_the_backup() {
        let io = FakeIo {
            replies: debian_probe_replies(true),
            ..Default::default()
        };
        let backup = FakeBackup(Default::default());
        let err = rt()
            .block_on(run_update(
                &io,
                &backup,
                116,
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
    fn apk_needs_allowlist() {
        let facts = StandardFacts {
            os: Os::Alpine,
            has_root_console: false,
            has_update_command: false,
            community_updater: false,
            legacy_backup_key: false,
        };
        let b = blockers(&updater_steps(Updater::Auto, &facts));
        assert!(b[0].starts_with("needs allowlist: apk"), "{b:?}");
        assert!(blockers(&updater_steps(Updater::Apt, &facts)).is_empty());
    }

    #[test]
    fn failed_step_names_what_already_ran() {
        let io = FakeIo {
            replies: vec![(
                "systemctl daemon-reload".into(),
                lxc_guest::ExecResult {
                    success: false,
                    exit_code: Some(1),
                    stdout: String::new(),
                    stderr: "boom".into(),
                },
            )],
            ..Default::default()
        };
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

    #[test]
    fn gate_script_checks_the_marker_age_and_names_the_ct() {
        let s = gate_script(116);
        assert!(s.starts_with("#!/bin/sh\n# orca-update-gate v1"));
        assert!(s.contains(BACKUP_MARKER));
        assert!(s.contains("-gt 3600"));
        assert!(s.contains("--ctid 116"));
    }
}
