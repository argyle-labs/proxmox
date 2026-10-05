//! Scheduled vzdump jobs, managed through `/cluster/backup` (the API behind
//! `/etc/pve/jobs.cfg`).
//!
//! Verbs:
//!
//! * `proxmox.backup_job.list` (read).
//! * `proxmox.backup_job.upsert` / `proxmox.backup_job.delete` (admin): dry-run
//!   by default, returning the field-by-field diff against the current job.
//!   `prune-backups` defaults to [`DEFAULT_PRUNE`], the fleet retention policy.
//! * `proxmox.guest.pxarexclude` (admin): a container's `/.pxarexclude`,
//!   written through orca's lxc-push seam.
//!
//! Diagnostics ([`diagnose_backup_jobs`]): a running guest no enabled job
//! covers, and jobs that queue behind each other on one node. vzdump holds a
//! per-node lock, so a node's jobs run one at a time: a job scheduled while an
//! earlier one is still running waits, and a long queue overruns its window.

use std::collections::{BTreeMap, HashMap};

use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::contract::diagnostics::{Finding, Severity};
use plugin_toolkit::contract::plan::PlannedChange;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::Config;
use crate::backup::{enc, post_form, put_form, raw_get_data};
use crate::execute::{self, Change};
use crate::generated::{self, types as gtypes};
use crate::lxc_guest::{self, GuestIo};
use crate::tools::{for_each_enabled_endpoint, resolve_config};

/// Fleet retention policy for scheduled backups.
pub const DEFAULT_PRUNE: &str = "keep-last=10";

/// Queue window assumed for a node with no finished vzdump task in its recent
/// history.
pub const DEFAULT_QUEUE_WINDOW_MIN: u32 = 60;

const PROVIDER: &str = "proxmox";
const WEEK_MIN: u32 = 7 * 24 * 60;
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const PRUNE_KEYS: [&str; 7] = [
    "keep-all",
    "keep-last",
    "keep-hourly",
    "keep-daily",
    "keep-weekly",
    "keep-monthly",
    "keep-yearly",
];
const MODES: [&str; 3] = ["snapshot", "suspend", "stop"];
const COMPRESS: [&str; 5] = ["0", "1", "gzip", "lzo", "zstd"];

/// Which guests a job backs up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Selection {
    Vmids { vmids: Vec<u64> },
    All { exclude: Vec<u64> },
    Pool { pool: String },
}

impl Selection {
    fn describe(&self) -> String {
        match self {
            Selection::Vmids { vmids } => format!("vmid={}", join_ids(vmids)),
            Selection::All { exclude } if exclude.is_empty() => "all".to_string(),
            Selection::All { exclude } => format!("all except {}", join_ids(exclude)),
            Selection::Pool { pool } => format!("pool={pool}"),
        }
    }
}

fn join_ids(ids: &[u64]) -> String {
    ids.iter().map(u64::to_string).collect::<Vec<_>>().join(",")
}

/// One vzdump job as `/cluster/backup` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BackupJob {
    pub id: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<Selection>,
    /// The job only runs on this node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes_template: Option<String>,
    /// Canonical `keep-*=N` list; `None` means the storage's own retention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prune_backups: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn truthy(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_i64().map(|n| n != 0),
        Value::String(s) => match s.as_str() {
            "1" | "true" => Some(true),
            "0" | "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// `pve-vmid-list`: ids separated by commas, semicolons or spaces.
pub fn parse_vmid_list(s: &str) -> Vec<u64> {
    let mut ids: Vec<u64> = s
        .split([',', ';', ' '])
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// `prune-backups` in canonical key order. PVE reports it either as a property
/// string or as an object, depending on version.
pub fn canonical_prune(v: &Value) -> Option<String> {
    let pairs: Vec<(String, String)> = match v {
        Value::String(s) => s
            .split(',')
            .filter_map(|p| {
                let (k, v) = p.split_once('=')?;
                Some((k.trim().to_string(), v.trim().to_string()))
            })
            .collect(),
        Value::Object(m) => m
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), scalar(v)?)))
            .collect(),
        _ => return None,
    };
    let mut known: Vec<(usize, String)> = pairs
        .into_iter()
        .filter_map(|(k, v)| {
            let rank = PRUNE_KEYS.iter().position(|p| *p == k)?;
            Some((rank, format!("{k}={v}")))
        })
        .collect();
    if known.is_empty() {
        return None;
    }
    known.sort();
    Some(
        known
            .into_iter()
            .map(|(_, s)| s)
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn validate_prune(s: &str) -> Result<String> {
    for part in s.split(',') {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("prune-backups '{s}': expected keep-*=N pairs"))?;
        if !PRUNE_KEYS.contains(&k.trim()) {
            bail!("prune-backups '{s}': unknown key '{k}'");
        }
        if v.trim().parse::<u32>().is_err() {
            bail!("prune-backups '{s}': '{v}' is not a count");
        }
    }
    canonical_prune(&Value::String(s.to_string()))
        .ok_or_else(|| anyhow!("prune-backups '{s}' is empty"))
}

pub fn parse_job(v: &Value) -> Option<BackupJob> {
    let get = |k: &str| v.get(k).and_then(scalar).filter(|s| !s.is_empty());
    let id = get("id")?;
    let selection = if v.get("all").and_then(truthy) == Some(true) {
        Some(Selection::All {
            exclude: get("exclude")
                .map(|s| parse_vmid_list(&s))
                .unwrap_or_default(),
        })
    } else if let Some(pool) = get("pool") {
        Some(Selection::Pool { pool })
    } else {
        get("vmid").map(|s| Selection::Vmids {
            vmids: parse_vmid_list(&s),
        })
    };
    // Jobs created before PVE 7 carry `starttime` + `dow` instead of `schedule`.
    let schedule = get("schedule").or_else(|| {
        let time = get("starttime")?;
        Some(match get("dow") {
            Some(dow) => format!("{dow} {time}"),
            None => time,
        })
    });
    Some(BackupJob {
        id,
        enabled: v.get("enabled").and_then(truthy).unwrap_or(true),
        schedule,
        storage: get("storage"),
        selection,
        node: get("node"),
        mode: get("mode"),
        compress: get("compress"),
        notes_template: get("notes-template"),
        prune_backups: v.get("prune-backups").and_then(canonical_prune),
        comment: get("comment"),
    })
}

pub fn parse_jobs(data: &Value) -> Vec<BackupJob> {
    let mut jobs: Vec<BackupJob> = data
        .as_array()
        .map(|a| a.iter().filter_map(parse_job).collect())
        .unwrap_or_default();
    jobs.sort_by(|a, b| a.id.cmp(&b.id));
    jobs
}

pub async fn fetch_jobs(cfg: &Config) -> Result<Vec<BackupJob>> {
    let http = cfg.build_reqwest_client()?;
    Ok(parse_jobs(
        &raw_get_data(&http, &cfg.base_url, "cluster/backup").await?,
    ))
}

// ── upsert planning ─────────────────────────────────────────────────────────

/// What `upsert` was asked for. `None` leaves the current value alone (or takes
/// PVE's default on create); `prune_backups` is always enforced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobSpec {
    pub id: String,
    pub enabled: Option<bool>,
    pub schedule: Option<String>,
    pub storage: Option<String>,
    pub selection: Option<Selection>,
    pub node: Option<String>,
    pub mode: Option<String>,
    pub compress: Option<String>,
    pub notes_template: Option<String>,
    pub prune_backups: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FieldChange {
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// The form write `upsert` would send.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JobWrite {
    pub create: bool,
    pub set: Vec<(String, String)>,
    /// Keys to clear (PUT `delete=`). Only switching selection clears keys.
    pub delete: Vec<String>,
    pub changes: Vec<FieldChange>,
}

impl JobWrite {
    pub fn is_noop(&self) -> bool {
        self.set.is_empty() && self.delete.is_empty()
    }
}

/// Pure: the write that turns `current` into `want`.
pub fn plan_upsert(current: Option<&BackupJob>, want: &JobSpec) -> Result<JobWrite> {
    if want.id.is_empty() || want.id.chars().any(char::is_whitespace) || want.id.len() > 50 {
        bail!(
            "job id '{}' must be 1-50 characters with no whitespace",
            want.id
        );
    }
    if let Some(m) = &want.mode
        && !MODES.contains(&m.as_str())
    {
        bail!("mode '{m}' must be one of {}", MODES.join(" | "));
    }
    if let Some(c) = &want.compress
        && !COMPRESS.contains(&c.as_str())
    {
        bail!("compress '{c}' must be one of {}", COMPRESS.join(" | "));
    }
    if want
        .notes_template
        .as_deref()
        .is_some_and(|n| n.contains(['\n', '\r']))
    {
        bail!("notes-template must be a single line");
    }
    let prune = validate_prune(&want.prune_backups)?;
    if let Some(Selection::Vmids { vmids }) = &want.selection
        && vmids.is_empty()
    {
        bail!("a vmid selection needs at least one vmid");
    }
    let create = current.is_none();
    if create {
        let mut missing = Vec::new();
        if want.schedule.is_none() {
            missing.push("schedule");
        }
        if want.storage.is_none() {
            missing.push("storage");
        }
        if want.selection.is_none() {
            missing.push("a guest selection (vmid, all or pool)");
        }
        if !missing.is_empty() {
            bail!(
                "job '{}' does not exist; creating it needs {}",
                want.id,
                missing.join(", ")
            );
        }
    }

    let mut w = JobWrite {
        create,
        ..Default::default()
    };
    let cur = current.cloned();
    let enabled = want.enabled.or(create.then_some(true));
    let fields: [(&str, Option<String>, Option<String>); 9] = [
        (
            "enabled",
            enabled.map(|b| if b { "1" } else { "0" }.to_string()),
            cur.as_ref()
                .map(|c| if c.enabled { "1" } else { "0" }.to_string()),
        ),
        (
            "schedule",
            want.schedule.clone(),
            cur.as_ref().and_then(|c| c.schedule.clone()),
        ),
        (
            "storage",
            want.storage.clone(),
            cur.as_ref().and_then(|c| c.storage.clone()),
        ),
        (
            "node",
            want.node.clone(),
            cur.as_ref().and_then(|c| c.node.clone()),
        ),
        (
            "mode",
            want.mode.clone(),
            cur.as_ref().and_then(|c| c.mode.clone()),
        ),
        (
            "compress",
            want.compress.clone(),
            cur.as_ref().and_then(|c| c.compress.clone()),
        ),
        (
            "notes-template",
            want.notes_template.clone(),
            cur.as_ref().and_then(|c| c.notes_template.clone()),
        ),
        (
            "prune-backups",
            Some(prune),
            cur.as_ref().and_then(|c| c.prune_backups.clone()),
        ),
        (
            "comment",
            want.comment.clone(),
            cur.as_ref().and_then(|c| c.comment.clone()),
        ),
    ];
    for (key, after, before) in fields {
        let Some(after) = after else { continue };
        if before.as_deref() == Some(after.as_str()) {
            continue;
        }
        w.set.push((key.to_string(), after.clone()));
        w.changes.push(FieldChange {
            field: key.to_string(),
            before,
            after: Some(after),
        });
    }

    let before_sel = cur.as_ref().and_then(|c| c.selection.clone());
    if let Some(sel) = &want.selection
        && before_sel.as_ref() != Some(sel)
    {
        let had = |k: &str| match (&before_sel, k) {
            (Some(Selection::Vmids { .. }), "vmid") => true,
            (Some(Selection::All { .. }), "all") => true,
            (Some(Selection::All { exclude }), "exclude") => !exclude.is_empty(),
            (Some(Selection::Pool { .. }), "pool") => true,
            _ => false,
        };
        let keep: &[&str] = match sel {
            Selection::Vmids { vmids } => {
                w.set.push(("vmid".into(), join_ids(vmids)));
                &["vmid"][..]
            }
            Selection::All { exclude } => {
                w.set.push(("all".into(), "1".into()));
                if !exclude.is_empty() {
                    w.set.push(("exclude".into(), join_ids(exclude)));
                }
                if exclude.is_empty() {
                    &["all"][..]
                } else {
                    &["all", "exclude"][..]
                }
            }
            Selection::Pool { pool } => {
                w.set.push(("pool".into(), pool.clone()));
                &["pool"][..]
            }
        };
        if !create {
            for k in ["vmid", "all", "exclude", "pool"] {
                if had(k) && !keep.contains(&k) {
                    w.delete.push(k.to_string());
                }
            }
        }
        w.changes.push(FieldChange {
            field: "selection".into(),
            before: before_sel.as_ref().map(Selection::describe),
            after: Some(sel.describe()),
        });
    }
    Ok(w)
}

fn planned_changes(id: &str, w: &JobWrite) -> Vec<PlannedChange> {
    let target = format!("cluster/backup/{id}");
    if w.create {
        let detail = w
            .changes
            .iter()
            .map(|c| format!("{}={}", c.field, c.after.as_deref().unwrap_or_default()))
            .collect::<Vec<_>>()
            .join(", ");
        return vec![PlannedChange::new(target, "create").with_detail(detail)];
    }
    w.changes
        .iter()
        .map(|c| {
            PlannedChange::new(&target, "set").with_detail(format!(
                "{}: {} -> {}",
                c.field,
                c.before.as_deref().unwrap_or("(unset)"),
                c.after.as_deref().unwrap_or("(unset)")
            ))
        })
        .collect()
}

// ── verbs ───────────────────────────────────────────────────────────────────

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct BackupJobListArgs {
    #[arg(long)]
    pub endpoint: String,
}

/// List the cluster's scheduled vzdump jobs.
#[orca_tool(
    domain = "proxmox",
    verb = "backup_job.list",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_backup_job_list(
    args: BackupJobListArgs,
    _ctx: &ToolCtx,
) -> Result<Vec<BackupJob>> {
    fetch_jobs(&resolve_config(&args.endpoint).await?).await
}

fn default_prune() -> String {
    DEFAULT_PRUNE.to_string()
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct BackupJobUpsertArgs {
    #[arg(long)]
    pub endpoint: String,
    /// Job id. Created when no job has it.
    #[arg(long)]
    pub id: String,
    /// PVE calendar event, e.g. `sun 01:00` or `mon..fri 03:35`.
    #[arg(long)]
    #[serde(default)]
    pub schedule: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub storage: Option<String>,
    /// Guests to back up. Repeatable or comma-separated.
    #[arg(long = "vmid", value_delimiter = ',')]
    #[serde(default)]
    pub vmids: Vec<u64>,
    /// Back up every guest (minus `exclude`).
    #[arg(long)]
    #[serde(default)]
    pub all: bool,
    /// With `all`: guests to skip.
    #[arg(long = "exclude", value_delimiter = ',')]
    #[serde(default)]
    pub exclude: Vec<u64>,
    /// Back up every guest in this pool.
    #[arg(long)]
    #[serde(default)]
    pub pool: Option<String>,
    /// Only run on this node.
    #[arg(long)]
    #[serde(default)]
    pub node: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub enabled: Option<bool>,
    /// `snapshot` | `suspend` | `stop`.
    #[arg(long)]
    #[serde(default)]
    pub mode: Option<String>,
    /// `0` | `1` | `gzip` | `lzo` | `zstd`.
    #[arg(long)]
    #[serde(default)]
    pub compress: Option<String>,
    /// e.g. `{{guestname}}`.
    #[arg(long)]
    #[serde(default)]
    pub notes_template: Option<String>,
    /// Retention; the fleet policy unless overridden.
    #[arg(long, default_value = DEFAULT_PRUNE)]
    #[serde(default = "default_prune")]
    pub prune_backups: String,
    #[arg(long)]
    #[serde(default)]
    pub comment: Option<String>,
    /// Apply. Omitted, returns the diff and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

impl BackupJobUpsertArgs {
    fn spec(&self) -> Result<JobSpec> {
        let given = [!self.vmids.is_empty(), self.all, self.pool.is_some()]
            .iter()
            .filter(|b| **b)
            .count();
        if given > 1 {
            bail!("choose one guest selection: vmid, all, or pool");
        }
        if !self.exclude.is_empty() && !self.all {
            bail!("exclude only applies with all");
        }
        let selection = if self.all {
            let mut exclude = self.exclude.clone();
            exclude.sort_unstable();
            exclude.dedup();
            Some(Selection::All { exclude })
        } else if let Some(pool) = &self.pool {
            Some(Selection::Pool { pool: pool.clone() })
        } else if !self.vmids.is_empty() {
            let mut vmids = self.vmids.clone();
            vmids.sort_unstable();
            vmids.dedup();
            Some(Selection::Vmids { vmids })
        } else {
            None
        };
        Ok(JobSpec {
            id: self.id.clone(),
            enabled: self.enabled,
            schedule: self.schedule.clone(),
            storage: self.storage.clone(),
            selection,
            node: self.node.clone(),
            mode: self.mode.clone(),
            compress: self.compress.clone(),
            notes_template: self.notes_template.clone(),
            prune_backups: self.prune_backups.clone(),
            comment: self.comment.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackupJobApplied {
    /// Always `false`: changes were applied.
    pub dry_run: bool,
    pub endpoint: String,
    pub id: String,
    pub action: String,
    pub changes: Vec<FieldChange>,
    /// The job as re-read after the write.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job: Option<BackupJob>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub async fn upsert(
    cfg: &Config,
    args: &BackupJobUpsertArgs,
    caller: Option<&CallerIdentity>,
) -> Result<Change<BackupJobApplied>> {
    const TOOL: &str = "proxmox.backup_job.upsert";
    let spec = args.spec()?;
    let jobs = fetch_jobs(cfg).await?;
    let current = jobs.iter().find(|j| j.id == spec.id);
    let w = plan_upsert(current, &spec)?;
    let verb = if w.create { "create" } else { "update" };
    if !args.execute {
        let summary = format!(
            "{verb} vzdump job '{}' on endpoint '{}'",
            spec.id, args.endpoint
        );
        return Ok(Change::Plan(execute::plan(
            TOOL,
            args,
            summary,
            planned_changes(&spec.id, &w),
        )?));
    }
    execute::authorize_execute(TOOL, caller)?;
    let mut warnings = Vec::new();
    let mut job = current.cloned();
    if !w.is_noop() {
        let http = cfg.build_reqwest_client()?;
        let root = cfg.base_url.trim_end_matches('/');
        if w.create {
            let mut pairs = vec![("id".to_string(), spec.id.clone())];
            pairs.extend(w.set.iter().cloned());
            post_form(&http, &format!("{root}/cluster/backup"), &pairs).await?;
        } else {
            let mut pairs = w.set.clone();
            if !w.delete.is_empty() {
                pairs.push(("delete".into(), w.delete.join(",")));
            }
            put_form(
                &http,
                &format!("{root}/cluster/backup/{}", enc(&spec.id)),
                &pairs,
            )
            .await?;
        }
        job = match fetch_jobs(cfg).await {
            Ok(jobs) => jobs.into_iter().find(|j| j.id == spec.id),
            Err(e) => {
                warnings.push(format!(
                    "job written, but re-reading it failed so its final state is unconfirmed: {e:#}"
                ));
                None
            }
        };
    }
    Ok(Change::Applied(BackupJobApplied {
        dry_run: false,
        endpoint: args.endpoint.clone(),
        id: spec.id,
        action: if w.is_noop() { "unchanged" } else { verb }.to_string(),
        changes: w.changes,
        job,
        warnings,
    }))
}

/// [MUTATES STATE] Create or update a scheduled vzdump job. Fields left out
/// keep their current value; `prune_backups` always applies (default
/// `keep-last=10`). Without `execute` returns the diff against the current job.
#[orca_tool(
    domain = "proxmox",
    verb = "backup_job.upsert",
    role = "admin",
    execute_gated = false
)]
async fn proxmox_backup_job_upsert(
    args: BackupJobUpsertArgs,
    ctx: &ToolCtx,
) -> Result<Change<BackupJobApplied>> {
    execute::guard("proxmox.backup_job.upsert", args.execute, ctx)?;
    let cfg = resolve_config(&args.endpoint).await?;
    upsert(&cfg, &args, ctx.caller().as_ref()).await
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct BackupJobDeleteArgs {
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub id: String,
    /// Apply. Omitted, returns the plan and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

pub async fn delete(
    cfg: &Config,
    args: &BackupJobDeleteArgs,
    caller: Option<&CallerIdentity>,
) -> Result<Change<BackupJobApplied>> {
    const TOOL: &str = "proxmox.backup_job.delete";
    let jobs = fetch_jobs(cfg).await?;
    let job = jobs.into_iter().find(|j| j.id == args.id).ok_or_else(|| {
        anyhow!(
            "no vzdump job '{}' on endpoint '{}'",
            args.id,
            args.endpoint
        )
    })?;
    let detail = format!(
        "{} {} -> {} ({})",
        job.schedule.as_deref().unwrap_or("(no schedule)"),
        job.selection
            .as_ref()
            .map(Selection::describe)
            .unwrap_or_default(),
        job.storage.as_deref().unwrap_or("(no storage)"),
        if job.enabled { "enabled" } else { "disabled" }
    );
    if !args.execute {
        return Ok(Change::Plan(execute::plan(
            TOOL,
            args,
            format!(
                "delete vzdump job '{}' on endpoint '{}'",
                args.id, args.endpoint
            ),
            vec![
                PlannedChange::new(format!("cluster/backup/{}", args.id), "delete")
                    .with_detail(detail),
            ],
        )?));
    }
    execute::authorize_execute(TOOL, caller)?;
    let http = cfg.build_reqwest_client()?;
    let url = format!(
        "{}/cluster/backup/{}",
        cfg.base_url.trim_end_matches('/'),
        enc(&args.id)
    );
    let resp = http
        .delete(&url)
        .send()
        .await
        .map_err(|e| anyhow!("DELETE {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("DELETE {url}: HTTP {}: {body}", status.as_u16());
    }
    Ok(Change::Applied(BackupJobApplied {
        dry_run: false,
        endpoint: args.endpoint.clone(),
        id: args.id.clone(),
        action: "delete".into(),
        changes: Vec::new(),
        job: Some(job),
        warnings: Vec::new(),
    }))
}

/// [MUTATES STATE] Delete a scheduled vzdump job. Without `execute` returns the
/// job that would be removed.
#[orca_tool(
    domain = "proxmox",
    verb = "backup_job.delete",
    role = "admin",
    execute_gated = false
)]
async fn proxmox_backup_job_delete(
    args: BackupJobDeleteArgs,
    ctx: &ToolCtx,
) -> Result<Change<BackupJobApplied>> {
    execute::guard("proxmox.backup_job.delete", args.execute, ctx)?;
    let cfg = resolve_config(&args.endpoint).await?;
    delete(&cfg, &args, ctx.caller().as_ref()).await
}

// ── .pxarexclude ────────────────────────────────────────────────────────────

const PXAREXCLUDE: &str = "/.pxarexclude";

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct PxarExcludeArgs {
    #[arg(long)]
    pub endpoint: String,
    /// LXC container id.
    #[arg(long)]
    pub ctid: u64,
    /// One `.pxarexclude` pattern (relative to the container root, e.g.
    /// `/data`). Repeatable; the file is replaced with exactly these lines.
    #[arg(long = "pattern", required = true)]
    pub patterns: Vec<String>,
    /// Apply. Omitted, returns the diff and changes nothing.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PxarExcludeApplied {
    /// Always `false`: changes were applied.
    pub dry_run: bool,
    pub ctid: u64,
    pub path: String,
    pub changed: bool,
    pub patterns: Vec<String>,
}

/// `-old` / `+new` lines between two files, in order of the new file.
pub(crate) fn line_diff(before: &str, after: &str) -> String {
    let old: Vec<&str> = before.lines().collect();
    let new: Vec<&str> = after.lines().collect();
    let mut out: Vec<String> = old
        .iter()
        .filter(|l| !new.contains(l))
        .map(|l| format!("-{l}"))
        .collect();
    out.extend(
        new.iter()
            .filter(|l| !old.contains(l))
            .map(|l| format!("+{l}")),
    );
    out.join(" ")
}

pub fn render_pxarexclude(patterns: &[String]) -> Result<String> {
    if patterns.is_empty() {
        bail!("at least one pattern is required");
    }
    if let Some(p) = patterns
        .iter()
        .find(|p| p.trim().is_empty() || p.contains('\n'))
    {
        bail!("pattern {p:?} must be one non-empty line");
    }
    Ok(patterns.iter().map(|p| format!("{}\n", p.trim())).collect())
}

pub async fn pxarexclude(
    io: &dyn GuestIo,
    ct: &lxc_guest::CtRef,
    local_node: &str,
    args: &PxarExcludeArgs,
    caller: Option<&CallerIdentity>,
) -> Result<Change<PxarExcludeApplied>> {
    const TOOL: &str = "proxmox.guest.pxarexclude";
    let want = render_pxarexclude(&args.patterns)?;
    lxc_guest::require_local(ct, local_node)?;
    let vmid = ct.vmid as u32;
    let current = lxc_guest::read_file(io, vmid, PXAREXCLUDE).await?;
    let changed = current.as_deref().map(str::trim) != Some(want.trim());
    if !args.execute {
        let changes = if changed {
            let action = if current.is_some() {
                "overwrite"
            } else {
                "create"
            };
            vec![
                PlannedChange::new(format!("ct/{}:{PXAREXCLUDE}", ct.vmid), action)
                    .with_detail(line_diff(current.as_deref().unwrap_or_default(), &want)),
            ]
        } else {
            Vec::new()
        };
        return Ok(Change::Plan(execute::plan(
            TOOL,
            args,
            format!("set {PXAREXCLUDE} in CT {}", ct.vmid),
            changes,
        )?));
    }
    execute::authorize_execute(TOOL, caller)?;
    if changed {
        io.write(vmid, PXAREXCLUDE, want.as_bytes(), Some("0644"))
            .await?;
    }
    Ok(Change::Applied(PxarExcludeApplied {
        dry_run: false,
        ctid: ct.vmid,
        path: PXAREXCLUDE.to_string(),
        changed,
        patterns: args.patterns.clone(),
    }))
}

/// [MUTATES STATE] Replace a container's `/.pxarexclude`, the file-level
/// exclude list vzdump's pxar archiver honours (e.g. `/data` to keep bulk data
/// out of the container backup). LXC only; the container must run on this
/// plugin's node. Without `execute` returns the diff.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.pxarexclude",
    role = "admin",
    execute_gated = false
)]
async fn proxmox_guest_pxarexclude(
    args: PxarExcludeArgs,
    ctx: &ToolCtx,
) -> Result<Change<PxarExcludeApplied>> {
    execute::guard("proxmox.guest.pxarexclude", args.execute, ctx)?;
    let client = resolve_config(&args.endpoint)
        .await?
        .build_generated_client()?;
    let ct = lxc_guest::find_ct(&client, args.ctid).await?;
    lxc_guest::ensure_local(&ct)?;
    pxarexclude(
        &lxc_guest::SeamIo,
        &ct,
        &crate::diagnostics::local_node(),
        &args,
        ctx.caller().as_ref(),
    )
    .await
}

// ── schedules ───────────────────────────────────────────────────────────────

fn parse_day(s: &str) -> Option<u32> {
    let s = s.get(..3)?;
    DAYS.iter().position(|d| *d == s).map(|i| i as u32)
}

fn parse_days(tok: &str) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for part in tok.split(',') {
        match part.split_once("..") {
            Some((a, b)) => {
                let (a, b) = (parse_day(a)?, parse_day(b)?);
                let mut d = a;
                loop {
                    out.push(d);
                    if d == b {
                        break;
                    }
                    d = (d + 1) % 7;
                }
            }
            None => out.push(parse_day(part)?),
        }
    }
    Some(out)
}

/// One calendar-event field (`*`, `5`, `1,13`, `8..17`, `*/15`, `0/30`).
fn parse_field(s: &str, max: u32) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for part in s.split(',') {
        if let Some((start, step)) = part.split_once('/') {
            let start = if start == "*" { 0 } else { start.parse().ok()? };
            let step: u32 = step.parse().ok()?;
            if step == 0 {
                return None;
            }
            out.extend((start..max).step_by(step as usize));
        } else if part == "*" {
            out.extend(0..max);
        } else if let Some((a, b)) = part.split_once("..") {
            let (a, b): (u32, u32) = (a.parse().ok()?, b.parse().ok()?);
            if b >= max || a > b {
                return None;
            }
            out.extend(a..=b);
        } else {
            let v: u32 = part.parse().ok()?;
            if v >= max {
                return None;
            }
            out.push(v);
        }
    }
    Some(out)
}

/// Start times of a PVE calendar event as minutes from Monday 00:00, or `None`
/// for a form this subset does not model (dates other than `*-*-*`, seconds
/// steps), which is reported rather than guessed.
pub fn schedule_starts(schedule: &str) -> Option<Vec<u32>> {
    let s = schedule.trim().to_ascii_lowercase();
    let all_days: Vec<u32> = (0..7).collect();
    let (days, hours, minutes) = match s.as_str() {
        "minutely" => return None,
        "hourly" => (all_days, (0..24).collect(), vec![0]),
        "daily" => (all_days, vec![0], vec![0]),
        "weekly" => (vec![0], vec![0], vec![0]),
        _ => {
            let mut days = None;
            let mut time = None;
            for tok in s.split_whitespace() {
                if tok == "*-*-*" {
                    continue;
                }
                if tok.contains(':') {
                    let mut parts = tok.split(':');
                    let h = parse_field(parts.next()?, 24)?;
                    let m = parse_field(parts.next()?, 60)?;
                    if parts.next().is_some_and(|sec| sec != "0" && sec != "00") {
                        return None;
                    }
                    if time.replace((h, m)).is_some() {
                        return None;
                    }
                } else if days.replace(parse_days(tok)?).is_some() {
                    return None;
                }
            }
            let (h, m) = time.unwrap_or((vec![0], vec![0]));
            (days.unwrap_or(all_days), h, m)
        }
    };
    let mut out = Vec::new();
    for d in &days {
        for h in &hours {
            out.extend(minutes.iter().map(|m| d * 1440 + h * 60 + m));
        }
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

// ── coverage + queue analysis ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRow {
    pub vmid: u64,
    /// `qemu` or `lxc`.
    pub kind: String,
    pub node: String,
    pub name: Option<String>,
    pub running: bool,
    pub template: bool,
    pub pool: Option<String>,
}

/// Whether `job` selects `g`, ignoring `enabled`.
pub fn selects(job: &BackupJob, g: &GuestRow) -> bool {
    if job.node.as_deref().is_some_and(|n| n != g.node) {
        return false;
    }
    match &job.selection {
        Some(Selection::Vmids { vmids }) => vmids.contains(&g.vmid),
        Some(Selection::All { exclude }) => !exclude.contains(&g.vmid),
        Some(Selection::Pool { pool }) => g.pool.as_deref() == Some(pool.as_str()),
        None => false,
    }
}

/// Running, non-template guests no enabled job selects.
pub fn uncovered<'a>(jobs: &[BackupJob], guests: &'a [GuestRow]) -> Vec<&'a GuestRow> {
    guests
        .iter()
        .filter(|g| g.running && !g.template)
        .filter(|g| !jobs.iter().any(|j| j.enabled && selects(j, g)))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueOverlap {
    pub node: String,
    /// Starts first; `second` queues behind it.
    pub first: String,
    pub second: String,
    pub gap_min: u32,
    pub window_min: u32,
    /// `window_min` came from this node's task history, not the default.
    pub measured: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueReport {
    pub overlaps: Vec<QueueOverlap>,
    /// `(job id, schedule)` that [`schedule_starts`] could not model.
    pub unparsed: Vec<(String, String)>,
}

/// Per node, enabled jobs that select at least one guest there and whose
/// starts fall within that node's queue window of each other. `windows` is the
/// longest recent vzdump run per node, in minutes.
pub fn queue_overlaps(
    jobs: &[BackupJob],
    guests: &[GuestRow],
    windows: &HashMap<String, u32>,
) -> QueueReport {
    let mut report = QueueReport::default();
    let mut starts: HashMap<&str, Vec<u32>> = HashMap::new();
    for j in jobs.iter().filter(|j| j.enabled) {
        match j.schedule.as_deref().map(|s| (s, schedule_starts(s))) {
            Some((_, Some(s))) => {
                starts.insert(&j.id, s);
            }
            Some((s, None)) => report.unparsed.push((j.id.clone(), s.to_string())),
            None => {}
        }
    }
    let mut by_node: BTreeMap<&str, Vec<&BackupJob>> = BTreeMap::new();
    for j in jobs.iter().filter(|j| starts.contains_key(j.id.as_str())) {
        let mut nodes: Vec<&str> = guests
            .iter()
            .filter(|g| !g.template && selects(j, g))
            .map(|g| g.node.as_str())
            .collect();
        nodes.sort_unstable();
        nodes.dedup();
        for n in nodes {
            by_node.entry(n).or_default().push(j);
        }
    }
    for (node, node_jobs) in by_node {
        let (window, measured) = match windows.get(node) {
            Some(w) => (*w, true),
            None => (DEFAULT_QUEUE_WINDOW_MIN, false),
        };
        for (i, a) in node_jobs.iter().enumerate() {
            for b in &node_jobs[i + 1..] {
                // The pair's closest approach in either direction, across the
                // week boundary.
                let mut best: Option<(u32, bool)> = None;
                for sa in &starts[a.id.as_str()] {
                    for sb in &starts[b.id.as_str()] {
                        let ab = (sb + WEEK_MIN - sa) % WEEK_MIN;
                        let ba = (sa + WEEK_MIN - sb) % WEEK_MIN;
                        let cand = if ab <= ba { (ab, true) } else { (ba, false) };
                        if best.is_none_or(|(g, _)| cand.0 < g) {
                            best = Some(cand);
                        }
                    }
                }
                let Some((gap, a_first)) = best else { continue };
                if gap >= window {
                    continue;
                }
                let (first, second) = if a_first { (a, b) } else { (b, a) };
                report.overlaps.push(QueueOverlap {
                    node: node.to_string(),
                    first: first.id.clone(),
                    second: second.id.clone(),
                    gap_min: gap,
                    window_min: window,
                    measured,
                });
            }
        }
    }
    report
}

/// Longest finished vzdump task in a `/nodes/{node}/tasks` listing, in whole
/// minutes (rounded up).
pub fn longest_vzdump_min(tasks: &Value) -> Option<u32> {
    tasks
        .as_array()?
        .iter()
        .filter(|t| t.get("type").and_then(Value::as_str) == Some("vzdump"))
        .filter_map(|t| {
            let start = t.get("starttime")?.as_i64()?;
            let end = t.get("endtime")?.as_i64()?;
            (end > start).then(|| ((end - start) as u64).div_ceil(60) as u32)
        })
        .max()
}

fn guest_rows(items: Vec<gtypes::GetResourcesClusterResourcesResponseItem>) -> Vec<GuestRow> {
    use gtypes::GetResourcesClusterResourcesResponseItemType as Kind;
    items
        .into_iter()
        .filter_map(|i| {
            let kind = match i.type_ {
                Kind::Qemu => "qemu",
                Kind::Lxc => "lxc",
                _ => return None,
            };
            let vmid = i.vmid.filter(|v| *v > 0)? as u64;
            Some(GuestRow {
                vmid,
                kind: kind.to_string(),
                node: i.node.filter(|n| !n.is_empty())?,
                name: i.name,
                running: i.status.as_deref() == Some("running"),
                template: i.template.unwrap_or(false),
                pool: i.pool,
            })
        })
        .collect()
}

pub fn finding_uncovered(scope: &str, endpoint: &str, g: &GuestRow, jobs: &[BackupJob]) -> Finding {
    let name = g
        .name
        .clone()
        .unwrap_or_else(|| format!("{}-{}", g.kind, g.vmid));
    let disabled: Vec<&str> = jobs
        .iter()
        .filter(|j| !j.enabled && selects(j, g))
        .map(|j| j.id.as_str())
        .collect();
    let mut detail = format!(
        "{} {} ('{name}') is running on node '{}' and no enabled vzdump job selects it, so it \
         has no scheduled backup.",
        g.kind, g.vmid, g.node
    );
    if !disabled.is_empty() {
        detail.push_str(&format!(
            " Disabled job(s) that would cover it: {}.",
            disabled.join(", ")
        ));
    }
    detail.push_str(&format!(
        " Add it to a job: `proxmox.backup_job.upsert --endpoint {endpoint} --id <job> --vmid \
         {} --execute` (keep the job's other vmids in the list).",
        g.vmid
    ));
    Finding {
        id: format!("backup-uncovered::{scope}::{}", g.vmid),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!(
            "{} {} ('{name}') is not covered by any enabled backup job",
            g.kind, g.vmid
        ),
        detail,
        repair: None,
    }
}

pub fn finding_overlap(scope: &str, o: &QueueOverlap) -> Finding {
    let window = if o.measured {
        format!(
            "the longest recent vzdump run on this node took {} min",
            o.window_min
        )
    } else {
        format!(
            "no finished vzdump run is in this node's recent task history, so a {} min run is assumed",
            o.window_min
        )
    };
    Finding {
        id: format!(
            "backup-queue::{scope}::{}::{}::{}",
            o.node, o.first, o.second
        ),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!(
            "Backup jobs '{}' and '{}' queue behind each other on node '{}'",
            o.first, o.second, o.node
        ),
        detail: format!(
            "'{}' starts {} min after '{}' on node '{}'; {window}. vzdump runs one job at a \
             time per node, so '{}' waits for '{}' to finish and the queue can overrun its \
             window. Spread the schedules further apart.",
            o.second, o.gap_min, o.first, o.node, o.second, o.first
        ),
        repair: None,
    }
}

pub fn finding_unparsed(scope: &str, id: &str, schedule: &str) -> Finding {
    Finding {
        id: format!("backup-schedule-unparsed::{scope}::{id}"),
        provider: PROVIDER.to_string(),
        severity: Severity::Info,
        title: format!("Backup job '{id}' schedule '{schedule}' was not checked for queueing"),
        detail: format!(
            "The schedule '{schedule}' of vzdump job '{id}' uses a calendar form the queue \
             check does not model, so it was left out of the per-node overlap check."
        ),
        repair: None,
    }
}

async fn diagnose_endpoint(cfg: &Config, endpoint: &str) -> Result<Vec<Finding>> {
    let http = cfg.build_reqwest_client()?;
    let client = generated::Client::new_with_client(&cfg.base_url, http.clone());
    let jobs = parse_jobs(&raw_get_data(&http, &cfg.base_url, "cluster/backup").await?);
    let guests = guest_rows(
        client
            .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
            .await
            .map_err(|e| anyhow!("cluster resources: {e}"))?
            .into_inner(),
    );
    let scope = crate::cluster::fetch_cluster_status(&client)
        .await
        .ok()
        .and_then(|s| s.name)
        .unwrap_or_else(|| endpoint.to_string());

    let mut nodes: Vec<&str> = guests.iter().map(|g| g.node.as_str()).collect();
    nodes.sort_unstable();
    nodes.dedup();
    let mut windows = HashMap::new();
    for n in nodes {
        let path = format!("nodes/{}/tasks?typefilter=vzdump&limit=100", enc(n));
        match raw_get_data(&http, &cfg.base_url, &path).await {
            Ok(tasks) => {
                if let Some(w) = longest_vzdump_min(&tasks) {
                    windows.insert(n.to_string(), w);
                }
            }
            Err(e) => {
                tracing::debug!(endpoint, node = n, error = %e, "backup queue: task history unreadable; using default window");
            }
        }
    }

    let mut findings: Vec<Finding> = uncovered(&jobs, &guests)
        .into_iter()
        .map(|g| finding_uncovered(&scope, endpoint, g, &jobs))
        .collect();
    let q = queue_overlaps(&jobs, &guests, &windows);
    findings.extend(q.overlaps.iter().map(|o| finding_overlap(&scope, o)));
    findings.extend(
        q.unparsed
            .iter()
            .map(|(id, s)| finding_unparsed(&scope, id, s)),
    );
    Ok(findings)
}

/// Coverage and queue findings for every enabled endpoint. Endpoints of one
/// cluster report the same jobs and guests, so findings are keyed by cluster
/// and deduplicated.
pub async fn diagnose_backup_jobs() -> Vec<Finding> {
    let mut findings = for_each_enabled_endpoint("diagnostics.backup_jobs", |cfg, ep| async move {
        diagnose_endpoint(&cfg, &ep.name).await
    })
    .await;
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lxc_guest::fake::{self, FakeIo};
    use plugin_toolkit::serde_json::json;
    use std::sync::{Arc, Mutex};

    /// Shape of a PVE 8 `/cluster/backup` listing.
    fn jobs_fixture() -> Value {
        json!([
            {"id": "backup-5fba7fbe", "type": "vzdump", "enabled": 1, "schedule": "sun 01:00",
             "storage": "pbs", "vmid": "103", "mode": "snapshot", "compress": "zstd",
             "notes-template": "{{guestname}}", "prune-backups": {"keep-last": "10"}},
            {"id": "backup-71860b8f", "type": "vzdump", "enabled": 1, "schedule": "03:35",
             "storage": "pbs", "vmid": "110,115", "mode": "snapshot",
             "prune-backups": "keep-daily=7,keep-last=3"},
            {"id": "backup-old", "type": "vzdump", "enabled": 0, "starttime": "02:00",
             "dow": "sat", "storage": "local", "all": 1, "exclude": "900"},
        ])
    }

    fn guest(vmid: u64, node: &str, running: bool) -> GuestRow {
        GuestRow {
            vmid,
            kind: "lxc".into(),
            node: node.into(),
            name: Some(format!("ct{vmid}")),
            running,
            template: false,
            pool: None,
        }
    }

    #[test]
    fn parses_object_and_string_prune_and_legacy_schedule() {
        let jobs = parse_jobs(&jobs_fixture());
        assert_eq!(jobs.len(), 3);
        let a = &jobs[0];
        assert_eq!(a.id, "backup-5fba7fbe");
        assert_eq!(a.prune_backups.as_deref(), Some("keep-last=10"));
        assert_eq!(a.selection, Some(Selection::Vmids { vmids: vec![103] }));
        let b = &jobs[1];
        assert_eq!(
            b.prune_backups.as_deref(),
            Some("keep-last=3,keep-daily=7"),
            "canonical key order"
        );
        assert_eq!(
            b.selection,
            Some(Selection::Vmids {
                vmids: vec![110, 115]
            })
        );
        let old = jobs.iter().find(|j| j.id == "backup-old").unwrap();
        assert!(!old.enabled);
        assert_eq!(old.schedule.as_deref(), Some("sat 02:00"));
        assert_eq!(old.selection, Some(Selection::All { exclude: vec![900] }));
    }

    #[test]
    fn missing_enabled_means_enabled() {
        let j = parse_job(&json!({"id": "x", "schedule": "01:00"})).unwrap();
        assert!(j.enabled);
    }

    fn spec(id: &str) -> JobSpec {
        JobSpec {
            id: id.into(),
            prune_backups: DEFAULT_PRUNE.into(),
            ..Default::default()
        }
    }

    #[test]
    fn create_needs_schedule_storage_and_selection() {
        let err = plan_upsert(None, &spec("new")).unwrap_err().to_string();
        assert!(err.contains("schedule") && err.contains("storage") && err.contains("selection"));

        let mut s = spec("new");
        s.schedule = Some("sun 01:00".into());
        s.storage = Some("pbs".into());
        s.selection = Some(Selection::Vmids { vmids: vec![116] });
        let w = plan_upsert(None, &s).unwrap();
        assert!(w.create);
        assert!(w.delete.is_empty());
        assert!(w.set.contains(&("enabled".into(), "1".into())));
        assert!(
            w.set
                .contains(&("prune-backups".into(), "keep-last=10".into()))
        );
        assert!(w.set.contains(&("vmid".into(), "116".into())));
    }

    #[test]
    fn update_diffs_only_changed_fields_and_enforces_retention() {
        let jobs = parse_jobs(&jobs_fixture());
        let cur = jobs.iter().find(|j| j.id == "backup-71860b8f").unwrap();
        let mut s = spec("backup-71860b8f");
        s.schedule = Some("03:35".into());
        s.storage = Some("pbs".into());
        let w = plan_upsert(Some(cur), &s).unwrap();
        assert_eq!(
            w.changes,
            vec![FieldChange {
                field: "prune-backups".into(),
                before: Some("keep-last=3,keep-daily=7".into()),
                after: Some("keep-last=10".into()),
            }]
        );

        let a = jobs.iter().find(|j| j.id == "backup-5fba7fbe").unwrap();
        let w = plan_upsert(Some(a), &spec("backup-5fba7fbe")).unwrap();
        assert!(w.is_noop(), "{w:?}");
    }

    #[test]
    fn switching_selection_clears_the_old_keys() {
        let jobs = parse_jobs(&jobs_fixture());
        let old = jobs.iter().find(|j| j.id == "backup-old").unwrap();
        let mut s = spec("backup-old");
        s.selection = Some(Selection::Vmids {
            vmids: vec![101, 102],
        });
        let w = plan_upsert(Some(old), &s).unwrap();
        assert!(w.set.contains(&("vmid".into(), "101,102".into())));
        assert_eq!(w.delete, vec!["all".to_string(), "exclude".to_string()]);
        let sel = w.changes.iter().find(|c| c.field == "selection").unwrap();
        assert_eq!(sel.before.as_deref(), Some("all except 900"));
        assert_eq!(sel.after.as_deref(), Some("vmid=101,102"));
    }

    #[test]
    fn invalid_values_are_refused() {
        let mut s = spec("x");
        s.mode = Some("fast".into());
        assert!(plan_upsert(None, &s).is_err());
        let mut s = spec("x");
        s.prune_backups = "keep-forever=1".into();
        assert!(plan_upsert(None, &s).is_err());
        let mut s = spec("x y");
        s.prune_backups = DEFAULT_PRUNE.into();
        assert!(plan_upsert(None, &s).is_err());
    }

    #[test]
    fn args_reject_two_selections() {
        let args: BackupJobUpsertArgs = serde_json::from_value(json!({
            "endpoint": "pve", "id": "x", "vmids": [1], "all": true,
        }))
        .unwrap();
        assert!(args.spec().is_err());
        let args: BackupJobUpsertArgs =
            serde_json::from_value(json!({"endpoint": "pve", "id": "x"})).unwrap();
        assert_eq!(
            args.prune_backups, DEFAULT_PRUNE,
            "retention defaults to the policy"
        );
    }

    #[test]
    fn schedules_cover_pve_forms() {
        assert_eq!(schedule_starts("sun 01:00"), Some(vec![6 * 1440 + 60]));
        assert_eq!(schedule_starts("03:35").unwrap().len(), 7);
        assert_eq!(
            schedule_starts("mon..fri 21:00").unwrap(),
            (0..5).map(|d| d * 1440 + 21 * 60).collect::<Vec<_>>()
        );
        assert_eq!(
            schedule_starts("sat..mon 00:00").unwrap(),
            vec![0, 5 * 1440, 6 * 1440],
            "wrapping range"
        );
        assert_eq!(schedule_starts("*/6:00").unwrap().len(), 28);
        assert_eq!(schedule_starts("daily"), schedule_starts("00:00"));
        assert_eq!(schedule_starts("*-*-* 02:30").unwrap().len(), 7);
        assert_eq!(schedule_starts("2026-01-01 02:30"), None);
        assert_eq!(schedule_starts("minutely"), None);
    }

    #[test]
    fn uncovered_skips_stopped_templates_and_disabled_coverage() {
        let jobs = parse_jobs(&jobs_fixture());
        let mut tmpl = guest(9000, "hyp1", true);
        tmpl.template = true;
        let guests = vec![
            guest(103, "hyp1", true),
            guest(116, "hyp1", true),
            guest(117, "hyp1", false),
            tmpl,
        ];
        let u: Vec<u64> = uncovered(&jobs, &guests).iter().map(|g| g.vmid).collect();
        assert_eq!(u, vec![116], "disabled `all` job does not count");
        let f = finding_uncovered("c", "pve", &guests[1], &jobs);
        assert!(f.detail.contains("backup-old"), "{}", f.detail);
    }

    #[test]
    fn node_restricted_job_only_covers_its_node() {
        let mut j = parse_job(&json!({"id": "j", "schedule": "01:00", "all": 1})).unwrap();
        j.node = Some("hyp1".into());
        assert!(selects(&j, &guest(1, "hyp1", true)));
        assert!(!selects(&j, &guest(2, "hyp2", true)));
    }

    #[test]
    fn pool_selection_matches_pool_members() {
        let j = parse_job(&json!({"id": "j", "schedule": "01:00", "pool": "infra"})).unwrap();
        let mut g = guest(1, "hyp1", true);
        assert!(!selects(&j, &g));
        g.pool = Some("infra".into());
        assert!(selects(&j, &g));
    }

    #[test]
    fn jobs_within_the_window_on_one_node_overlap() {
        let jobs = parse_jobs(&json!([
            {"id": "a", "schedule": "03:00", "vmid": "101"},
            {"id": "b", "schedule": "03:20", "vmid": "102"},
            {"id": "c", "schedule": "06:00", "vmid": "103"},
            {"id": "d", "schedule": "03:10", "vmid": "201"},
        ]));
        let guests = vec![
            guest(101, "hyp1", true),
            guest(102, "hyp1", true),
            guest(103, "hyp1", true),
            guest(201, "hyp2", true),
        ];
        let windows = HashMap::from([("hyp1".to_string(), 45)]);
        let r = queue_overlaps(&jobs, &guests, &windows);
        assert_eq!(
            r.overlaps,
            vec![QueueOverlap {
                node: "hyp1".into(),
                first: "a".into(),
                second: "b".into(),
                gap_min: 20,
                window_min: 45,
                measured: true,
            }],
            "c is 3h later; d is on another node"
        );
    }

    #[test]
    fn overlap_across_the_week_boundary_and_default_window() {
        let jobs = parse_jobs(&json!([
            {"id": "late", "schedule": "sun 23:50", "vmid": "1"},
            {"id": "early", "schedule": "mon 00:10", "vmid": "2"},
            {"id": "odd", "schedule": "2026-01-01 00:00", "vmid": "1"},
        ]));
        let guests = vec![guest(1, "n", true), guest(2, "n", true)];
        let r = queue_overlaps(&jobs, &guests, &HashMap::new());
        assert_eq!(r.overlaps.len(), 1);
        let o = &r.overlaps[0];
        assert_eq!(
            (o.first.as_str(), o.second.as_str(), o.gap_min),
            ("late", "early", 20)
        );
        assert!(!o.measured);
        assert_eq!(o.window_min, DEFAULT_QUEUE_WINDOW_MIN);
        assert_eq!(r.unparsed, vec![("odd".into(), "2026-01-01 00:00".into())]);
    }

    #[test]
    fn longest_vzdump_ignores_running_and_other_tasks() {
        let tasks = json!([
            {"type": "vzdump", "starttime": 1000, "endtime": 1000 + 25 * 60 + 1},
            {"type": "vzdump", "starttime": 5000},
            {"type": "qmstart", "starttime": 0, "endtime": 99999},
        ]);
        assert_eq!(longest_vzdump_min(&tasks), Some(26));
        assert_eq!(longest_vzdump_min(&json!([])), None);
    }

    // ── HTTP-level tests against recorded PVE responses ───────────────────

    fn reply(status: u16, data: Value) -> String {
        let body = serde_json::to_vec(&json!({ "data": data })).unwrap();
        json!({
            "status": status,
            "headers": [["content-type", "application/json"]],
            "body": body,
        })
        .to_string()
    }

    fn test_config() -> Config {
        Config::new(
            "https://10.0.0.5:8006/api2/json",
            "orca@pve!orca",
            "00000000-0000-0000-0000-000000000000",
        )
    }

    /// Answer `http.request` by method + path; `responses` are consumed in
    /// order per route so a re-read can differ from the first read.
    fn run_against<T>(
        routes: Vec<(&'static str, &'static str, Vec<String>)>,
        f: impl AsyncFnOnce() -> T,
    ) -> (T, Vec<Value>) {
        let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
        let log = seen.clone();
        let routes = Arc::new(Mutex::new(routes));
        let out = plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, raw: &str| {
                assert_eq!(cap, "http.request");
                let req: Value = serde_json::from_str(raw).unwrap();
                log.lock().unwrap().push(req.clone());
                let method = req["method"].as_str().unwrap().to_string();
                let url = req["url"].as_str().unwrap().to_string();
                let path = url.split('?').next().unwrap().to_string();
                let mut routes = routes.lock().unwrap();
                for (m, suffix, bodies) in routes.iter_mut() {
                    if *m == method && path.ends_with(*suffix) {
                        return Ok(if bodies.len() > 1 {
                            bodies.remove(0)
                        } else {
                            bodies[0].clone()
                        });
                    }
                }
                panic!("unexpected request {method} {url}");
            }),
            || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(f())
            },
        );
        let seen = seen.lock().unwrap().clone();
        (out, seen)
    }

    fn admin() -> CallerIdentity {
        CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: "admin".into(),
            can_mutate: true,
        }
    }

    fn body_of(req: &Value) -> String {
        let bytes: Vec<u8> = serde_json::from_value(req["body"].clone()).unwrap();
        String::from_utf8(bytes).unwrap()
    }

    fn upsert_args(v: Value) -> BackupJobUpsertArgs {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn dry_run_upsert_returns_the_diff_and_never_writes() {
        let routes = vec![("GET", "/cluster/backup", vec![reply(200, jobs_fixture())])];
        let args = upsert_args(json!({"endpoint": "pve", "id": "backup-71860b8f"}));
        let (res, seen) = run_against(routes, async || upsert(&test_config(), &args, None).await);
        let Change::Plan(plan) = res.unwrap() else {
            panic!("expected a plan")
        };
        assert!(plan.dry_run && plan.detailed);
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(
            plan.changes[0].detail.as_deref(),
            Some("prune-backups: keep-last=3,keep-daily=7 -> keep-last=10")
        );
        assert!(seen.iter().all(|r| r["method"] == "GET"));
    }

    #[test]
    fn execute_update_puts_changes_with_delete_and_rereads() {
        let after = json!([{"id": "backup-old", "enabled": 1, "schedule": "sat 02:00",
            "storage": "local", "vmid": "116", "prune-backups": "keep-last=10"}]);
        let routes = vec![
            (
                "GET",
                "/cluster/backup",
                vec![reply(200, jobs_fixture()), reply(200, after)],
            ),
            (
                "PUT",
                "/cluster/backup/backup-old",
                vec![reply(200, Value::Null)],
            ),
        ];
        let args = upsert_args(json!({
            "endpoint": "pve", "id": "backup-old", "vmids": [116], "enabled": true,
            "execute": true,
        }));
        let (res, seen) = run_against(routes, async || {
            upsert(&test_config(), &args, Some(&admin())).await
        });
        let Change::Applied(out) = res.unwrap() else {
            panic!("expected applied")
        };
        assert_eq!(out.action, "update");
        assert_eq!(
            out.job.unwrap().selection,
            Some(Selection::Vmids { vmids: vec![116] })
        );
        let put = seen.iter().find(|r| r["method"] == "PUT").unwrap();
        let body = body_of(put);
        assert!(body.contains("vmid=116"), "{body}");
        assert!(body.contains("enabled=1"), "{body}");
        assert!(body.contains("prune-backups=keep-last%3D10"), "{body}");
        assert!(body.contains("delete=all%2Cexclude"), "{body}");
    }

    #[test]
    fn execute_create_posts_the_id() {
        let routes = vec![
            ("GET", "/cluster/backup", vec![reply(200, json!([]))]),
            ("POST", "/cluster/backup", vec![reply(200, Value::Null)]),
        ];
        let args = upsert_args(json!({
            "endpoint": "pve", "id": "ct116", "vmids": [116], "schedule": "sun 01:00",
            "storage": "pbs", "execute": true,
        }));
        let (res, seen) = run_against(routes, async || {
            upsert(&test_config(), &args, Some(&admin())).await
        });
        let Change::Applied(out) = res.unwrap() else {
            panic!("expected applied")
        };
        assert_eq!(out.action, "create");
        let post = seen.iter().find(|r| r["method"] == "POST").unwrap();
        let body = body_of(post);
        assert!(body.starts_with("id=ct116"), "{body}");
        assert!(
            body.contains("schedule=sun%2001%3A00") || body.contains("schedule=sun+01%3A00"),
            "{body}"
        );
    }

    #[test]
    fn execute_without_admin_is_refused_before_writing() {
        let routes = vec![("GET", "/cluster/backup", vec![reply(200, jobs_fixture())])];
        let args = upsert_args(json!({
            "endpoint": "pve", "id": "backup-71860b8f", "execute": true,
        }));
        let (res, seen) = run_against(routes, async || upsert(&test_config(), &args, None).await);
        assert!(res.unwrap_err().to_string().contains("no caller identity"));
        assert!(seen.iter().all(|r| r["method"] == "GET"));
    }

    #[test]
    fn delete_plans_then_deletes() {
        let routes = vec![
            ("GET", "/cluster/backup", vec![reply(200, jobs_fixture())]),
            (
                "DELETE",
                "/cluster/backup/backup-old",
                vec![reply(200, Value::Null)],
            ),
        ];
        let plan_args = BackupJobDeleteArgs {
            endpoint: "pve".into(),
            id: "backup-old".into(),
            execute: false,
        };
        let (res, seen) = run_against(routes.clone(), async || {
            delete(&test_config(), &plan_args, None).await
        });
        assert!(matches!(res.unwrap(), Change::Plan(p) if p.changes[0].action == "delete"));
        assert!(seen.iter().all(|r| r["method"] == "GET"));

        let exec_args = BackupJobDeleteArgs {
            execute: true,
            ..plan_args
        };
        let (res, seen) = run_against(routes, async || {
            delete(&test_config(), &exec_args, Some(&admin())).await
        });
        assert!(matches!(res.unwrap(), Change::Applied(a) if a.action == "delete"));
        assert!(seen.iter().any(|r| r["method"] == "DELETE"));
    }

    #[test]
    fn delete_of_unknown_job_is_an_error() {
        let routes = vec![("GET", "/cluster/backup", vec![reply(200, json!([]))])];
        let args = BackupJobDeleteArgs {
            endpoint: "pve".into(),
            id: "nope".into(),
            execute: false,
        };
        let (res, _) = run_against(routes, async || delete(&test_config(), &args, None).await);
        assert!(res.unwrap_err().to_string().contains("no vzdump job"));
    }

    #[test]
    fn diagnose_endpoint_reports_uncovered_and_queued() {
        let routes = vec![
            (
                "GET",
                "/cluster/backup",
                vec![reply(
                    200,
                    json!([
                        {"id": "a", "enabled": 1, "schedule": "03:35", "vmid": "110"},
                        {"id": "b", "enabled": 1, "schedule": "03:50", "vmid": "115"},
                    ]),
                )],
            ),
            (
                "GET",
                "/cluster/resources",
                vec![reply(
                    200,
                    json!([
                        {"id": "lxc/110", "type": "lxc", "node": "hyp1", "vmid": 110, "status": "running"},
                        {"id": "lxc/115", "type": "lxc", "node": "hyp1", "vmid": 115, "status": "running"},
                        {"id": "lxc/116", "type": "lxc", "node": "hyp1", "vmid": 116, "status": "running", "name": "media"},
                    ]),
                )],
            ),
            (
                "GET",
                "/cluster/status",
                vec![reply(
                    200,
                    json!([{"type": "cluster", "name": "lab", "id": "cluster"}]),
                )],
            ),
            (
                "GET",
                "/nodes/hyp1/tasks",
                vec![reply(
                    200,
                    json!([{"type": "vzdump", "starttime": 0, "endtime": 40 * 60}]),
                )],
            ),
        ];
        let (res, seen) = run_against(routes, async || {
            diagnose_endpoint(&test_config(), "pve").await
        });
        let findings = res.unwrap();
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"backup-uncovered::lab::116"), "{ids:?}");
        assert!(ids.contains(&"backup-queue::lab::hyp1::a::b"), "{ids:?}");
        assert!(seen.iter().all(|r| r["method"] == "GET"));
    }

    #[test]
    fn pxarexclude_diffs_then_writes_only_on_change() {
        let ct = lxc_guest::CtRef {
            node: "hyp1".into(),
            vmid: 116,
            name: None,
            running: true,
        };
        let args = PxarExcludeArgs {
            endpoint: "pve".into(),
            ctid: 116,
            patterns: vec!["/data".into()],
            execute: false,
        };
        let io = FakeIo::with(&[(
            "head -c 65536 -- /.pxarexclude",
            fake::missing("/.pxarexclude"),
        )]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let plan = rt
            .block_on(pxarexclude(&io, &ct, "hyp1", &args, None))
            .unwrap();
        let Change::Plan(p) = plan else { panic!() };
        assert_eq!(p.changes[0].action, "create");
        assert_eq!(p.changes[0].detail.as_deref(), Some("+/data"));
        assert!(io.writes.lock().unwrap().is_empty());

        let exec = PxarExcludeArgs {
            execute: true,
            ..args
        };
        let out = rt
            .block_on(pxarexclude(&io, &ct, "hyp1", &exec, Some(&admin())))
            .unwrap();
        assert!(matches!(out, Change::Applied(a) if a.changed));
        assert_eq!(
            io.writes.lock().unwrap()[0],
            (
                "/.pxarexclude".into(),
                "/data\n".into(),
                Some("0644".into())
            )
        );

        let same = FakeIo::with(&[("head -c 65536 -- /.pxarexclude", fake::ok("/data"))]);
        let out = rt
            .block_on(pxarexclude(&same, &ct, "hyp1", &exec, Some(&admin())))
            .unwrap();
        assert!(matches!(out, Change::Applied(a) if !a.changed));
        assert!(same.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn pxarexclude_refuses_a_container_on_another_node() {
        let ct = lxc_guest::CtRef {
            node: "hyp2".into(),
            vmid: 116,
            name: None,
            running: true,
        };
        let args = PxarExcludeArgs {
            endpoint: "pve".into(),
            ctid: 116,
            patterns: vec!["/data".into()],
            execute: false,
        };
        let io = FakeIo::default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let err = rt
            .block_on(pxarexclude(&io, &ct, "hyp1", &args, None))
            .unwrap_err();
        assert!(err.to_string().contains("runs on node 'hyp2'"));
        assert!(io.execs.lock().unwrap().is_empty());
    }
}
