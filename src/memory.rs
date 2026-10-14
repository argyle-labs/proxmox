//! Node memory: three independent rules over the PVE API.
//!
//! * **Over-allocation** — configured memory of every guest that is running or
//!   starts on boot, plus a host reserve, against physical RAM. A VM with a
//!   balloon target counts at that floor. [`check_allocation`] is the guard a
//!   guest create runs first.
//! * **Under-use** — each guest's RRD memory average and peak over a window
//!   against its allocation. Informational only; nothing is resized.
//! * **Live pressure** — the node's current used RAM and swap.
//!
//! A QEMU VM's RRD `mem` is the host's view of the guest; without a guest agent
//! reporting through the balloon driver it overstates real use, so VM usage is
//! marked as an estimate.

use std::collections::BTreeMap;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};
use plugin_toolkit::prelude::*;
use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json::Value;

use crate::Config;
use crate::GuestKind;
use crate::backup::{enc, raw_get_data};
use crate::tools::{for_each_enabled_endpoint, resolve_config};

const PROVIDER: &str = "proxmox";
const MIB: f64 = 1024.0 * 1024.0;
/// PVE's memory default when a create omits `memory`.
pub const PVE_DEFAULT_MEMORY_MIB: u64 = 512;
const TIMEFRAMES: [&str; 5] = ["hour", "day", "week", "month", "year"];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryThresholds {
    /// RAM held back for the host itself.
    pub reserve_mib: u64,
    /// RRD window for under-use: hour, day, week, month or year.
    pub timeframe: String,
    /// A guest averaging below this share of its allocation is under-used.
    pub idle_pct: f64,
    /// Margin added to a guest's peak when suggesting a size.
    pub headroom_pct: f64,
    /// Used RAM at or above this share of physical is pressure.
    pub mem_pressure_pct: f64,
    /// Used swap above this share of total swap is pressure.
    pub swap_pressure_pct: f64,
}

impl Default for MemoryThresholds {
    fn default() -> Self {
        Self {
            reserve_mib: 4096,
            timeframe: "week".into(),
            idle_pct: 40.0,
            headroom_pct: 20.0,
            mem_pressure_pct: 90.0,
            swap_pressure_pct: 25.0,
        }
    }
}

// ── rule 1: over-allocation ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct GuestMem {
    pub vmid: u64,
    pub name: String,
    pub kind: GuestKind,
    pub memory_mib: u64,
    /// QEMU balloon target; 0 means ballooning is off.
    pub balloon_mib: Option<u64>,
    pub running: bool,
    pub onboot: bool,
}

impl GuestMem {
    pub fn allocated_mib(&self) -> u64 {
        match (self.kind, self.balloon_mib) {
            (GuestKind::Qemu, Some(b)) if b > 0 => b,
            _ => self.memory_mib,
        }
    }

    fn counted(&self) -> bool {
        self.running || self.onboot
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GuestAllocRow {
    pub vmid: u64,
    pub name: String,
    pub kind: String,
    pub allocated_mib: u64,
    pub running: bool,
    pub onboot: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AllocationReport {
    pub node: String,
    pub physical_mib: u64,
    pub reserve_mib: u64,
    /// Sum over running and onboot guests.
    pub allocated_mib: u64,
    /// `physical - reserve - allocated`; negative when over-allocated.
    pub headroom_mib: i64,
    pub over_allocated: bool,
    pub guests: Vec<GuestAllocRow>,
    /// Stopped guests that do not start on boot; not in `allocated_mib`.
    pub stopped: Vec<GuestAllocRow>,
}

pub fn allocation(
    node: &str,
    physical_mib: u64,
    reserve_mib: u64,
    guests: &[GuestMem],
) -> AllocationReport {
    let (counted, stopped): (Vec<_>, Vec<_>) = guests.iter().partition(|g| g.counted());
    let row = |g: &&GuestMem| GuestAllocRow {
        vmid: g.vmid,
        name: g.name.clone(),
        kind: g.kind.as_str().to_string(),
        allocated_mib: g.allocated_mib(),
        running: g.running,
        onboot: g.onboot,
    };
    let allocated_mib: u64 = counted.iter().map(|g| g.allocated_mib()).sum();
    let headroom_mib = physical_mib as i64 - reserve_mib as i64 - allocated_mib as i64;
    AllocationReport {
        node: node.to_string(),
        physical_mib,
        reserve_mib,
        allocated_mib,
        headroom_mib,
        over_allocated: headroom_mib < 0,
        guests: counted.iter().map(row).collect(),
        stopped: stopped.iter().map(row).collect(),
    }
}

/// Refuse setting guest `vmid` (or a new guest when `None`) to `new_mib` when
/// the node would then be over-allocated. The guest is assumed to run.
pub fn check_allocation(
    r: &AllocationReport,
    vmid: Option<u64>,
    new_mib: u64,
) -> std::result::Result<(), String> {
    let current = vmid
        .and_then(|v| r.guests.iter().find(|g| g.vmid == v))
        .map_or(0, |g| g.allocated_mib);
    let others = r.allocated_mib - current;
    let after = others + new_mib;
    if after + r.reserve_mib <= r.physical_mib {
        return Ok(());
    }
    let largest = r.physical_mib.saturating_sub(r.reserve_mib + others);
    let target = vmid.map_or_else(|| "a new guest".to_string(), |v| format!("guest {v}"));
    Err(format!(
        "giving {target} {new_mib} MiB would allocate {after} MiB on node '{}' ({others} MiB to \
         other running/onboot guests) plus a {} MiB host reserve, over its {} MiB physical; \
         largest value that fits is {largest} MiB",
        r.node, r.reserve_mib, r.physical_mib
    ))
}

fn finding_over_allocated(scope: &str, r: &AllocationReport) -> Finding {
    Finding {
        id: format!("memory-overallocated::{scope}::{}", r.node),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!(
            "PVE node '{}' is over-allocated: {} MiB to guests + {} MiB reserve > {} MiB physical",
            r.node, r.allocated_mib, r.reserve_mib, r.physical_mib
        ),
        detail: format!(
            "{} running or onboot guests on node '{}' are configured for {} MiB (VMs at their \
             balloon floor where set). With the {} MiB host reserve that is {} MiB more than the \
             node's {} MiB of RAM. If they all claim what they are allowed, something is \
             OOM-killed. {} stopped guests ({} MiB) are not counted. Lower a guest's memory or \
             move one to another node.",
            r.guests.len(),
            r.node,
            r.allocated_mib,
            r.reserve_mib,
            -r.headroom_mib,
            r.physical_mib,
            r.stopped.len(),
            r.stopped.iter().map(|g| g.allocated_mib).sum::<u64>(),
        ),
        repair: None,
    }
}

// ── rule 2: under-use ──────────────────────────────────────────────────────

/// One RRD series as `(time, mem bytes)`; buckets with no value are dropped.
pub fn rrd_mem_series(rrd: &Value) -> Series {
    rrd.as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s.get("time")?.as_i64()?, s.get("mem")?.as_f64()?)))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GuestUsage {
    pub vmid: u64,
    pub name: String,
    pub kind: String,
    pub allocated_mib: u64,
    pub avg_mib: u64,
    pub peak_mib: u64,
    pub avg_pct: f64,
    pub under_used: bool,
    /// `peak * (1 + headroom)`, rounded up to 256 MiB, never above the allocation.
    pub suggested_mib: u64,
    pub reclaimable_mib: u64,
    /// VM figures are the host's view and overstate use without a guest agent.
    pub estimate: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UsageReport {
    pub node: String,
    pub timeframe: String,
    pub allocated_mib: u64,
    /// Guests summed per RRD timestamp, then averaged.
    pub avg_mib: u64,
    /// Highest per-timestamp sum of the guests' bucket maxima.
    pub peak_mib: u64,
    pub reclaimable_mib: u64,
    pub guests: Vec<GuestUsage>,
}

fn mean(s: &[(i64, f64)]) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    s.iter().map(|(_, v)| v).sum::<f64>() / s.len() as f64
}

fn peak(s: &[(i64, f64)]) -> f64 {
    s.iter().map(|(_, v)| *v).fold(0.0, f64::max)
}

/// `None` when the guest has no samples in the window.
pub fn guest_usage(
    g: &GuestMem,
    avg: &[(i64, f64)],
    max: &[(i64, f64)],
    t: &MemoryThresholds,
) -> Option<GuestUsage> {
    if avg.is_empty() && max.is_empty() {
        return None;
    }
    let allocated_mib = g.allocated_mib();
    let avg_mib = (mean(avg) / MIB).round() as u64;
    let peak_mib = ((peak(max).max(peak(avg))) / MIB).ceil() as u64;
    let avg_pct = if allocated_mib == 0 {
        0.0
    } else {
        avg_mib as f64 / allocated_mib as f64 * 100.0
    };
    let padded = (peak_mib as f64 * (1.0 + t.headroom_pct / 100.0)).ceil() as u64;
    let suggested_mib = padded.div_ceil(256).saturating_mul(256).min(allocated_mib);
    let under_used = allocated_mib > 0 && avg_pct < t.idle_pct;
    Some(GuestUsage {
        vmid: g.vmid,
        name: g.name.clone(),
        kind: g.kind.as_str().to_string(),
        allocated_mib,
        avg_mib,
        peak_mib,
        avg_pct,
        under_used,
        suggested_mib,
        reclaimable_mib: if under_used {
            allocated_mib - suggested_mib
        } else {
            0
        },
        estimate: g.kind == GuestKind::Qemu,
    })
}

/// `(time, mem bytes)` RRD samples.
pub type Series = Vec<(i64, f64)>;

/// Node totals from per-guest series: `(guest, avg series, max series)`.
pub fn node_usage(
    node: &str,
    t: &MemoryThresholds,
    series: &[(GuestMem, Series, Series)],
) -> UsageReport {
    let mut avg_by_t: BTreeMap<i64, f64> = BTreeMap::new();
    let mut max_by_t: BTreeMap<i64, f64> = BTreeMap::new();
    let mut guests = Vec::new();
    for (g, avg, max) in series {
        for (ts, v) in avg {
            *avg_by_t.entry(*ts).or_default() += v;
        }
        for (ts, v) in max {
            *max_by_t.entry(*ts).or_default() += v;
        }
        if let Some(u) = guest_usage(g, avg, max, t) {
            guests.push(u);
        }
    }
    let sums = |m: &BTreeMap<i64, f64>| m.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>();
    UsageReport {
        node: node.to_string(),
        timeframe: t.timeframe.clone(),
        allocated_mib: guests.iter().map(|g| g.allocated_mib).sum(),
        avg_mib: (mean(&sums(&avg_by_t)) / MIB).round() as u64,
        peak_mib: (peak(&sums(&max_by_t)) / MIB).ceil() as u64,
        reclaimable_mib: guests.iter().map(|g| g.reclaimable_mib).sum(),
        guests,
    }
}

fn finding_under_used(scope: &str, node: &str, timeframe: &str, u: &GuestUsage) -> Finding {
    Finding {
        id: format!("memory-underused::{scope}::{node}::{}", u.vmid),
        provider: PROVIDER.to_string(),
        severity: Severity::Info,
        title: format!(
            "{} {} ('{}') averages {:.0}% of its {} MiB",
            u.kind, u.vmid, u.name, u.avg_pct, u.allocated_mib
        ),
        detail: format!(
            "Over the last {timeframe} {} {} on node '{node}' averaged {} MiB and peaked at {} MiB \
             of its {} MiB allocation. Sizing it to {} MiB (peak plus headroom) would free {} MiB.{}",
            u.kind,
            u.vmid,
            u.avg_mib,
            u.peak_mib,
            u.allocated_mib,
            u.suggested_mib,
            u.reclaimable_mib,
            if u.estimate {
                " VM usage is the host's view and overstates real use without a guest agent."
            } else {
                ""
            }
        ),
        repair: None,
    }
}

// ── rule 3: live pressure ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PressureReport {
    pub node: String,
    pub mem_used_mib: u64,
    pub mem_total_mib: u64,
    pub mem_used_pct: f64,
    pub swap_used_mib: u64,
    pub swap_total_mib: u64,
    pub swap_used_pct: f64,
    pub under_pressure: bool,
}

pub fn pressure(node: &str, status: &Value, t: &MemoryThresholds) -> PressureReport {
    let get = |k: &str, f: &str| status.get(k).and_then(|m| m.get(f)).and_then(Value::as_u64);
    let pct = |u: u64, total: u64| {
        if total == 0 {
            0.0
        } else {
            u as f64 / total as f64 * 100.0
        }
    };
    let (mu, mt) = (
        get("memory", "used").unwrap_or(0),
        get("memory", "total").unwrap_or(0),
    );
    let (su, st) = (
        get("swap", "used").unwrap_or(0),
        get("swap", "total").unwrap_or(0),
    );
    let (mem_used_pct, swap_used_pct) = (pct(mu, mt), pct(su, st));
    PressureReport {
        node: node.to_string(),
        mem_used_mib: mu >> 20,
        mem_total_mib: mt >> 20,
        mem_used_pct,
        swap_used_mib: su >> 20,
        swap_total_mib: st >> 20,
        swap_used_pct,
        under_pressure: (mt > 0 && mem_used_pct >= t.mem_pressure_pct)
            || (st > 0 && swap_used_pct > t.swap_pressure_pct),
    }
}

fn finding_pressure(scope: &str, p: &PressureReport) -> Finding {
    Finding {
        id: format!("memory-pressure::{scope}::{}", p.node),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!(
            "PVE node '{}' is under memory pressure: RAM {:.0}%, swap {:.0}%",
            p.node, p.mem_used_pct, p.swap_used_pct
        ),
        detail: format!(
            "Node '{}' is using {} of {} MiB RAM and {} of {} MiB swap right now. Guests on it \
             are at risk of slowdowns from swapping or of an OOM kill.",
            p.node, p.mem_used_mib, p.mem_total_mib, p.swap_used_mib, p.swap_total_mib
        ),
        repair: None,
    }
}

// ── fetch ──────────────────────────────────────────────────────────────────

/// PVE accepts `memory` as `4096` or `current=4096`.
fn parse_memory_mib(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?;
    s.split(',').find_map(|p| match p.split_once('=') {
        Some(("current", n)) => n.parse().ok(),
        None => p.parse().ok(),
        _ => None,
    })
}

fn as_flag(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_u64() == Some(1),
        Some(Value::String(s)) => s == "1",
        _ => false,
    }
}

/// Physical RAM in MiB and the non-template guests on `node`.
async fn node_guests(
    http: &reqwest::Client,
    base: &str,
    node: &str,
) -> Result<(Value, Vec<GuestMem>)> {
    let status = raw_get_data(http, base, &format!("nodes/{}/status", enc(node))).await?;
    let mut guests = Vec::new();
    for kind in [GuestKind::Lxc, GuestKind::Qemu] {
        let list = raw_get_data(
            http,
            base,
            &format!("nodes/{}/{}", enc(node), kind.as_str()),
        )
        .await?;
        for item in list.as_array().into_iter().flatten() {
            let Some(vmid) = item
                .get("vmid")
                .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
            else {
                continue;
            };
            if as_flag(item.get("template")) {
                continue;
            }
            let path = format!("nodes/{}/{}/{vmid}/config", enc(node), kind.as_str());
            let cfg = raw_get_data(http, base, &path).await?;
            guests.push(GuestMem {
                vmid,
                name: item
                    .get("name")
                    .and_then(Value::as_str)
                    .map_or_else(|| format!("{}-{vmid}", kind.as_str()), str::to_string),
                kind,
                memory_mib: cfg
                    .get("memory")
                    .and_then(parse_memory_mib)
                    .unwrap_or(PVE_DEFAULT_MEMORY_MIB),
                balloon_mib: cfg.get("balloon").and_then(parse_memory_mib),
                running: item.get("status").and_then(Value::as_str) == Some("running"),
                onboot: as_flag(cfg.get("onboot")),
            });
        }
    }
    Ok((status, guests))
}

fn physical_mib(status: &Value) -> u64 {
    status
        .get("memory")
        .and_then(|m| m.get("total"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        >> 20
}

async fn rrd(
    http: &reqwest::Client,
    base: &str,
    node: &str,
    g: &GuestMem,
    timeframe: &str,
    cf: &str,
) -> Vec<(i64, f64)> {
    let path = format!(
        "nodes/{}/{}/{}/rrddata?timeframe={timeframe}&cf={cf}",
        enc(node),
        g.kind.as_str(),
        g.vmid
    );
    match raw_get_data(http, base, &path).await {
        Ok(v) => rrd_mem_series(&v),
        Err(e) => {
            tracing::warn!(node, vmid = g.vmid, error = %e, "memory: rrddata failed");
            Vec::new()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NodeMemoryReport {
    pub endpoint: String,
    pub allocation: AllocationReport,
    pub usage: UsageReport,
    pub pressure: PressureReport,
}

async fn node_report(
    cfg: &Config,
    endpoint: &str,
    node: &str,
    t: &MemoryThresholds,
) -> Result<NodeMemoryReport> {
    let http = cfg.build_reqwest_client()?;
    let (status, guests) = node_guests(&http, &cfg.base_url, node).await?;
    let mut series = Vec::new();
    for g in guests.iter().filter(|g| g.running) {
        let avg = rrd(&http, &cfg.base_url, node, g, &t.timeframe, "AVERAGE").await;
        let max = rrd(&http, &cfg.base_url, node, g, &t.timeframe, "MAX").await;
        series.push((g.clone(), avg, max));
    }
    Ok(NodeMemoryReport {
        endpoint: endpoint.to_string(),
        allocation: allocation(node, physical_mib(&status), t.reserve_mib, &guests),
        usage: node_usage(node, t, &series),
        pressure: pressure(node, &status, t),
    })
}

async fn node_names(cfg: &Config) -> Result<Vec<String>> {
    let http = cfg.build_reqwest_client()?;
    let nodes = raw_get_data(&http, &cfg.base_url, "nodes").await?;
    Ok(nodes
        .as_array()
        .into_iter()
        .flatten()
        .filter(|n| n.get("status").and_then(Value::as_str) != Some("offline"))
        .filter_map(|n| n.get("node")?.as_str().map(str::to_string))
        .collect())
}

/// The over-allocation guard for a create of `new_mib` on `node`.
pub(crate) async fn guard_create(
    endpoint: &str,
    node: &str,
    new_mib: u64,
    reserve_mib: u64,
) -> Result<()> {
    let cfg = resolve_config(endpoint).await?;
    let http = cfg.build_reqwest_client()?;
    let (status, guests) = node_guests(&http, &cfg.base_url, node).await?;
    let r = allocation(node, physical_mib(&status), reserve_mib, &guests);
    if r.physical_mib == 0 {
        bail!("node '{node}' reported no physical memory; refusing to create blind");
    }
    check_allocation(&r, None, new_mib).map_err(|e| anyhow::anyhow!("{e}"))
}

pub async fn diagnose_memory() -> Vec<Finding> {
    let mut findings = for_each_enabled_endpoint("diagnostics.memory", |cfg, ep| async move {
        let t = MemoryThresholds::default();
        let client = cfg.build_generated_client()?;
        let scope = crate::cluster::fetch_cluster_status(&client)
            .await
            .ok()
            .and_then(|s| s.name)
            .unwrap_or_else(|| ep.name.clone());
        let mut out = Vec::new();
        for node in node_names(&cfg).await? {
            let r = match node_report(&cfg, &ep.name, &node, &t).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(endpoint = %ep.name, node, error = %e, "memory: node read failed");
                    continue;
                }
            };
            if r.allocation.physical_mib > 0 && r.allocation.over_allocated {
                out.push(finding_over_allocated(&scope, &r.allocation));
            }
            if r.pressure.under_pressure {
                out.push(finding_pressure(&scope, &r.pressure));
            }
            out.extend(
                r.usage
                    .guests
                    .iter()
                    .filter(|u| u.under_used)
                    .map(|u| finding_under_used(&scope, &node, &t.timeframe, u)),
            );
        }
        Ok(out)
    })
    .await;
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));
    findings
}

// ── read verb ──────────────────────────────────────────────────────────────

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct ProxmoxMemoryArgs {
    #[arg(long)]
    pub endpoint: String,
    /// One node; every online node when omitted.
    #[arg(long)]
    pub node: Option<String>,
    #[arg(long, default_value_t = 4096)]
    pub reserve_mib: u64,
    /// RRD window for under-use: hour, day, week, month or year.
    #[arg(long, default_value = "week")]
    pub timeframe: String,
    #[arg(long, default_value_t = 40.0)]
    pub idle_pct: f64,
    #[arg(long, default_value_t = 20.0)]
    pub headroom_pct: f64,
    #[arg(long, default_value_t = 90.0)]
    pub mem_pressure_pct: f64,
    #[arg(long, default_value_t = 25.0)]
    pub swap_pressure_pct: f64,
}

/// Per-node memory: allocation vs physical (with host reserve), per-guest
/// usage over an RRD window, and live RAM/swap pressure.
#[orca_tool(
    domain = "proxmox",
    verb = "memory",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_memory(args: ProxmoxMemoryArgs, _ctx: &ToolCtx) -> Result<Vec<NodeMemoryReport>> {
    if !TIMEFRAMES.contains(&args.timeframe.as_str()) {
        bail!("timeframe must be one of {}", TIMEFRAMES.join(", "));
    }
    let t = MemoryThresholds {
        reserve_mib: args.reserve_mib,
        timeframe: args.timeframe,
        idle_pct: args.idle_pct,
        headroom_pct: args.headroom_pct,
        mem_pressure_pct: args.mem_pressure_pct,
        swap_pressure_pct: args.swap_pressure_pct,
    };
    let cfg = resolve_config(&args.endpoint).await?;
    let nodes = match args.node {
        Some(n) => vec![n],
        None => node_names(&cfg).await?,
    };
    let mut out = Vec::new();
    for node in nodes {
        out.push(node_report(&cfg, &args.endpoint, &node, &t).await?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    fn ct(vmid: u64, mib: u64, running: bool, onboot: bool) -> GuestMem {
        GuestMem {
            vmid,
            name: format!("ct{vmid}"),
            kind: GuestKind::Lxc,
            memory_mib: mib,
            balloon_mib: None,
            running,
            onboot,
        }
    }

    fn vm(vmid: u64, mib: u64, balloon: Option<u64>) -> GuestMem {
        GuestMem {
            kind: GuestKind::Qemu,
            balloon_mib: balloon,
            ..ct(vmid, mib, true, true)
        }
    }

    /// 64101 MiB node, guests totalling 54272 MiB, one CT 20480 → 43008.
    fn real_node() -> AllocationReport {
        allocation(
            "n",
            64101,
            4096,
            &[
                ct(100, 20480, true, true),
                vm(101, 16384, None),
                ct(102, 17408, true, false),
            ],
        )
    }

    #[test]
    fn real_case_raise_is_refused_with_largest_fit() {
        let r = real_node();
        assert_eq!(r.allocated_mib, 54272);
        assert!(!r.over_allocated);
        assert_eq!(r.headroom_mib, 64101 - 4096 - 54272);
        let e = check_allocation(&r, Some(100), 43008).unwrap_err();
        assert!(e.contains("largest value that fits is 26213 MiB"), "{e}");
        assert!(check_allocation(&r, Some(100), 26213).is_ok());
        assert!(check_allocation(&r, Some(100), 26214).is_err());
    }

    #[test]
    fn new_guest_counts_against_full_allocation() {
        let r = real_node();
        assert!(check_allocation(&r, None, 5733).is_ok());
        let e = check_allocation(&r, None, 5734).unwrap_err();
        assert!(e.contains("largest value that fits is 5733 MiB"), "{e}");
    }

    #[test]
    fn balloon_floor_counts_instead_of_memory() {
        assert_eq!(vm(1, 8192, Some(2048)).allocated_mib(), 2048);
        assert_eq!(
            vm(1, 8192, Some(0)).allocated_mib(),
            8192,
            "0 = ballooning off"
        );
        assert_eq!(vm(1, 8192, None).allocated_mib(), 8192);
        let r = allocation("n", 16384, 4096, &[vm(1, 16384, Some(4096))]);
        assert_eq!(r.allocated_mib, 4096);
        assert!(!r.over_allocated);
    }

    #[test]
    fn stopped_guests_are_counted_only_when_onboot() {
        let r = allocation(
            "n",
            32768,
            4096,
            &[
                ct(1, 8192, true, false),
                ct(2, 8192, false, true),
                ct(3, 30000, false, false),
            ],
        );
        assert_eq!(r.allocated_mib, 16384);
        assert_eq!(r.guests.len(), 2);
        assert_eq!(r.stopped.len(), 1);
        assert_eq!(r.stopped[0].vmid, 3);
        assert!(!r.over_allocated);
    }

    #[test]
    fn reserve_tips_a_node_over() {
        let r = allocation("n", 32768, 4096, &[ct(1, 30000, true, true)]);
        assert!(r.over_allocated);
        assert_eq!(r.headroom_mib, -1328);
        let f = finding_over_allocated("c", &r);
        assert_eq!(f.severity, Severity::Warn);
        assert_eq!(f.id, "memory-overallocated::c::n");
    }

    #[test]
    fn parses_memory_forms() {
        assert_eq!(parse_memory_mib(&json!(4096)), Some(4096));
        assert_eq!(parse_memory_mib(&json!("4096")), Some(4096));
        assert_eq!(parse_memory_mib(&json!("current=2048")), Some(2048));
        assert_eq!(parse_memory_mib(&json!("x")), None);
    }

    fn flat(n: usize, mib: f64) -> Vec<(i64, f64)> {
        (0..n).map(|i| (i as i64 * 60, mib * MIB)).collect()
    }

    #[test]
    fn under_used_guest_is_sized_to_peak_plus_headroom() {
        let t = MemoryThresholds::default();
        let g = ct(1, 8192, true, true);
        let avg = flat(10, 1024.0);
        let mut max = flat(10, 1024.0);
        max[3].1 = 3000.0 * MIB;
        let u = guest_usage(&g, &avg, &max, &t).unwrap();
        assert_eq!(u.avg_mib, 1024);
        assert_eq!(u.peak_mib, 3000);
        assert!(u.under_used);
        // 3000 * 1.2 = 3600 → 3840 (256 MiB steps)
        assert_eq!(u.suggested_mib, 3840);
        assert_eq!(u.reclaimable_mib, 8192 - 3840);
        assert!(!u.estimate);
    }

    #[test]
    fn busy_guest_is_not_flagged_and_suggestion_caps_at_allocation() {
        let t = MemoryThresholds::default();
        let u = guest_usage(&vm(1, 4096, None), &flat(5, 3500.0), &flat(5, 4000.0), &t).unwrap();
        assert!(!u.under_used);
        assert_eq!(u.suggested_mib, 4096);
        assert_eq!(u.reclaimable_mib, 0);
        assert!(u.estimate);
    }

    #[test]
    fn no_samples_means_no_usage() {
        let t = MemoryThresholds::default();
        assert!(guest_usage(&ct(1, 1024, true, true), &[], &[], &t).is_none());
    }

    #[test]
    fn node_peak_sums_per_timestamp_not_per_guest_peaks() {
        let t = MemoryThresholds::default();
        let a = vec![(0, 1000.0 * MIB), (60, 100.0 * MIB)];
        let b = vec![(0, 100.0 * MIB), (60, 1000.0 * MIB)];
        let r = node_usage(
            "n",
            &t,
            &[
                (ct(1, 4096, true, true), a.clone(), a),
                (ct(2, 4096, true, true), b.clone(), b),
            ],
        );
        assert_eq!(r.peak_mib, 1100);
        assert_eq!(r.avg_mib, 1100);
        assert_eq!(r.allocated_mib, 8192);
        assert_eq!(r.guests.len(), 2);
    }

    #[test]
    fn rrd_series_skips_empty_buckets() {
        let v = json!([{"time": 0, "mem": 1.0}, {"time": 60}, {"time": 120, "mem": 3.0}]);
        assert_eq!(rrd_mem_series(&v), vec![(0, 1.0), (120, 3.0)]);
    }

    fn status(mu: u64, mt: u64, su: u64, st: u64) -> Value {
        json!({"memory": {"used": mu << 20, "total": mt << 20},
               "swap": {"used": su << 20, "total": st << 20}})
    }

    #[test]
    fn pressure_on_ram_or_swap() {
        let t = MemoryThresholds::default();
        assert!(!pressure("n", &status(50, 100, 0, 100), &t).under_pressure);
        assert!(pressure("n", &status(90, 100, 0, 100), &t).under_pressure);
        assert!(pressure("n", &status(10, 100, 26, 100), &t).under_pressure);
        assert!(!pressure("n", &status(10, 100, 25, 100), &t).under_pressure);
        let none = pressure("n", &status(0, 0, 0, 0), &t);
        assert!(!none.under_pressure);
        assert_eq!(
            finding_pressure("c", &pressure("n", &status(95, 100, 0, 0), &t)).id,
            "memory-pressure::c::n"
        );
    }
}
