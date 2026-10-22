use crate::responses::{ResourceType, cluster_resources};
use crate::tools::for_each_enabled_endpoint;
use crate::{GuestKind, responses::GuestConfigData};
use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::diagnostics::{
    DIAGNOSE_OP, DiagnoseArgs, DiagnosticsProvider, Finding, REPAIR_OP, RepairArgs, RepairOutcome,
    RepairSpec, Severity,
};
use plugin_toolkit::serde_json;

pub struct ProxmoxDiagnostics;

impl DiagnosticsProvider for ProxmoxDiagnostics {
    fn name(&self) -> &str {
        PROVIDER
    }

    fn diagnose(&self, args: DiagnoseArgs) -> BoxFuture<'_, anyhow::Result<Vec<Finding>>> {
        Box::pin(async move { Ok(diagnose(args).await) })
    }

    fn repair(&self, args: RepairArgs) -> BoxFuture<'_, anyhow::Result<RepairOutcome>> {
        Box::pin(async move { Ok(repair(args).await) })
    }
}

pub const DIAG_PREFIX: &str = "proxmox.__diagnostics";
const PROVIDER: &str = "proxmox";
pub const ENABLE_AGENT_OP: &str = "proxmox.put_update_vm_nodes_node_qemu_vmid_config";
const AGENT_PING_OP: &str = "proxmox.post_ping_nodes_node_qemu_vmid_agent_ping";
const RAISE_CT_MEMORY_OP: &str = "proxmox.put_update_vm_nodes_node_lxc_vmid_config";
pub const REACHES: [&str; 3] = [ENABLE_AGENT_OP, AGENT_PING_OP, RAISE_CT_MEMORY_OP];

pub fn diagnostics_backend_def() -> BackendDef {
    BackendDef {
        domain: "diagnostics".to_string(),
        name: PROVIDER.to_string(),
        invoke_prefix: DIAG_PREFIX.to_string(),
        ..Default::default()
    }
}

pub fn dispatch(
    name: &str,
    args: serde_json::Value,
) -> Option<Result<serde_json::Value, serde_json::Value>> {
    let op = name
        .strip_prefix(DIAG_PREFIX)?
        .strip_prefix('.')?
        .to_string();
    Some(plugin_toolkit::reactor::block_on(async move {
        if op == DIAGNOSE_OP {
            let args: DiagnoseArgs =
                serde_json::from_value(args).map_err(|e| err_val(format!("diagnose args: {e}")))?;
            let findings = diagnose(args).await;
            serde_json::to_value(&findings).map_err(|e| err_val(e.to_string()))
        } else if op == REPAIR_OP {
            let args: RepairArgs =
                serde_json::from_value(args).map_err(|e| err_val(format!("repair args: {e}")))?;
            let outcome = repair(args).await;
            serde_json::to_value(&outcome).map_err(|e| err_val(e.to_string()))
        } else {
            Err(err_val(format!("unknown diagnostics op '{op}'")))
        }
    }))
}

fn err_val(msg: impl Into<String>) -> serde_json::Value {
    serde_json::Value::String(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentState {
    Ok,
    Disabled,
    Unresponsive,
}

fn classify(enabled_in_config: bool, ping_ok: bool) -> AgentState {
    if !enabled_in_config {
        AgentState::Disabled
    } else if ping_ok {
        AgentState::Ok
    } else {
        AgentState::Unresponsive
    }
}

fn config_agent_enabled(cfg: &GuestConfigData) -> bool {
    if cfg.get_int("agent") == Some(1) {
        return true;
    }
    if let Some(s) = cfg.get_str("agent") {
        let first = s.split(',').next().unwrap_or("").trim();
        return first == "1" || first == "enabled=1";
    }
    false
}

pub async fn diagnose(args: DiagnoseArgs) -> Vec<Finding> {
    let mut findings = diagnose_qemu_agents(args).await;
    findings.extend(diagnose_lxc_shm_traps().await);
    findings.extend(diagnose_host_workloads());
    findings.extend(crate::overallocation::diagnose_overallocation().await);
    findings.extend(crate::memory::diagnose_memory().await);
    findings.extend(diagnose_guest_mounts());
    findings.extend(crate::backup_jobs::diagnose_backup_jobs().await);
    findings.extend(crate::bind_mounts::diagnose_bind_mounts());
    findings.extend(crate::thin_pool::diagnose_thin_pools().await);
    findings.extend(crate::stale_snapshots::diagnose_stale_snapshots().await);
    findings
}

fn diagnose_guest_mounts() -> Vec<Finding> {
    let dir = std::path::Path::new("/etc/pve/lxc");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let node = local_node();
    let root_dev = crate::mount_scan::root_device();
    let mut findings = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|x| x.to_str()) != Some("conf") {
            continue;
        }
        let Some(vmid) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let Ok(conf) = std::fs::read_to_string(&path) else {
            continue;
        };
        let name = ct_name(&conf).unwrap_or_else(|| format!("ct-{vmid}"));
        let specs = crate::mount_scan::specs_for_guest(vmid, &conf, root_dev);
        for f in plugin_toolkit::mount_audit::audit(&specs) {
            findings.push(finding_guest_mount(&node, vmid, &name, &f));
        }
    }
    findings
}

fn finding_guest_mount(
    node: &str,
    vmid: u64,
    name: &str,
    f: &plugin_toolkit::mount_audit::MountFinding,
) -> Finding {
    use plugin_toolkit::mount_audit::Risk;
    let severity = match f.risk {
        Risk::UnboundedOnHostRootFs => Severity::Crit,
        Risk::UnboundedScratch => Severity::Warn,
        Risk::UnusedProvisioned => Severity::Info,
    };
    let headline = match f.risk {
        Risk::UnboundedOnHostRootFs => format!(
            "CT {vmid} ('{name}') can fill PVE node '{node}' — uncapped bind mount on the node root"
        ),
        Risk::UnboundedScratch => {
            format!("CT {vmid} ('{name}') has an uncapped bind mount")
        }
        Risk::UnusedProvisioned => {
            format!("CT {vmid} ('{name}') has a provisioned mount nothing uses")
        }
    };
    Finding {
        id: format!("guest-mount::{node}::{}", f.id),
        provider: PROVIDER.to_string(),
        severity,
        title: headline,
        detail: format!(
            "{}\n\nNode '{node}', CT {vmid} ('{name}'). A bind mount cannot be quota'd by the \
             hypervisor, so the only way to bound it is to move the source onto a dedicated \
             volume (`pct set {vmid} -mpN <storage>:<size>,mp=<target>`) or to cap the writer. \
             Note that a scratch directory measures 0 bytes at rest, so a level-based check \
             never sees this — only the configuration does.",
            f.detail
        ),
        repair: None,
    }
}

fn diagnose_host_workloads() -> Vec<Finding> {
    let node = local_node();
    crate::host_workloads::scan_host_workloads()
        .into_iter()
        .map(|label| finding_host_workload(&node, &label))
        .collect()
}

fn finding_host_workload(node: &str, label: &str) -> Finding {
    Finding {
        id: format!("host-workload::{node}::{label}"),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!(
            "Non-hypervisor workload '{label}' is running directly on PVE node '{node}'"
        ),
        detail: format!(
            "The process/service '{label}' is running on the bare-metal PVE node '{node}' rather \
             than inside an LXC or VM. A hypervisor host should run only the virtualization + \
             base-OS stack (pve*, qemu/kvm, corosync, zfs, sshd, systemd) so it stays clean and \
             disposable — able to be backed up, migrated, and rebuilt as a unit. A workload on the \
             node itself can't be managed that way and competes with guests for the node's \
             resources. Move '{label}' into a dedicated LXC or VM and remove it from the host. \
             orca does not stop host processes automatically — this needs a deliberate migration."
        ),
        repair: None,
    }
}

async fn diagnose_qemu_agents(_args: DiagnoseArgs) -> Vec<Finding> {
    for_each_enabled_endpoint("diagnostics.qemu_agent", |_, ep| async move {
        let items = cluster_resources(&ep.name, Some("vm"))?;

        let mut findings = Vec::new();
        for e in items {
            if !matches!(e.type_, ResourceType::Qemu) {
                continue;
            }
            if e.template.unwrap_or(false) {
                continue;
            }
            if e.status.as_deref() != Some("running") {
                continue;
            }
            let (node, vmid) = match (e.node, e.vmid) {
                (Some(n), Some(v)) if !n.is_empty() && v > 0 => (n, v as u64),
                _ => continue,
            };
            let name = e.name.unwrap_or_else(|| format!("vmid-{vmid}"));

            let config = match plugin_toolkit::api::call::<GuestConfigData>(
                crate::backup::config_op(GuestKind::Qemu, "get"),
                &ep.name,
                serde_json::json!({ "node": node, "vmid": vmid }),
            ) {
                Ok(c) => c,
                Err(err) => {
                    tracing::debug!(node = %node, vmid, error = %err,
                            "qemu-agent diag: guest_config failed (guest may have been deleted)");
                    continue;
                }
            };
            let enabled = config_agent_enabled(&config);

            let ping_ok = if enabled {
                plugin_toolkit::api::call::<serde_json::Value>(
                    AGENT_PING_OP,
                    &ep.name,
                    serde_json::json!({ "node": node, "vmid": vmid }),
                )
                .is_ok()
            } else {
                false
            };

            match classify(enabled, ping_ok) {
                AgentState::Ok => {}
                AgentState::Disabled => {
                    findings.push(finding_disabled(&ep.name, &node, vmid, &name))
                }
                AgentState::Unresponsive => {
                    findings.push(finding_unresponsive(&ep.name, &node, vmid, &name))
                }
            }
        }
        Ok(findings)
    })
    .await
}

pub(crate) fn local_node() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".to_string())
}

fn ct_name(conf: &str) -> Option<String> {
    conf.lines()
        .find_map(|l| l.trim().strip_prefix("hostname:"))
        .map(|v| v.trim().to_string())
        .filter(|s| !s.is_empty())
}

async fn diagnose_lxc_shm_traps() -> Vec<Finding> {
    for_each_enabled_endpoint("diagnostics.shm_trap", |_, ep| async move {
        shm_findings(&ep.name)
    })
    .await
}

fn shm_findings(endpoint: &str) -> anyhow::Result<Vec<Finding>> {
    let resources = crate::api_path::get(endpoint, "cluster/resources?type=vm")?;
    let mut findings = Vec::new();
    for (node, vmid, name) in lxc_guests(&resources) {
        let config = match ct_config(endpoint, &node, vmid) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(vmid, error = %e, "shm-trap: CT config read failed");
                continue;
            }
        };
        for trap in ct_traps(&config) {
            findings.push(finding_shm_trap(endpoint, &node, vmid, &name, &trap));
        }
    }
    Ok(findings)
}

fn ct_config(endpoint: &str, node: &str, vmid: u64) -> anyhow::Result<serde_json::Value> {
    crate::api_path::get(endpoint, &format!("nodes/{node}/lxc/{vmid}/config"))
}

fn ct_traps(config: &serde_json::Value) -> Vec<crate::shm_trap::ShmTrap> {
    crate::shm_trap::classify_traps(&crate::shm_trap::parse_lxc_conf(&conf_lines(config)))
}

fn lxc_guests(resources: &serde_json::Value) -> Vec<(String, u64, String)> {
    resources
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r.get("type").and_then(serde_json::Value::as_str) == Some("lxc"))
        .filter(|r| r.get("template").and_then(serde_json::Value::as_u64) != Some(1))
        .filter_map(|r| {
            let node = r.get("node")?.as_str()?.to_string();
            let vmid = r.get("vmid")?.as_u64()?;
            let name = r
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("ct-{vmid}"));
            Some((node, vmid, name))
        })
        .collect()
}

fn conf_lines(config: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(mem) = config.get("memory") {
        let mem = mem.as_str().map_or_else(|| mem.to_string(), str::to_string);
        out.push_str(&format!("memory: {mem}\n"));
    }
    for pair in config
        .get("lxc")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let [k, v] = pair.as_array().map(Vec::as_slice).unwrap_or_default()
            && let (Some(k), Some(v)) = (k.as_str(), v.as_str())
        {
            out.push_str(&format!("{k}: {v}\n"));
        }
    }
    out
}

fn finding_shm_trap(
    endpoint: &str,
    node: &str,
    vmid: u64,
    name: &str,
    trap: &crate::shm_trap::ShmTrap,
) -> Finding {
    let suggested = crate::shm_trap::suggested_memory_mb(trap.tmpfs_mb);
    Finding {
        id: format!("lxc-shm-trap::{node}::{vmid}::{}", trap.target),
        provider: PROVIDER.to_string(),
        severity: Severity::Crit,
        title: format!(
            "CT {vmid} ('{name}') tmpfs /{} is {} MiB but the memory cap is {} MiB — OOM-kill risk",
            trap.target, trap.tmpfs_mb, trap.memory_mb
        ),
        detail: format!(
            "The tmpfs mount /{tgt} in CT {vmid} on node '{node}' is sized {tmpfs} MiB, which is \
             at/above the container's {mem} MiB memory cgroup. tmpfs pages count against that \
             cgroup, so filling /{tgt} (e.g. a Plex/Jellyfin transcode writing to /dev/shm) pushes \
             the CT past its limit and the kernel OOM-kills the process — a crash-loop. Raise the \
             CT's memory (suggested {suggested} MiB, leaving headroom for the workload) or cap the \
             tmpfs below the memory limit by hand.",
            tgt = trap.target,
            tmpfs = trap.tmpfs_mb,
            mem = trap.memory_mb,
        ),
        repair: Some(RepairSpec {
            id: format!("shm-memory::{endpoint}::{node}::{vmid}::{suggested}"),
            description: format!(
                "Raise CT {vmid} memory from {} MiB to {suggested} MiB through the PVE API so \
                 the {} MiB tmpfs /{} sits under the cap.",
                trap.memory_mb, trap.tmpfs_mb, trap.target
            ),
            automatic: false,
            privileged: false,
            delegate: None,
        }),
    }
}

fn raise_ct_memory(
    endpoint: &str,
    node: &str,
    vmid: u64,
    memory_mb: u64,
) -> Result<String, String> {
    let config =
        ct_config(endpoint, node, vmid).map_err(|e| format!("GET CT {vmid} config: {e:#}"))?;
    let traps = ct_traps(&config);
    if !traps
        .iter()
        .any(|t| crate::shm_trap::suggested_memory_mb(t.tmpfs_mb) == memory_mb)
    {
        return Err(format!(
            "CT {vmid}: {memory_mb} MiB does not match a current shm trap ({} found); re-run diagnose",
            traps.len()
        ));
    }
    let status = crate::api_path::get(endpoint, &format!("nodes/{node}/status"))
        .map_err(|e| format!("GET node {node} status: {e:#}"))?;
    let total_mb = status
        .pointer("/memory/total")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("node {node} status has no memory.total"))?
        / (1024 * 1024);
    if memory_mb > total_mb {
        return Err(format!(
            "CT {vmid}: {memory_mb} MiB exceeds node {node} memory ({total_mb} MiB); cap = node total RAM, ignores other guests' commitments"
        ));
    }
    let Some(pairs) = memory_raise_pairs(&config, memory_mb)? else {
        return Err(format!(
            "CT {vmid} memory is already at or above {memory_mb} MiB (already fixed?)"
        ));
    };
    crate::api_path::send(
        "PUT",
        endpoint,
        &format!("nodes/{node}/lxc/{vmid}/config"),
        &pairs,
    )
    .map_err(|e| format!("PUT CT {vmid} memory: {e:#}"))?;
    Ok(format!(
        "Raised CT {vmid} memory to {memory_mb} MiB through the PVE API; a running CT applies \
         it live."
    ))
}

fn memory_raise_pairs(
    config: &serde_json::Value,
    memory_mb: u64,
) -> Result<Option<Vec<(String, String)>>, String> {
    let digest = config
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or("CT config has no digest")?;
    let current = match config.get("memory") {
        None => 512,
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| format!("CT memory '{v}' is not a number"))?,
    };
    if current >= memory_mb {
        return Ok(None);
    }
    Ok(Some(vec![
        ("memory".to_string(), memory_mb.to_string()),
        ("digest".to_string(), digest.to_string()),
    ]))
}

fn finding_disabled(endpoint: &str, node: &str, vmid: u64, name: &str) -> Finding {
    Finding {
        id: format!("qemu-agent-disabled::{endpoint}::{node}::{vmid}"),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!("QEMU guest agent not enabled on '{name}' (vmid {vmid})"),
        detail: format!(
            "VM {vmid} on node '{node}' ({endpoint}) is running without the QEMU guest agent \
             enabled in its config. orca can't run in-guest exec/diagnostics or a clean \
             shutdown until the agent is enabled and the qemu-guest-agent package is installed \
             in the guest."
        ),
        repair: Some(RepairSpec {
            id: format!("enable::{endpoint}::{node}::{vmid}"),
            description: "Enable the QEMU guest agent in the VM config (`agent: 1`). Takes effect \
                          after the VM is powered off and on; the qemu-guest-agent package must \
                          also be installed inside the guest."
                .to_string(),
            automatic: false,
            privileged: false,
            delegate: None,
        }),
    }
}

fn finding_unresponsive(endpoint: &str, node: &str, vmid: u64, name: &str) -> Finding {
    Finding {
        id: format!("qemu-agent-unresponsive::{endpoint}::{node}::{vmid}"),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!("QEMU guest agent enabled but not responding on '{name}' (vmid {vmid})"),
        detail: format!(
            "VM {vmid} on node '{node}' ({endpoint}) has the guest agent enabled in config but it \
             is not answering — the qemu-guest-agent package is almost certainly not installed or \
             not running inside the guest. orca has no in-guest channel to fix this automatically."
        ),
        repair: Some(RepairSpec {
            id: format!("guest-install::{endpoint}::{node}::{vmid}"),
            description:
                "Install and start qemu-guest-agent inside the guest OS, then power-cycle \
                          the VM. orca cannot do this automatically (no in-guest channel until the \
                          agent responds)."
                    .to_string(),
            automatic: false,
            privileged: true,
            delegate: None,
        }),
    }
}

fn parse_repair_id(id: &str) -> Option<(String, String, String, u64)> {
    let mut p = id.split("::");
    let action = p.next()?.to_string();
    let endpoint = p.next()?.to_string();
    let node = p.next()?.to_string();
    let vmid: u64 = p.next()?.parse().ok()?;
    if p.next().is_some() {
        return None;
    }
    Some((action, endpoint, node, vmid))
}

fn outcome(repair_id: &str, ok: bool, message: String) -> RepairOutcome {
    RepairOutcome {
        id: repair_id.to_string(),
        provider: PROVIDER.to_string(),
        ok,
        message,
    }
}

pub async fn repair(args: RepairArgs) -> RepairOutcome {
    if let Some(rest) = args.repair_id.strip_prefix("shm-memory::") {
        let parsed = match rest.split("::").collect::<Vec<_>>().as_slice() {
            [endpoint, node, vmid, mb] => vmid
                .parse::<u64>()
                .ok()
                .zip(mb.parse::<u64>().ok())
                .map(|(v, m)| (endpoint.to_string(), node.to_string(), v, m)),
            _ => None,
        };
        let Some((endpoint, node, vmid, memory_mb)) = parsed else {
            return outcome(
                &args.repair_id,
                false,
                format!("malformed shm-memory repair id '{}'", args.repair_id),
            );
        };
        return match raise_ct_memory(&endpoint, &node, vmid, memory_mb) {
            Ok(msg) => outcome(&args.repair_id, true, msg),
            Err(e) => outcome(&args.repair_id, false, e),
        };
    }
    let Some((action, endpoint, node, vmid)) = parse_repair_id(&args.repair_id) else {
        return outcome(
            &args.repair_id,
            false,
            format!("unrecognized repair id '{}'", args.repair_id),
        );
    };
    match action.as_str() {
        "enable" => match enable_agent(&endpoint, &node, vmid).await {
            Ok(()) => outcome(
                &args.repair_id,
                true,
                format!(
                    "Enabled the QEMU guest agent in the config for vmid {vmid} on '{node}'. \
                     Power-cycle the VM for it to take effect, and ensure qemu-guest-agent is \
                     installed inside the guest."
                ),
            ),
            Err(e) => outcome(
                &args.repair_id,
                false,
                format!("failed to enable the guest agent for vmid {vmid}: {e}"),
            ),
        },
        "guest-install" => outcome(
            &args.repair_id,
            false,
            format!(
                "qemu-guest-agent must be installed inside vmid {vmid} — orca has no in-guest \
                 channel until the agent responds. In the guest run: (Debian/Ubuntu) \
                 `apt-get install -y qemu-guest-agent && systemctl enable --now qemu-guest-agent`; \
                 (RHEL/Alma/Rocky) `dnf install -y qemu-guest-agent && systemctl enable --now \
                 qemu-guest-agent`; then power-cycle the VM."
            ),
        ),
        other => outcome(
            &args.repair_id,
            false,
            format!("unknown repair action '{other}'"),
        ),
    }
}

async fn enable_agent(endpoint: &str, node: &str, vmid: u64) -> anyhow::Result<()> {
    plugin_toolkit::api::call::<serde_json::Value>(
        ENABLE_AGENT_OP,
        endpoint,
        serde_json::json!({ "node": node, "vmid": vmid, "body": { "agent": "1" } }),
    )
    .map_err(|e| e.context("PUT vm config"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::responses::GuestConfigResponse;

    fn cfg_from(json: &str) -> GuestConfigData {
        serde_json::from_str::<GuestConfigResponse>(json)
            .unwrap()
            .data
    }

    #[test]
    fn agent_enabled_parses_bare_and_property_forms() {
        assert!(config_agent_enabled(&cfg_from(r#"{"data":{"agent":1}}"#)));
        assert!(config_agent_enabled(&cfg_from(r#"{"data":{"agent":"1"}}"#)));
        assert!(config_agent_enabled(&cfg_from(
            r#"{"data":{"agent":"enabled=1,fstrim_cloned_disks=1"}}"#
        )));
        assert!(!config_agent_enabled(&cfg_from(r#"{"data":{"agent":0}}"#)));
        assert!(!config_agent_enabled(&cfg_from(
            r#"{"data":{"agent":"0"}}"#
        )));
        assert!(!config_agent_enabled(&cfg_from(
            r#"{"data":{"agent":"enabled=0"}}"#
        )));
        assert!(!config_agent_enabled(&cfg_from(r#"{"data":{"cores":2}}"#)));
    }

    #[test]
    fn classify_covers_the_three_states() {
        assert_eq!(classify(false, false), AgentState::Disabled);
        assert_eq!(classify(false, true), AgentState::Disabled);
        assert_eq!(classify(true, true), AgentState::Ok);
        assert_eq!(classify(true, false), AgentState::Unresponsive);
    }

    #[test]
    fn findings_carry_stable_ids_and_matching_repairs() {
        let d = finding_disabled("pve", "n1", 104, "runner");
        assert_eq!(d.id, "qemu-agent-disabled::pve::n1::104");
        assert_eq!(d.severity, Severity::Warn);
        let r = d.repair.unwrap();
        assert_eq!(r.id, "enable::pve::n1::104");
        assert!(!r.automatic && !r.privileged && r.delegate.is_none());

        let u = finding_unresponsive("pve", "n1", 104, "runner");
        assert_eq!(u.id, "qemu-agent-unresponsive::pve::n1::104");
        let ur = u.repair.unwrap();
        assert_eq!(ur.id, "guest-install::pve::n1::104");
        assert!(!ur.automatic && ur.privileged);
    }

    #[test]
    fn repair_id_round_trips() {
        let (action, endpoint, node, vmid) = parse_repair_id("enable::pve-lab::hyp1::104").unwrap();
        assert_eq!(action, "enable");
        assert_eq!(endpoint, "pve-lab");
        assert_eq!(node, "hyp1");
        assert_eq!(vmid, 104);
        assert!(parse_repair_id("enable::pve::hyp1").is_none());
        assert!(parse_repair_id("enable::pve::hyp1::notanum").is_none());
    }

    #[test]
    fn shm_trap_finding_is_high_with_matching_resize_repair() {
        let trap = crate::shm_trap::ShmTrap {
            target: "dev/shm".into(),
            tmpfs_mb: 6144,
            memory_mb: 4096,
        };
        let f = finding_shm_trap("pve", "thor", 110, "mimir", &trap);
        assert_eq!(f.id, "lxc-shm-trap::thor::110::dev/shm");
        assert_eq!(f.severity, Severity::Crit);
        let r = f.repair.unwrap();
        assert_eq!(r.id, "shm-memory::pve::thor::110::12288");
        assert!(!r.automatic && !r.privileged);
    }

    #[test]
    fn host_workload_finding_is_warn_with_no_auto_repair() {
        let f = finding_host_workload("frigg", "minio");
        assert_eq!(f.id, "host-workload::frigg::minio");
        assert_eq!(f.severity, Severity::Warn);
        assert!(f.title.contains("minio") && f.title.contains("frigg"));
        assert!(f.repair.is_none());
    }

    #[test]
    fn memory_raise_sets_memory_with_digest_only_when_higher() {
        let cfg = serde_json::json!({"digest": "abc", "memory": 4096});
        assert_eq!(
            memory_raise_pairs(&cfg, 12288).unwrap().unwrap(),
            [
                ("memory".to_string(), "12288".to_string()),
                ("digest".to_string(), "abc".to_string())
            ]
        );
        assert!(memory_raise_pairs(&cfg, 4096).unwrap().is_none());
        let defaulted = serde_json::json!({"digest": "d"});
        assert!(memory_raise_pairs(&defaulted, 1024).unwrap().is_some());
        let stringy = serde_json::json!({"digest": "d", "memory": "2048"});
        assert!(memory_raise_pairs(&stringy, 2048).unwrap().is_none());
        assert!(memory_raise_pairs(&serde_json::json!({"memory": 1}), 2048).is_err());
    }

    #[test]
    fn shm_trap_inputs_come_from_the_api_config() {
        let resources = serde_json::json!([
            {"type": "lxc", "node": "thor", "vmid": 110, "name": "mimir"},
            {"type": "lxc", "node": "thor", "vmid": 9000, "template": 1},
            {"type": "qemu", "node": "thor", "vmid": 120},
            {"type": "lxc", "node": "odin", "vmid": 111}
        ]);
        assert_eq!(
            lxc_guests(&resources),
            [
                ("thor".to_string(), 110, "mimir".to_string()),
                ("odin".to_string(), 111, "ct-111".to_string())
            ]
        );
        let config = serde_json::json!({
            "memory": 4096,
            "lxc": [
                ["lxc.mount.entry", "tmpfs dev/shm tmpfs size=6g,mode=1777 0 0"],
                ["lxc.cgroup2.devices.allow", "c 226:* rwm"]
            ]
        });
        let profile = crate::shm_trap::parse_lxc_conf(&conf_lines(&config));
        let traps = crate::shm_trap::classify_traps(&profile);
        assert_eq!(traps.len(), 1);
        assert_eq!(traps[0].tmpfs_mb, 6144);
        assert_eq!(traps[0].memory_mb, 4096);
    }

    type Reply = (u16, String);

    fn run_pve<F, T>(respond: F, f: impl FnOnce() -> T) -> (T, Vec<String>)
    where
        F: Fn(&str, &str, &str) -> Reply + 'static,
    {
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = log.clone();
        let out = plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, raw: &str| {
                assert_eq!(cap, "api.call");
                let (method, path, args) = crate::test_support::api_call_route(raw);
                let path = path.trim_start_matches('/').to_string();
                let body = if args["body"].is_null() {
                    String::new()
                } else {
                    args["body"].to_string()
                };
                seen.lock().unwrap().push(format!("{method} {path} {body}"));
                let (status, out) = respond(&method, &path, &body);
                crate::test_support::api_call_reply(
                    &serde_json::json!({ "status": status, "body": out.into_bytes() }).to_string(),
                )
            }),
            f,
        );
        let log = log.lock().unwrap().clone();
        (out, log)
    }

    const TRAP_CONFIG: &str = r#"{"data":{"digest":"d1","memory":4096,"lxc":[["lxc.mount.entry","tmpfs dev/shm tmpfs size=6g,mode=1777 0 0"]]}}"#;

    fn pve_reply(put: Reply) -> impl Fn(&str, &str, &str) -> Reply + 'static {
        move |method, path, _body| match (method, path) {
            ("GET", "nodes/thor/lxc/110/config") => (200, TRAP_CONFIG.to_string()),
            ("GET", "nodes/thor/status") => (
                200,
                r#"{"data":{"memory":{"total":68719476736}}}"#.to_string(),
            ),
            ("PUT", "nodes/thor/lxc/110/config") => put.clone(),
            _ => (404, "{}".to_string()),
        }
    }

    #[test]
    fn repair_reads_then_puts_memory_with_the_digest() {
        let (msg, log) = run_pve(pve_reply((200, r#"{"data":null}"#.to_string())), || {
            raise_ct_memory("pve", "thor", 110, 12288)
        });
        assert!(msg.unwrap().contains("12288 MiB"));
        assert_eq!(log.len(), 3, "{log:?}");
        assert!(
            log[2].starts_with("PUT nodes/thor/lxc/110/config "),
            "{log:?}"
        );
        assert!(
            log[2].contains(r#""memory":"12288""#) && log[2].contains(r#""digest":"d1""#),
            "{log:?}"
        );
    }

    #[test]
    fn repair_surfaces_a_digest_mismatch() {
        let reply = (
            400,
            r#"{"errors":{"digest":"detected modified configuration"}}"#.to_string(),
        );
        let (out, _) = run_pve(pve_reply(reply), || {
            raise_ct_memory("pve", "thor", 110, 12288)
        });
        let err = out.unwrap_err();
        assert!(
            err.contains("PUT CT 110 memory") && err.contains("400"),
            "{err}"
        );
    }

    #[test]
    fn repair_rejects_a_mismatched_or_oversized_target() {
        let (out, log) = run_pve(pve_reply((200, "{}".to_string())), || {
            raise_ct_memory("pve", "thor", 110, 999_999)
        });
        let err = out.unwrap_err();
        assert!(err.contains("does not match a current shm trap"), "{err}");
        assert!(!log.iter().any(|l| l.starts_with("PUT")));

        let small_node = |method: &str, path: &str, _: &str| match (method, path) {
            ("GET", "nodes/thor/lxc/110/config") => (200, TRAP_CONFIG.to_string()),
            ("GET", "nodes/thor/status") => (
                200,
                r#"{"data":{"memory":{"total":8589934592}}}"#.to_string(),
            ),
            _ => (200, r#"{"data":null}"#.to_string()),
        };
        let (out, log) = run_pve(small_node, || raise_ct_memory("pve", "thor", 110, 12288));
        let err = out.unwrap_err();
        assert!(err.contains("exceeds node thor memory (8192 MiB)"), "{err}");
        assert!(!log.iter().any(|l| l.starts_with("PUT")));
    }

    #[test]
    fn a_failed_ct_config_read_does_not_stop_the_sweep() {
        let routes = |_: &str, path: &str, _: &str| {
            match path {
            "cluster/resources" => (
                200,
                r#"{"data":[{"type":"lxc","node":"thor","vmid":109},{"type":"lxc","node":"thor","vmid":110,"name":"mimir"}]}"#
                    .to_string(),
            ),
            "nodes/thor/lxc/110/config" => (200, TRAP_CONFIG.to_string()),
            _ => (500, "{}".to_string()),
        }
        };
        let (findings, log) = run_pve(routes, || shm_findings("pve"));
        let findings = findings.unwrap();
        assert!(
            log.iter()
                .any(|l| l.starts_with("GET nodes/thor/lxc/109/config"))
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "lxc-shm-trap::thor::110::dev/shm");
    }

    #[test]
    fn malformed_shm_memory_id_fails_cleanly() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt.block_on(repair(RepairArgs {
            provider: "proxmox".into(),
            repair_id: "shm-memory::pve::thor::notanum::2048".into(),
            confirm: true,
        }));
        assert!(!out.ok);
        assert!(out.message.contains("malformed"));
    }

    #[test]
    fn unknown_diagnostics_op_is_an_error() {
        let r = dispatch("proxmox.__diagnostics.bogus", serde_json::json!({})).unwrap();
        assert!(r.is_err());
        assert!(dispatch("proxmox.__unit.list", serde_json::json!({})).is_none());
    }

    #[test]
    fn guest_install_repair_is_honest_no_channel_guidance() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt.block_on(repair(RepairArgs {
            provider: "proxmox".into(),
            repair_id: "guest-install::pve::n1::104".into(),
            confirm: true,
        }));
        assert!(!out.ok, "no in-guest channel — must not claim success");
        assert!(out.message.contains("qemu-guest-agent"));
        assert_eq!(out.id, "guest-install::pve::n1::104");
    }
}
