//! QEMU guest-agent assurance — a `diagnostics` domain provider.
//!
//! orca can only run in-guest exec / clean-shutdown / live-IP discovery against
//! a QEMU VM when the VM has the guest agent **both** enabled in its PVE config
//! (`agent: 1`) **and** the `qemu-guest-agent` package installed + running
//! inside the guest. This provider diagnoses that, per running VM, and proposes
//! repairs that flow — via orca's diagnostics→notification bridge — into
//! dismissable notifications the user can act on, ignore, or ignore permanently.
//!
//! Two findings:
//!
//! * **disabled** — the VM is running but `agent` is off/absent in its config.
//!   Repair (`enable::…`) is in-place: PUT `agent: 1` on the VM config. It needs
//!   confirmation (not automatic) because it only takes effect after a
//!   power-cycle and still requires the in-guest package.
//! * **unresponsive** — `agent` is enabled in config but the guest agent does
//!   not answer a ping: the package is almost certainly not installed/running
//!   in the guest. There is no in-guest channel to fix this automatically, so
//!   the repair (`guest-install::…`) returns honest manual guidance rather than
//!   pretending to act. This is the VM104 / gha-runner case.
//!
//! LXC guests need no agent (orca uses `pct exec` on the node), so they are not
//! diagnosed here.

use crate::generated::{self, types as gtypes};
use crate::tools::{for_each_enabled_endpoint, resolve_config};
use crate::{GuestKind, fetch_guest_config, responses::GuestConfigData};
use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::contract::diagnostics::{
    DIAGNOSE_OP, DiagnoseArgs, Finding, REPAIR_OP, RepairArgs, RepairOutcome, RepairSpec, Severity,
};
use plugin_toolkit::serde_json;

/// Backend invoke prefix — the loader forms `{prefix}.{diagnose|repair}` and
/// routes it here through [`crate::registration::backend_dispatch`].
pub const DIAG_PREFIX: &str = "proxmox.__diagnostics";
const PROVIDER: &str = "proxmox";

/// The `diagnostics` backend descriptor this plugin advertises.
pub fn diagnostics_backend_def() -> BackendDef {
    BackendDef {
        domain: "diagnostics".to_string(),
        name: PROVIDER.to_string(),
        invoke_prefix: DIAG_PREFIX.to_string(),
        ..Default::default()
    }
}

/// Route a `proxmox.__diagnostics.{diagnose|repair}` backend call. Returns
/// `None` for any other name so the caller can fall through.
pub fn dispatch(name: &str, args_json: &str) -> Option<Result<String, String>> {
    let op = name
        .strip_prefix(DIAG_PREFIX)?
        .strip_prefix('.')?
        .to_string();
    let args_json = args_json.to_string();
    Some(plugin_toolkit::reactor::block_on(async move {
        if op == DIAGNOSE_OP {
            let args: DiagnoseArgs =
                serde_json::from_str(&args_json).map_err(|e| format!("diagnose args: {e}"))?;
            let findings = diagnose(args).await;
            serde_json::to_string(&findings).map_err(|e| e.to_string())
        } else if op == REPAIR_OP {
            let args: RepairArgs =
                serde_json::from_str(&args_json).map_err(|e| format!("repair args: {e}"))?;
            let outcome = repair(args).await;
            serde_json::to_string(&outcome).map_err(|e| e.to_string())
        } else {
            Err(format!("unknown diagnostics op '{op}'"))
        }
    }))
}

/// Guest-agent state for one running QEMU VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentState {
    /// Enabled in config and responding — healthy, no finding.
    Ok,
    /// Not enabled in the VM config.
    Disabled,
    /// Enabled in config but not answering (package missing/stopped in guest).
    Unresponsive,
}

/// Pure classifier: given whether the agent is enabled in config and whether it
/// answered a ping, decide the state.
fn classify(enabled_in_config: bool, ping_ok: bool) -> AgentState {
    if !enabled_in_config {
        AgentState::Disabled
    } else if ping_ok {
        AgentState::Ok
    } else {
        AgentState::Unresponsive
    }
}

/// Is the QEMU guest agent enabled in a VM config's `agent` field? PVE returns
/// it either as a bare `1`/`0` or a property string like
/// `enabled=1,fstrim_cloned_disks=1`.
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

/// Diagnose every running QEMU VM across all enabled endpoints.
pub async fn diagnose(_args: DiagnoseArgs) -> Vec<Finding> {
    for_each_enabled_endpoint("diagnostics.qemu_agent", |cfg, ep| async move {
        let http = cfg.build_reqwest_client()?;
        let client = generated::Client::new_with_client(&cfg.base_url, http.clone());
        let items = client
            .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
            .await
            .map_err(|e| anyhow::anyhow!("cluster resources: {e}"))?
            .into_inner();

        let mut findings = Vec::new();
        for e in items {
            if !matches!(
                e.type_,
                gtypes::GetResourcesClusterResourcesResponseItemType::Qemu
            ) {
                continue;
            }
            if e.template.unwrap_or(false) {
                continue;
            }
            if e.status.as_deref() != Some("running") {
                continue; // a stopped VM can't answer the agent — not a fault.
            }
            let (node, vmid) = match (e.node, e.vmid) {
                (Some(n), Some(v)) if !n.is_empty() && v > 0 => (n, v as u64),
                _ => continue,
            };
            let name = e.name.unwrap_or_else(|| format!("vmid-{vmid}"));

            let cfg_resp = match fetch_guest_config(
                &http,
                &cfg.base_url,
                &node,
                GuestKind::Qemu,
                vmid,
            )
            .await
            {
                Ok(c) => c,
                Err(err) => {
                    tracing::debug!(node = %node, vmid, error = %err,
                            "qemu-agent diag: guest_config failed (guest may have been deleted)");
                    continue;
                }
            };
            let enabled = config_agent_enabled(&cfg_resp.data);

            // Only ping when the config says the agent should be up; a ping to a
            // config-disabled agent always fails and would be noise.
            let ping_ok = if enabled {
                client
                    .post_ping_nodes_node_qemu_vmid_agent_ping(&node, vmid as i64)
                    .await
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

/// Parse a repair id `<action>::<endpoint>::<node>::<vmid>`.
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

/// Run a repair by its `RepairSpec.id`.
pub async fn repair(args: RepairArgs) -> RepairOutcome {
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
        // No in-guest channel — return honest, actionable guidance rather than
        // pretending to remediate.
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

/// Set `agent: 1` on a VM's config via the PVE API.
async fn enable_agent(endpoint: &str, node: &str, vmid: u64) -> anyhow::Result<()> {
    let cfg = resolve_config(endpoint).await?;
    let client = cfg.build_generated_client()?;
    let body = gtypes::PutUpdateVmNodesNodeQemuVmidConfigBody {
        agent: Some("1".to_string()),
        ..Default::default()
    };
    client
        .put_update_vm_nodes_node_qemu_vmid_config(node, vmid as i64, &body)
        .await
        .map_err(|e| anyhow::anyhow!("PUT vm config: {e}"))?;
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
        // absent
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
    fn unknown_diagnostics_op_is_an_error() {
        let r = dispatch("proxmox.__diagnostics.bogus", "{}").unwrap();
        assert!(r.is_err());
        // A non-diagnostics name falls through.
        assert!(dispatch("proxmox.__unit.list", "{}").is_none());
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
