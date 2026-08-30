//! Domain-backend registration for the hybrid export.
//!
//! proxmox contributes five backends to orca's `contract` registries:
//!
//! - `cluster_roster` (`proxmox.list_clusters`) — fleet cluster grouping.
//! - `topology` (`proxmox.collect_claims`) — parent-host nesting by guest MACs.
//! - `host_facts` (`proxmox.get_facts`) — this host's cluster membership, folded
//!   into its mesh-propagated system snapshot for grouping from any vantage.
//! - `unit` (`proxmox.__unit.*`) — the five-verb managed-unit surface exposing
//!   every cluster VM/LXC as a unit (see [`crate::unit_provider`]).
//! - `diagnostics` (`proxmox.__diagnostics.*`) — QEMU guest-agent assurance
//!   (see [`crate::diagnostics`]).
//! - `deploy_target` (`proxmox.__deploy.{endpoint}/{kind}.*`) — the generic
//!   deploy front door, one target per configured row (see [`crate::deploy`]).
//!
//! The first three route back through the normal `proxmox.` tool dispatch (their
//! ops ARE `#[orca_tool]`s), so [`backend_dispatch`] falls through for them and
//! the macro's hybrid `invoke` reaches the tool surface. The `unit` and
//! `diagnostics` backends need bespoke routing — they dispatch through
//! [`contract::unit::dispatch_op`] / [`crate::diagnostics::dispatch`] against
//! their providers.

use std::sync::OnceLock;

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::backend_def::{host_facts_backend_def, topology_backend_def, unit_backend_def};
use plugin_toolkit::contract::unit::UnitProvider;
use plugin_toolkit::serde_json;

use crate::unit_provider::ProxmoxUnitProvider;

const UNIT_PREFIX: &str = "proxmox.__unit";

fn unit_provider() -> &'static ProxmoxUnitProvider {
    static PROVIDER: OnceLock<ProxmoxUnitProvider> = OnceLock::new();
    PROVIDER.get_or_init(ProxmoxUnitProvider::new)
}

/// Backend descriptors this plugin advertises. cluster_roster + topology keep
/// their `proxmox` prefix (routing to `proxmox.list_clusters` /
/// `proxmox.collect_claims` tools); the unit backend routes to `proxmox.__unit`.
pub fn backends_json() -> String {
    let mut defs = vec![
        BackendDef {
            domain: "cluster_roster".to_string(),
            name: "proxmox".to_string(),
            invoke_prefix: "proxmox".to_string(),
            ..Default::default()
        },
        topology_backend_def("proxmox", "proxmox"),
        // Reports this host's cluster membership (via the PVE API) into its
        // mesh-propagated system snapshot → routes to `proxmox.get_facts`.
        host_facts_backend_def("proxmox", "proxmox"),
        // Derived from the live provider's declarations rather than restated as
        // a literal — add a kind or verb to ProxmoxUnitProvider and the
        // registered unit backend follows automatically.
        unit_backend_def(unit_provider() as &dyn UnitProvider, UNIT_PREFIX),
        // QEMU guest-agent assurance — routes `proxmox.__diagnostics.*`.
        crate::diagnostics::diagnostics_backend_def(),
        // Per-guest network mounts (unprivileged LXC `lxc.mount.entry`) — routes
        // `proxmox.__guest_mount.*` (see [`crate::guest_mount`]).
        crate::guest_mount::guest_mount_backend_def(),
    ];
    // Three config-backup KINDs — pve-config / vm / lxc — each routing
    // `proxmox.__backup_*.*` (see [`crate::backup`]).
    defs.extend(crate::backup::backend_defs());
    // One generic `deploy_target` per configured `(endpoint, kind)` row —
    // routes `proxmox.__deploy.{endpoint}/{kind}.*` (see [`crate::deploy`]).
    defs.extend(crate::deploy::backend_defs());
    serde_json::to_string(&defs).unwrap_or_else(|_| "[]".to_string())
}

/// Handle the loader's `proxmox.__unit.*` backend calls against the singleton
/// [`ProxmoxUnitProvider`]. Returns `None` for anything else so the macro's
/// hybrid `invoke` falls through to the `proxmox.` tool surface (which owns the
/// cluster_roster + topology ops). Async work is driven to completion on the
/// subprocess reactor via [`plugin_toolkit::reactor::block_on`].
pub fn backend_dispatch(
    name: &str,
    args: plugin_toolkit::serde_json::Value,
) -> Option<Result<plugin_toolkit::serde_json::Value, plugin_toolkit::serde_json::Value>> {
    if let Some(op) = name
        .strip_prefix(UNIT_PREFIX)
        .and_then(|s| s.strip_prefix('.'))
    {
        // `dispatch_op` now takes a parsed `Value` and returns
        // `Result<Value, Value>` — exactly this backend ABI's shape.
        return Some(plugin_toolkit::reactor::block_on(
            plugin_toolkit::contract::unit::dispatch_op(
                unit_provider() as &dyn UnitProvider,
                op,
                args,
            ),
        ));
    }
    // The sub-dispatchers each take the args `Value` by value and return `None`
    // when the name isn't theirs, so clone for every attempt but the last.
    // Config-backup KINDs (`proxmox.__backup_pveconfig|vm|lxc.*`).
    if let Some(res) = crate::backup::dispatch(name, args.clone()) {
        return Some(res);
    }
    // Generic deploy-target ops (`proxmox.__deploy.{endpoint}/{kind}.*`).
    if let Some(res) = crate::deploy::dispatch(name, args.clone()) {
        return Some(res);
    }
    // Per-guest network mounts (`proxmox.__guest_mount.*`).
    if let Some(res) = crate::guest_mount::dispatch(name, args.clone()) {
        return Some(res);
    }
    // QEMU guest-agent diagnostics (`proxmox.__diagnostics.*`).
    crate::diagnostics::dispatch(name, args)
}
