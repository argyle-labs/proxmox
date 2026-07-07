//! Domain-backend registration for the hybrid export.
//!
//! proxmox contributes three backends to orca's `contract` registries:
//!
//! - `cluster_roster` (`proxmox.list_clusters`) — fleet cluster grouping.
//! - `topology` (`proxmox.collect_claims`) — parent-host nesting by guest MACs.
//! - `unit` (`proxmox.__unit.*`) — the five-verb managed-unit surface exposing
//!   every cluster VM/LXC as a unit (see [`crate::unit_provider`]).
//!
//! The first two route back through the normal `proxmox.` tool dispatch (their
//! ops ARE `#[orca_tool]`s), so [`backend_dispatch`] returns `None` for them and
//! the macro's hybrid `invoke` falls through to the tool surface. Only the
//! `unit` backend needs bespoke routing — it dispatches through
//! [`contract::unit::dispatch_op`] against the singleton provider.

use std::sync::OnceLock;

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::contract::unit::UnitProvider;
use plugin_toolkit::export::{dispatch_unit_op, topology_backend_def, unit_backend_def};
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
    let defs = vec![
        BackendDef {
            domain: "cluster_roster".to_string(),
            name: "proxmox".to_string(),
            invoke_prefix: "proxmox".to_string(),
            ..Default::default()
        },
        topology_backend_def("proxmox", "proxmox"),
        // Derived from the live provider's declarations rather than restated as
        // a literal — add a kind or verb to ProxmoxUnitProvider and the
        // registered unit backend follows automatically.
        unit_backend_def(unit_provider() as &dyn UnitProvider, UNIT_PREFIX),
    ];
    serde_json::to_string(&defs).unwrap_or_else(|_| "[]".to_string())
}

/// Handle the loader's `proxmox.__unit.*` backend calls against the singleton
/// [`ProxmoxUnitProvider`]. Returns `None` for anything else so the macro's
/// hybrid `invoke` falls through to the `proxmox.` tool surface (which owns the
/// cluster_roster + topology ops). Async work runs on the toolkit's shared
/// runtime behind the synchronous FFI boundary.
pub fn backend_dispatch(name: &str, args_json: &str) -> Option<Result<String, String>> {
    let op = name.strip_prefix(UNIT_PREFIX)?.strip_prefix('.')?;
    Some(dispatch_unit_op(
        unit_provider() as &dyn UnitProvider,
        op,
        args_json,
    ))
}
