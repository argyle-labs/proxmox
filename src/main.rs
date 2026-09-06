//! Dynamic (subprocess) entrypoint for the proxmox plugin.
//!
//! proxmox is a **hybrid** plugin: the `proxmox.` `#[orca_tool]` surface PLUS a
//! spread of typed domain facets, all composed on the [`Plugin`] builder — which
//! emits the combined `backends()` payload and the single wire dispatch, so the
//! plugin hand-writes no op-string routing.
//!
//! Facets:
//! * `unit` — the five-verb managed-unit surface (every cluster VM/LXC).
//! * `topology` — parent-host nesting by guest MACs.
//! * `host_facts` — this host's corosync cluster membership.
//! * `diagnostics` — QEMU guest-agent + LXC shm-trap + host-workload assurance.
//! * `cluster_roster` — fleet cluster grouping. A **tool-backed** backend: its op
//!   IS the `proxmox.list_clusters` `#[orca_tool]`, so it advertises a def only
//!   and dispatch falls through to the tool surface.
//! * `backup` (3 KINDs) + `deploy_target` (one per configured row) — dynamic,
//!   config-derived backend sets with no single-instance typed builder facet, so
//!   they ride the builder's `.backend(def, dispatcher)` escape hatch, reusing the
//!   existing `crate::backup::dispatch` / `crate::deploy::dispatch` routers.

plugin_toolkit::instrument::bootstrap!();

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::plugin::Plugin;

// Force-link the `proxmox.` #[orca_tool] surface so its inventory (a separate
// module from the facets referenced below) isn't dead-stripped at link time.
// Other `proxmox::` refs below already pull the rlib today, but keep this guard
// so the inventory survives if those refs ever change.
#[allow(unused_imports)]
use proxmox::tools as _;

fn main() -> plugin_toolkit::anyhow::Result<()> {
    let mut plugin = Plugin::named("proxmox")
        .version(env!("CARGO_PKG_VERSION"))
        .tools(["proxmox."])
        .schema_json(proxmox::deploy::schemas_json())
        .unit(proxmox::unit_provider::ProxmoxUnitProvider::new())
        .topology(proxmox::topology::ProxmoxTopology)
        .host_facts(proxmox::cluster_roster_impl::ProxmoxHostFacts)
        .diagnostics(proxmox::diagnostics::ProxmoxDiagnostics)
        // cluster_roster: def only — its op is the `proxmox.list_clusters` tool,
        // so dispatch falls through to the `#[orca_tool]` surface.
        .tool_backend(BackendDef {
            domain: "cluster_roster".to_string(),
            name: "proxmox".to_string(),
            invoke_prefix: "proxmox".to_string(),
            ..Default::default()
        });

    // Config-backup KINDs (`proxmox.__backup_*.*`) — dynamic set, shared router.
    for def in proxmox::backup::backend_defs() {
        plugin = plugin.backend(def, Box::new(proxmox::backup::dispatch));
    }
    // Generic deploy-target rows (`proxmox.__deploy.{endpoint}/{kind}.*`) — one
    // def per configured row, shared router keyed by the row id.
    for def in proxmox::deploy::backend_defs() {
        plugin = plugin.backend(def, Box::new(proxmox::deploy::dispatch));
    }

    plugin.serve()
}
