//! Dynamic (subprocess) entrypoint for the proxmox plugin.
//!
//! proxmox is a **hybrid** plugin: the `proxmox.` `#[orca_tool]` surface PLUS a
//! spread of typed domain facets, all composed on the [`Plugin`] builder — which
//! emits the combined `backends()` payload and the single wire dispatch, so the
//! plugin hand-writes no op-string routing.
//!
//! Facets:
//! * `unit` — the five-verb managed-unit surface (every cluster VM/LXC).
//!
//! `unit`, `diagnostics` and `guest_exec` reach execute-gated api-surface ops,
//! which core refuses unless the backend declares them in `reaches`; the typed
//! facet builders take no `reaches`, so those three ride `.backend` with the
//! same prefix routing the facets emit.
//! * `topology` — parent-host nesting by guest MACs.
//! * `host_facts` — this host's corosync cluster membership.
//! * `diagnostics` — QEMU guest-agent + LXC shm-trap + host-workload assurance.
//! * `cluster_roster` — fleet cluster grouping. A **tool-backed** backend: its op
//!   IS the `proxmox.list_clusters` `#[orca_tool]`, so it advertises a def only
//!   and dispatch falls through to the tool surface.
//! * `guest_mount` — network-share mounts inside LXCs, via the `.backend` hatch.
//! * `backup` (3 KINDs) + `deploy_target` (one per configured row) — dynamic,
//!   config-derived backend sets with no single-instance typed builder facet, so
//!   they ride the builder's `.backend(def, dispatcher)` escape hatch, reusing the
//!   existing `crate::backup::dispatch` / `crate::deploy::dispatch` routers.

plugin_toolkit::instrument::bootstrap!();

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::contract::diagnostics::DiagnosticsProvider;
use plugin_toolkit::contract::guest_exec::GuestExec;
use plugin_toolkit::contract::unit::UnitProvider;
use plugin_toolkit::plugin::Plugin;
use plugin_toolkit::serde_json::Value;

type Dispatcher = Box<dyn Fn(&str, Value) -> Option<Result<Value, Value>>>;

fn route<F>(prefix: String, op: F) -> Dispatcher
where
    F: Fn(&str, Value) -> Result<Value, Value> + 'static,
{
    Box::new(move |tool: &str, args: Value| {
        let rest = tool.strip_prefix(&prefix)?.strip_prefix('.')?;
        Some(op(rest, args))
    })
}

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
        .api_surface("proxmox", proxmox::API_SURFACE)
        .schema_json(proxmox::deploy::schemas_json())
        .topology(proxmox::topology::ProxmoxTopology)
        .host_facts(proxmox::cluster_roster_impl::ProxmoxHostFacts)
        .backend(
            proxmox::guest_mount::guest_mount_backend_def(),
            Box::new(proxmox::guest_mount::dispatch),
        )
        // cluster_roster: def only — its op is the `proxmox.list_clusters` tool,
        // so dispatch falls through to the `#[orca_tool]` surface.
        .tool_backend(BackendDef {
            domain: "cluster_roster".to_string(),
            name: "proxmox".to_string(),
            invoke_prefix: "proxmox".to_string(),
            ..Default::default()
        });

    let unit = proxmox::unit_provider::ProxmoxUnitProvider::new();
    let prefix = format!("unit.__backend.{}", unit.name());
    let def = BackendDef {
        reaches: proxmox::unit_provider::reaches(),
        ..plugin_toolkit::backend_def::unit_backend_def(&unit, &prefix)
    };
    plugin = plugin.backend(
        def,
        route(prefix, move |op, args| {
            plugin_toolkit::reactor::block_on(plugin_toolkit::contract::unit::dispatch_op(
                &unit, op, args,
            ))
        }),
    );

    let diagnostics = proxmox::diagnostics::ProxmoxDiagnostics;
    let prefix = format!("diagnostics.__backend.{}", diagnostics.name());
    plugin =
        plugin.backend(
            BackendDef {
                domain: "diagnostics".to_string(),
                name: diagnostics.name().to_string(),
                invoke_prefix: prefix.clone(),
                reaches: vec![proxmox::diagnostics::ENABLE_AGENT_OP.to_string()],
                ..Default::default()
            },
            route(prefix, move |op, args| {
                plugin_toolkit::reactor::block_on(
                    plugin_toolkit::contract::diagnostics::dispatch_op(&diagnostics, op, args),
                )
            }),
        );

    let guest_exec = proxmox::guest_exec::ProxmoxGuestExec;
    let prefix = format!("guest_exec.__backend.{}", guest_exec.name());
    plugin =
        plugin.backend(
            BackendDef {
                domain: "guest_exec".to_string(),
                name: guest_exec.name().to_string(),
                invoke_prefix: prefix.clone(),
                reaches: proxmox::guest_exec::REACHES.map(String::from).to_vec(),
                ..Default::default()
            },
            route(prefix, move |op, args| {
                plugin_toolkit::reactor::block_on(
                    plugin_toolkit::contract::guest_exec::dispatch_op(&guest_exec, op, args),
                )
            }),
        );

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
