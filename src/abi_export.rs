//! ABI-stable cdylib export for the proxmox plugin.
//!
//! proxmox is a **hybrid** plugin: the `proxmox.` tool surface (endpoint
//! registry CRUD + node/guest drill-in + lifecycle) PLUS three domain backends
//! — `cluster_roster`, `topology`, and the five-verb `unit` surface (see
//! [`crate::registration`]). The toolkit's [`export_tool_plugin!`] hybrid arm
//! generates the metadata fns, the `proxmox.`-scoped manifest, and an `invoke`
//! that tries the backend dispatch first (the `proxmox.__unit.*` calls the
//! loader makes) then falls through to tool dispatch. cluster_roster + topology
//! route through the tool surface, so `backend_dispatch` returns `None` for them.
//!
//! `abi_stable` remains a direct dep because `#[export_root_module]` (which the
//! macro invokes) expands to bare `::abi_stable` paths.

plugin_toolkit::export_tool_plugin! {
    name: "proxmox",
    target_compat: ">=7.0",
    backends: crate::registration::backends_json(),
    backend_dispatch: crate::registration::backend_dispatch,
}
