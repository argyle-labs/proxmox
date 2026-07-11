//! Dynamic (subprocess) entrypoint for the proxmox plugin.
//!
//! The toolkit's `serve_tool_plugin!` (hybrid arm) emits `fn main`, serving this
//! plugin over the orca socket. This is the dynamic replacement for the retired
//! cdylib `export_tool_plugin!` export — the plugin is a `[[bin]]`, owns only its
//! domain client, and reaches orca only through the socket.
//!
//! proxmox is a **hybrid** plugin: the `proxmox.` tool surface PLUS three domain
//! backends — `cluster_roster`, `topology`, and the five-verb `unit` surface (see
//! [`proxmox::registration`]). `backends` advertises all three; `backend_dispatch`
//! handles the loader's `proxmox.__unit.*` calls and declines everything else so
//! serve() falls through to the `#[orca_tool]` surface.
plugin_toolkit::serve_tool_plugin! {
    name: "proxmox",
    target_compat: ">=7.0",
    backends: proxmox::registration::backends_json(),
    backend_dispatch: proxmox::registration::backend_dispatch,
}
