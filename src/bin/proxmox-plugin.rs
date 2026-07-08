//! Out-of-process entrypoint for the proxmox plugin.
//!
//! orca spawns this binary as a subprocess and connects a Unix-domain socket
//! (`$ORCA_PLUGIN_SOCKET`); [`plugin_toolkit::serve::serve`] performs the
//! wire-protocol handshake and then serves tool + backend invocations until orca
//! sends `Shutdown`. HTTP to the PVE API stays in-process (progenitor's client
//! still links reqwest); DB / secret access is delegated to orca over the
//! capability channel.
//!
//! This shares its declared surface with the cdylib export
//! ([`proxmox::abi_export`]): the SAME `registration::backends_json()` and
//! `registration::backend_dispatch` back both entrypoints, so the in-process and
//! out-of-process forms stay in lockstep. The cdylib is retired once every host
//! runs a daemon new enough to spawn subprocesses.

use plugin_toolkit::serve::{PluginSpec, serve};

fn main() -> anyhow::Result<()> {
    // Logs go to stderr, which orca's supervisor inherits from the child.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    serve(PluginSpec {
        name: "proxmox".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        prefixes: vec!["proxmox.".to_string()],
        // Same declarations the cdylib export advertises — cluster_roster,
        // topology, host_facts, and the five-verb unit surface.
        backends_json: proxmox::registration::backends_json(),
        schema_json: plugin_toolkit::export::EMPTY_SCHEMAS.to_string(),
        // Routes `proxmox.__unit.*` to the unit provider; declines everything
        // else so serve() falls through to the `#[orca_tool]` surface.
        backend_dispatch: Some(proxmox::registration::backend_dispatch),
    })
}
