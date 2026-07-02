//! Convert a Proxmox VE `apidoc.js` (or `apidoc.json`) into an OpenAPI 3.x
//! spec and print it to stdout — the Proxmox-specific spec-refresh step.
//!
//! Proxmox ships its API description as `apidoc.js` (a JS `apidoc` tree), not
//! OpenAPI. This example walks that dialect and emits an `openapiv3` document.
//! It is Proxmox-only, so it lives with the proxmox plugin — not in orca's
//! generic `openapi` crate. The generic normalize → progenitor pass runs at
//! build time in `build.rs` (`plugin_toolkit_build::openapi::generate_all`),
//! so this tool only needs to parse and serialize.
//!
//! Refresh the vendored spec:
//!   cargo run --example pve_to_openapi -- path/to/apidoc.js > specs/proxmox.openapi.json

#[path = "../spec-tools/from_pve.rs"]
mod from_pve;

use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let path: PathBuf = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: pve_to_openapi <apidoc.js>"))?
        .into();
    let raw = std::fs::read_to_string(&path)?;
    let spec = from_pve::parse_str(&raw)?;
    eprintln!("pve_to_openapi: paths={}", spec.paths.paths.len());
    let out = serde_json::to_string_pretty(&spec)?;
    println!("{out}");
    Ok(())
}
