//! Generate the typed Proxmox VE client from the vendored OpenAPI spec.
//!
//! Refresh: `make proxmox-spec-refresh` (re-runs `openapi::from_pve` over
//! a fresh `apidoc.js` pulled from a cluster node).

fn main() {
    let specs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs");
    plugin_toolkit_build::openapi::generate_all(specs_dir, "proxmox")
        .expect("proxmox openapi codegen");
}
