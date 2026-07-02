//! Generate the typed Proxmox VE client from the vendored OpenAPI spec.
//!
//! Refresh the vendored spec from a fresh `apidoc.js` pulled from a cluster
//! node (Proxmox ships `apidoc.js`, not OpenAPI):
//!   cargo run --example pve_to_openapi -- apidoc.js > specs/proxmox.openapi.json

fn main() {
    let specs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs");
    plugin_toolkit_build::openapi::generate_all(specs_dir, "proxmox")
        .expect("proxmox openapi codegen");
}
