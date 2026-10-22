//! Generate the `orca.api-surface/v1` table from the vendored OpenAPI spec.
//!
//! Refresh the vendored spec from a fresh `apidoc.js` pulled from a cluster
//! node (Proxmox ships `apidoc.js`, not OpenAPI):
//!   cargo run --example pve_to_openapi -- apidoc.js > specs/proxmox.openapi.json

use openapi::surface::{Auth, AuthScheme, EndpointBinding, ResponseRules};
use plugin_toolkit_build::surface_table;

fn main() {
    let specs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    // Proxmox VE diverges from its documented schema on the wire: every body
    // is wrapped in `{"data": …}`, booleans arrive as 0/1, and PSI `pressure*`
    // numbers arrive quoted. The `response` rules below tell core's executor.
    surface_table::openapi::generate(
        &specs_dir.join("proxmox.openapi.json"),
        &out_dir,
        "proxmox",
        &surface_table::openapi::Options {
            api_root: "/api2/json".to_string(),
            auth: Some(Auth {
                scheme: AuthScheme::Header,
                header: "Authorization".to_string(),
                template: "PVEAPIToken={endpoint.token_id}={secret}".to_string(),
                secret: "proxmox.{endpoint}.token_secret".to_string(),
            }),
            response: ResponseRules {
                envelope: Some("/data".to_string()),
                null_as: None,
                lenient_bool: true,
                lenient_number: true,
            },
            endpoint: EndpointBinding {
                columns: vec!["token_id".to_string()],
                ..EndpointBinding::default()
            },
            read_allowlist: Some(specs_dir.join("read_allowlist.txt")),
            gated_gets: Some(specs_dir.join("gated_gets.txt")),
            renames: Default::default(),
        },
    )
    .expect("proxmox api surface table");
}
