//! Generate the typed Proxmox VE client and the `orca.api-surface/v1` table
//! from the vendored OpenAPI spec.
//!
//! Refresh the vendored spec from a fresh `apidoc.js` pulled from a cluster
//! node (Proxmox ships `apidoc.js`, not OpenAPI):
//!   cargo run --example pve_to_openapi -- apidoc.js > specs/proxmox.openapi.json

use openapi::surface::{Auth, AuthScheme, EndpointBinding, ResponseRules};
use plugin_toolkit_build::surface_table;

fn main() {
    let specs_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs");
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    // Proxmox VE diverges from its own documented schema on the wire in three
    // ways, all handled at the deserialize/transport seam so the generated
    // types stay inline with the docs and no call site is patched:
    //   * every body is wrapped in `{"data": …}` — peeled by `unwrap_envelope`;
    //   * booleans are documented as `boolean` but serialized as integer 0/1 —
    //     accepted by the lenient bool deserializers;
    //   * PSI `pressure*` fields are documented as `number` but serialized as
    //     quoted strings (`"0.00"`) — accepted by the lenient number
    //     deserializers (the type stays `f64`).
    plugin_toolkit_build::openapi::generate_all_with_options(
        &specs_dir,
        "proxmox",
        plugin_toolkit_build::openapi::CodegenOptions {
            unwrapper: Some("crate::unwrap_envelope"),
            lenient_booleans: true,
            lenient_numbers: true,
        },
    )
    .expect("proxmox openapi codegen");

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
            endpoint: EndpointBinding::default(),
            read_allowlist: Some(specs_dir.join("read_allowlist.txt")),
            gated_gets: Some(specs_dir.join("gated_gets.txt")),
            renames: Default::default(),
        },
    )
    .expect("proxmox api surface table");
}
