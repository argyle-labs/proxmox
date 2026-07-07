//! Generate the typed Proxmox VE client from the vendored OpenAPI spec.
//!
//! Refresh the vendored spec from a fresh `apidoc.js` pulled from a cluster
//! node (Proxmox ships `apidoc.js`, not OpenAPI):
//!   cargo run --example pve_to_openapi -- apidoc.js > specs/proxmox.openapi.json

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

    // Generate the orca tool surface from the just-emitted client via the
    // shared toolkit pass (was the local `build/surface.rs` prototype). Write
    // methods surface as `data_mutation = true` + `role = "admin"`; a specific
    // operation can opt out to `role = "read"` via `x-orca-user-callable: true`
    // in the spec.
    plugin_toolkit_build::surface::openapi::generate(&specs_dir, &out_dir, "proxmox")
        .expect("proxmox surface codegen");
}
