//! Generate the typed Proxmox VE client from the vendored OpenAPI spec.
//!
//! Refresh the vendored spec from a fresh `apidoc.js` pulled from a cluster
//! node (Proxmox ships `apidoc.js`, not OpenAPI):
//!   cargo run --example pve_to_openapi -- apidoc.js > specs/proxmox.openapi.json

#[path = "build/ungate.rs"]
mod ungate;

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

    plugin_toolkit_build::surface::openapi::generate(&specs_dir, &out_dir, "proxmox")
        .expect("proxmox surface codegen");

    let allowlist_path = specs_dir.join("read_allowlist.txt");
    println!("cargo:rerun-if-changed={}", allowlist_path.display());
    println!("cargo:rerun-if-changed=build/ungate.rs");
    let gated_path = specs_dir.join("gated_gets.txt");
    println!("cargo:rerun-if-changed={}", gated_path.display());
    let allow = ungate::parse_allowlist(
        &std::fs::read_to_string(&allowlist_path).expect("read read_allowlist.txt"),
    );
    let gated = ungate::parse_allowlist(
        &std::fs::read_to_string(&gated_path).expect("read gated_gets.txt"),
    );
    let surface = out_dir.join("proxmox_surface.rs");
    let out = ungate::classify_gets(
        &std::fs::read_to_string(&surface).expect("read proxmox surface"),
        &allow,
        &gated,
    );
    let spec: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(specs_dir.join("proxmox.openapi.json")).expect("read spec"),
    )
    .expect("parse spec");
    let no_tool = spec["paths"]
        .as_object()
        .expect("spec paths")
        .iter()
        .filter(|(_, ops)| ops["get"]["x-orca-no-tool"] == true)
        .map(|(path, _)| path.clone())
        .collect();
    for warning in ungate::check_unused(&out.unused, &gated, &no_tool) {
        println!("cargo:warning={warning}");
    }
    assert_eq!(
        out.rewritten, out.gets,
        "every surfaced GET must be classified"
    );
    std::fs::write(
        out_dir.join("proxmox_surface_source.rs"),
        format!("{:?}", out.source),
    )
    .expect("write proxmox surface source");
    std::fs::write(&surface, out.source).expect("write proxmox surface");
}
