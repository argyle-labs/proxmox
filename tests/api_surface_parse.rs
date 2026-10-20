use openapi::surface::ApiSurface;

#[test]
fn embedded_table_parses_with_declared_auth_columns() {
    let text = std::str::from_utf8(proxmox::API_SURFACE).expect("utf-8 table");
    let surface = ApiSurface::parse(text).expect("api surface parses");
    assert!(surface.endpoint.columns.iter().any(|c| c == "token_id"));
}
