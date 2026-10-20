use std::collections::{BTreeMap, BTreeSet};

use plugin_toolkit::serde_json::{self, Value};

const ALLOWLIST: &str = include_str!("../specs/read_allowlist.txt");
const GATED: &str = include_str!("../specs/gated_gets.txt");
const SURFACED_GETS: usize = 324;

const NO_TOOL_GETS: &[&str] = &[
    "/nodes/{node}/qemu/{vmid}/agent/exec-status",
    "/nodes/{node}/storage/{storage}/file-restore/download",
];

const GATED_GETS: usize = 30;

const CREDENTIAL_GETS: &[&str] = &[
    "/cluster/acme/plugins",
    "/cluster/acme/plugins/{id}",
    "/cluster/notifications/endpoints/smtp",
    "/cluster/notifications/endpoints/smtp/{name}",
    "/cluster/notifications/endpoints/gotify",
    "/cluster/notifications/endpoints/gotify/{name}",
    "/cluster/notifications/endpoints/webhook",
    "/cluster/notifications/endpoints/webhook/{name}",
    "/cluster/metrics/server",
    "/nodes/{node}/subscription",
    "/cluster/config/join",
    "/nodes/{node}/apt/changelog",
    "/nodes/{node}/query-url-metadata",
    "/nodes/{node}/query-oci-repo-tags",
    "/nodes/{node}/qemu/{vmid}/agent/file-read",
    "/nodes/{node}/storage/{storage}/file-restore/download",
];

const DENIED: &[&str] = &[
    "/nodes/{node}/qemu/{vmid}/agent/file-read",
    "/nodes/{node}/qemu/{vmid}/agent/exec-status",
    "/nodes/{node}/storage/{storage}/file-restore/download",
    "/nodes/{node}/storage/{storage}/file-restore/list",
    "/nodes/{node}/query-url-metadata",
    "/nodes/{node}/query-oci-repo-tags",
    "/nodes/{node}/scan",
    "/nodes/{node}/scan/cifs",
    "/nodes/{node}/scan/nfs",
    "/nodes/{node}/scan/iscsi",
    "/nodes/{node}/scan/lvm",
    "/nodes/{node}/scan/lvmthin",
    "/nodes/{node}/scan/zfs",
    "/cluster/acme/plugins",
    "/cluster/acme/plugins/{id}",
    "/cluster/acme/account/{name}",
    "/nodes/{node}/qemu/{vmid}/cloudinit",
    "/nodes/{node}/qemu/{vmid}/config",
    "/nodes/{node}/lxc/{vmid}/config",
    "/nodes/{node}/qemu/{vmid}/pending",
    "/nodes/{node}/lxc/{vmid}/pending",
    "/nodes/{node}/vzdump/extractconfig",
    "/cluster/config/join",
    "/nodes/{node}/qemu/{vmid}/vncwebsocket",
    "/nodes/{node}/lxc/{vmid}/vncwebsocket",
    "/nodes/{node}/vncwebsocket",
    "/nodes/{node}/qemu/{vmid}/mtunnelwebsocket",
    "/nodes/{node}/lxc/{vmid}/mtunnelwebsocket",
    "/nodes/{node}/report",
    "/nodes/{node}/journal",
    "/nodes/{node}/tasks/{upid}/log",
    "/nodes/{node}/replication/{id}/log",
    "/nodes/{node}/ceph/cfg/raw",
    "/nodes/{node}/ceph/cfg/db",
    "/nodes/{node}/ceph/log",
    "/nodes/{node}/hosts",
    "/nodes/{node}/firewall/log",
    "/nodes/{node}/qemu/{vmid}/firewall/log",
    "/nodes/{node}/lxc/{vmid}/firewall/log",
    "/cluster/notifications/endpoints/smtp/{name}",
    "/cluster/notifications/endpoints/gotify/{name}",
    "/cluster/notifications/endpoints/webhook/{name}",
    "/cluster/metrics/server",
    "/nodes/{node}/qemu/{vmid}/snapshot",
    "/nodes/{node}/lxc/{vmid}/snapshot",
    "/nodes/{node}/storage/{storage}/content",
];

fn parse_list(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

fn surface() -> Value {
    serde_json::from_slice(proxmox::API_SURFACE).expect("api surface is JSON")
}

fn ops() -> Vec<Value> {
    surface()["ops"].as_array().expect("ops").clone()
}

fn surfaced_gets() -> BTreeMap<String, Value> {
    ops()
        .into_iter()
        .filter(|op| op["method"] == "GET" && op["internal"] != true)
        .map(|op| (op["path"].as_str().unwrap().to_string(), op))
        .collect()
}

fn role_of(op: &Value) -> &str {
    op["policy"]["role"].as_str().expect("role set")
}

fn gated(op: &Value) -> bool {
    op["policy"]["execute_gated"] == true
}

#[test]
fn surface_binds_pve_auth_envelope_and_root() {
    let s = surface();
    assert_eq!(s["format"], "orca.api-surface/v1");
    assert_eq!(s["surface"], "proxmox");
    assert_eq!(s["base"]["api_root"], "/api2/json");
    assert_eq!(s["auth"]["header"], "Authorization");
    assert_eq!(
        s["auth"]["template"],
        "PVEAPIToken={endpoint.token_id}={secret}"
    );
    assert_eq!(s["auth"]["secret"], "proxmox.{endpoint}.token_secret");
    assert_eq!(s["response"]["envelope"], "/data");
    assert_eq!(s["response"]["lenient_bool"], true);
    assert_eq!(s["response"]["lenient_number"], true);
    assert_eq!(s["endpoint"]["table"], "endpoints");
    assert_eq!(s["endpoint"]["key"], "name");
}

#[test]
fn every_op_is_a_proxmox_tool_with_a_unique_name() {
    let mut seen = BTreeSet::new();
    for op in ops() {
        let name = op["tool"].as_str().unwrap().to_string();
        assert!(name.starts_with("proxmox."), "{name}");
        assert!(seen.insert(name.clone()), "duplicate {name}");
    }
}

#[test]
fn no_hand_written_tool_shadows_a_surface_op() {
    let manifest = plugin_toolkit::dispatch::tool_manifest_json();
    let tools: Vec<Value> = serde_json::from_str(&manifest).expect("manifest");
    let names: BTreeSet<String> = ops()
        .iter()
        .map(|op| op["tool"].as_str().unwrap().to_string())
        .collect();
    for t in tools {
        let name = t["name"].as_str().unwrap();
        assert!(
            !names.contains(name),
            "{name} is both a tool and a surface op"
        );
    }
}

#[test]
fn only_action_gets_need_execute_and_no_get_is_a_mutation() {
    let gets = surfaced_gets();
    assert_eq!(gets.len(), SURFACED_GETS);
    let gated_list = parse_list(GATED);
    for (path, op) in &gets {
        assert_eq!(gated(op), gated_list.contains(path), "{path}");
        assert_eq!(op["policy"]["data_mutation"], false, "{path}");
    }
}

#[test]
fn action_gets_are_pinned_admin_and_gated() {
    let gated_list = parse_list(GATED);
    assert_eq!(gated_list.len(), GATED_GETS);
    for path in CREDENTIAL_GETS {
        assert!(gated_list.contains(*path), "{path} not in gated_gets.txt");
    }
    let gets = surfaced_gets();
    for path in &gated_list {
        if NO_TOOL_GETS.contains(&path.as_str()) {
            assert!(!gets.contains_key(path), "{path} is surfaced");
            continue;
        }
        let op = &gets[path];
        assert_eq!(role_of(op), "admin", "{path}");
        assert!(gated(op), "{path}");
    }
}

#[test]
fn only_allowlisted_gets_are_read_role() {
    let allow = parse_list(ALLOWLIST);
    for (path, op) in surfaced_gets() {
        let want = if allow.contains(&path) {
            "read"
        } else {
            "admin"
        };
        assert_eq!(role_of(&op), want, "{path}");
    }
}

#[test]
fn sensitive_gets_are_pinned_admin() {
    let allow = parse_list(ALLOWLIST);
    let gets = surfaced_gets();
    for path in DENIED {
        assert!(!allow.contains(*path), "{path} is allowlisted");
        if NO_TOOL_GETS.contains(path) {
            assert!(!gets.contains_key(*path), "{path} is surfaced");
            continue;
        }
        let op = gets
            .get(*path)
            .unwrap_or_else(|| panic!("{path} not surfaced"));
        assert_eq!(role_of(op), "admin", "{path}");
    }
    for (path, op) in &gets {
        if path.starts_with("/access") {
            assert_eq!(role_of(op), "admin", "{path}");
        }
    }
}

#[test]
fn inventory_and_status_gets_are_read_role() {
    let gets = surfaced_gets();
    for path in [
        "/version",
        "/cluster/resources",
        "/cluster/status",
        "/nodes/{node}/lxc",
        "/nodes/{node}/qemu/{vmid}/status/current",
        "/nodes/{node}/storage/{storage}/status",
    ] {
        assert_eq!(role_of(&gets[path]), "read", "{path}");
    }
}

#[test]
fn writes_are_admin_execute_gated_and_not_data_mutations() {
    for op in ops().iter().filter(|op| op["method"] != "GET") {
        let name = op["tool"].as_str().unwrap();
        assert!(gated(op), "{name}");
        assert_eq!(role_of(op), "admin", "{name}");
        assert_eq!(op["policy"]["data_mutation"], false, "{name}");
    }
}

#[test]
fn allowlist_ignores_comments_and_blanks() {
    assert_eq!(
        parse_list("# c\n\n /version \n"),
        BTreeSet::from(["/version".to_string()])
    );
}
