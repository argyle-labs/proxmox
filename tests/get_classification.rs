use std::collections::{BTreeMap, BTreeSet};

#[path = "../build/ungate.rs"]
mod ungate;

const ALLOWLIST: &str = include_str!("../specs/read_allowlist.txt");
const GATED: &str = include_str!("../specs/gated_gets.txt");
const SURFACED_GETS: usize = 230;

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

fn surfaced_gets() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut lines = proxmox::SURFACE_SOURCE.lines();
    while let Some(line) = lines.next() {
        if let Some(path) = line
            .strip_prefix("/// Auto-generated from `GET ")
            .and_then(|r| r.strip_suffix("`."))
        {
            let attr = lines.next().expect("attribute after doc line");
            out.insert(path.to_string(), attr.to_string());
        }
    }
    out
}

fn role_of(attr: &str) -> &str {
    let rest = attr.split("role = \"").nth(1).expect("role set");
    &rest[..rest.find('"').unwrap()]
}

#[test]
fn only_action_gets_need_execute_and_no_get_is_a_mutation() {
    let gets = surfaced_gets();
    assert_eq!(gets.len(), SURFACED_GETS);
    let gated = ungate::parse_allowlist(GATED);
    for (path, attr) in &gets {
        let want = format!("execute_gated = {}", gated.contains(path));
        assert!(attr.contains(&want), "{path}: {attr}");
        assert!(attr.contains("data_mutation = false"), "{path}: {attr}");
    }
}

#[test]
fn action_gets_are_pinned_admin_and_gated() {
    let gated = ungate::parse_allowlist(GATED);
    assert_eq!(gated.len(), GATED_GETS);
    for path in CREDENTIAL_GETS {
        assert!(gated.contains(*path), "{path} not in gated_gets.txt");
    }
    let gets = surfaced_gets();
    for path in &gated {
        let attr = &gets[path];
        assert_eq!(role_of(attr), "admin", "{path}");
        assert!(attr.contains("execute_gated = true"), "{path}: {attr}");
    }
}

#[test]
fn only_allowlisted_gets_are_read_role() {
    let allow = ungate::parse_allowlist(ALLOWLIST);
    for (path, attr) in surfaced_gets() {
        let want = if allow.contains(&path) {
            "read"
        } else {
            "admin"
        };
        assert_eq!(role_of(&attr), want, "{path}");
    }
}

#[test]
fn sensitive_gets_are_pinned_admin() {
    let allow = ungate::parse_allowlist(ALLOWLIST);
    let gets = surfaced_gets();
    for path in DENIED {
        assert!(!allow.contains(*path), "{path} is allowlisted");
        let attr = gets
            .get(*path)
            .unwrap_or_else(|| panic!("{path} not surfaced"));
        assert_eq!(role_of(attr), "admin", "{path}");
    }
    for (path, attr) in &gets {
        if path.starts_with("/access") {
            assert_eq!(role_of(attr), "admin", "{path}");
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

fn allow(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

#[test]
fn rewrite_classifies_through_interleaved_attributes() {
    let src = "/// Auto-generated from `GET /a`.\n\
               #[allow(dead_code)]\n\
               #[orca_tool(cli = \"skip\", verb = \"a\", domain = \"proxmox\")]\n\
               /// Auto-generated from `GET /b`.\n\
               #[orca_tool(domain = \"proxmox\", verb = \"b\", cli = \"skip\")]\n";
    let out = ungate::classify_gets(src, &allow(&["/a"]), &BTreeSet::new());
    assert!(out.unused.is_empty());
    assert_eq!((out.gets, out.rewritten), (2, 2));
    let lines: Vec<&str> = out.source.lines().collect();
    assert_eq!(
        lines[2],
        "#[orca_tool(cli = \"skip\", verb = \"a\", domain = \"proxmox\", role = \"read\", \
         execute_gated = false, data_mutation = false)]"
    );
    assert!(lines[4].ends_with("role = \"admin\", execute_gated = false, data_mutation = false)]"));
}

#[test]
fn rewrite_drops_a_get_doc_line_not_followed_by_an_attribute() {
    let src = "/// Auto-generated from `GET /a`.\n\
               fn stray() {}\n\
               #[orca_tool(domain = \"proxmox\", verb = \"x\", cli = \"skip\")]\n\
               /// Auto-generated from `PUT /b`.\n\
               #[orca_tool(domain = \"proxmox\", verb = \"b\", cli = \"skip\", role = \"admin\")]\n";
    let out = ungate::classify_gets(src, &allow(&["/a"]), &BTreeSet::new());
    assert_eq!(out.source, src);
    assert_eq!((out.gets, out.rewritten), (1, 0));
    assert_eq!(out.unused, allow(&["/a"]));
}

#[test]
#[should_panic(expected = "already sets role")]
fn rewrite_refuses_a_get_that_already_sets_a_role() {
    ungate::classify_gets(
        "/// Auto-generated from `GET /a`.\n#[orca_tool(verb = \"a\", role = \"any\")]\n",
        &BTreeSet::new(),
        &BTreeSet::new(),
    );
}

#[test]
fn rewrite_gates_listed_action_gets_and_reports_unmatched_entries() {
    let src = "/// Auto-generated from `GET /scan`.\n#[orca_tool(verb = \"s\")]\n";
    let out = ungate::classify_gets(src, &BTreeSet::new(), &allow(&["/scan", "/gone"]));
    assert!(
        out.source
            .contains("role = \"admin\", execute_gated = true")
    );
    assert_eq!(out.unused, allow(&["/gone"]));
}

#[test]
#[should_panic(expected = "both read-allowlisted and gated")]
fn rewrite_refuses_a_path_both_allowed_and_gated() {
    ungate::classify_gets("", &allow(&["/a"]), &allow(&["/a"]));
}

fn tool_for(path: &str) -> String {
    let attr = &surfaced_gets()[path];
    let rest = attr.split("verb = \"").nth(1).unwrap();
    format!("proxmox.{}", &rest[..rest.find('"').unwrap()])
}

#[allow(unused_imports)]
use proxmox as _;

fn read_principal_may_call(path: &str) -> bool {
    use plugin_toolkit::dispatch::tool_roles::authorize;
    let name = tool_for(path);
    let role = plugin_toolkit::dispatch::required_role(&name).expect("registered");
    let mutation = plugin_toolkit::dispatch::data_mutation_names().contains(&name.as_str());
    authorize("read", false, role, mutation) || authorize("read", true, role, mutation)
}

#[test]
fn read_principal_is_refused_admin_gets_and_allowed_allowlisted_ones() {
    for path in [
        "/nodes/{node}/lxc/{vmid}/config",
        "/access/users",
        "/nodes/{node}/scan/nfs",
    ] {
        assert!(!read_principal_may_call(path), "{path}");
    }
    for path in ["/cluster/resources", "/nodes/{node}/lxc"] {
        assert!(read_principal_may_call(path), "{path}");
    }
}

#[test]
fn allowlist_ignores_comments_and_blanks() {
    assert_eq!(
        ungate::parse_allowlist("# c\n\n /version \n"),
        allow(&["/version"])
    );
}
