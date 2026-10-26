use std::path::{Component, Path};

use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::backup::config_op;
use crate::guest_label::guests;

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuestConfigArgs {
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub vmid: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GuestConfig {
    pub endpoint: String,
    pub node: String,
    pub kind: String,
    pub vmid: u64,
    pub allowlisted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lxc_isolation: Option<Value>,
    pub config: Value,
}

const SENSITIVE_HOST_PATHS: &[&str] = &[
    "/run",
    "/var/run",
    "/",
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/boot",
    "/dev",
    "/var/lib/docker",
    "/var/lib/containers",
    "/var/lib/lxc",
    "/home",
    "/usr",
];

fn normalize_path(path: &str) -> Option<String> {
    let mut rooted = false;
    let mut parts: Vec<&str> = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir => rooted = true,
            Component::Normal(part) => parts.push(part.to_str()?),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::CurDir | Component::Prefix(_) => {}
        }
    }
    let joined = parts.join("/");
    Some(if rooted { format!("/{joined}") } else { joined })
}

fn host_path_class(path: &str) -> &'static str {
    let sensitive = normalize_path(path).is_none_or(|p| {
        SENSITIVE_HOST_PATHS
            .iter()
            .any(|s| p == *s || (*s != "/" && p.starts_with(&format!("{s}/"))))
    });
    if sensitive { "sensitive" } else { "ordinary" }
}

fn basename(path: &str) -> &str {
    let p = path.trim_end_matches('/');
    p.rsplit('/')
        .next()
        .filter(|b| !b.is_empty())
        .unwrap_or("/")
}

fn raw_lxc(config: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(entries) = config.get("lxc").and_then(Value::as_array) {
        for e in entries {
            if let Some([k, v]) = e.as_array().map(Vec::as_slice)
                && let (Some(k), Some(v)) = (k.as_str(), v.as_str())
            {
                out.push((k.to_string(), v.to_string()));
            }
        }
    }
    if let Some(map) = config.as_object() {
        for (k, v) in map.iter().filter(|(k, _)| k.starts_with("lxc.")) {
            if let Some(v) = v.as_str() {
                out.push((k.clone(), v.to_string()));
            }
        }
    }
    out
}

fn feature_value<'a>(config: &'a Value, name: &str) -> Option<&'a str> {
    config
        .get("features")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim())
}

fn feature_on(config: &Value, name: &str) -> bool {
    feature_value(config, name) == Some("1")
}

fn raw_values(raw: &[(String, String)], key: &str) -> Vec<String> {
    raw.iter()
        .filter(|(k, _)| k == key)
        .flat_map(|(_, v)| v.split_whitespace().map(str::to_string))
        .collect()
}

fn is_unprivileged(config: &Value) -> bool {
    match config.get("unprivileged") {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_u64() == Some(1),
        Some(Value::String(s)) => s.trim() == "1",
        _ => false,
    }
}

pub fn lxc_isolation(config: &Value) -> Value {
    let raw = raw_lxc(config);
    let unprivileged = is_unprivileged(config);
    let seccomp = raw
        .iter()
        .rev()
        .find(|(k, _)| k == "lxc.seccomp.profile")
        .map(|(_, v)| v.trim().to_string());
    let devices: Vec<Value> = raw
        .iter()
        .filter_map(|(k, v)| {
            let action = match k.as_str() {
                "lxc.cgroup.devices.allow" | "lxc.cgroup2.devices.allow" => "allow",
                "lxc.cgroup.devices.deny" | "lxc.cgroup2.devices.deny" => "deny",
                _ => return None,
            };
            Some(json!({ "action": action, "rule": v.trim() }))
        })
        .collect();
    let apparmor = raw
        .iter()
        .rev()
        .find(|(k, _)| k == "lxc.apparmor.profile")
        .map(|(_, v)| v.trim().to_string());
    let raw_mounts: Vec<Value> = raw
        .iter()
        .filter(|(k, _)| k == "lxc.mount.entry")
        .map(|(_, v)| {
            let source = v.split_whitespace().next().unwrap_or_default();
            json!({ "name": basename(source), "class": host_path_class(source) })
        })
        .collect();
    let mut mount_points = Vec::new();
    if let Some(map) = config.as_object() {
        for (key, value) in map.iter().filter(|(k, _)| indexed(k, "mp")) {
            let Some(spec) = value.as_str() else { continue };
            let source = spec.split(',').next().unwrap_or_default();
            let target = options(spec)
                .find(|(k, _)| *k == "mp")
                .map(|(_, v)| v)
                .unwrap_or_default();
            let bind = source.starts_with('/');
            mount_points.push(json!({
                "key": key,
                "target": target,
                "bind": bind,
                "readOnly": options(spec).any(|(k, v)| k == "ro" && v == "1"),
                "class": bind.then(|| host_path_class(source)),
                "name": bind.then(|| basename(source)),
            }));
        }
    }
    json!({
        "unprivileged": unprivileged,
        "privileged": !unprivileged,
        "capDrop": raw_values(&raw, "lxc.cap.drop"),
        "capKeep": raw_values(&raw, "lxc.cap.keep"),
        "seccompProfile": seccomp,
        "mountAuto": raw_values(&raw, "lxc.mount.auto"),
        "idmapCount": raw.iter().filter(|(k, _)| k == "lxc.idmap").count(),
        "devices": devices,
        "apparmorProfile": apparmor,
        "rawMountCount": raw_mounts.len(),
        "rawMounts": raw_mounts,
        "mountPoints": mount_points,
        "keyctl": feature_on(config, "keyctl"),
        "nesting": feature_on(config, "nesting"),
        "fuse": feature_on(config, "fuse"),
        "mount": feature_value(config, "mount")
            .map(|v| v.split(';').filter(|m| !m.is_empty()).collect::<Vec<_>>())
            .unwrap_or_default(),
    })
}

const PLAIN_KEYS: &[&str] = &[
    "cores",
    "memory",
    "sockets",
    "ostype",
    "onboot",
    "unprivileged",
    "features",
    "hostname",
    "name",
];

const DISK_PREFIXES: &[&str] = &[
    "rootfs", "mp", "scsi", "virtio", "sata", "ide", "efidisk", "tpmstate",
];

const NET_OPTIONS: &[&str] = &[
    "name",
    "bridge",
    "hwaddr",
    "macaddr",
    "ip",
    "ip6",
    "gw",
    "gw6",
    "firewall",
    "tag",
    "trunks",
    "type",
    "mtu",
    "rate",
    "link_down",
    "queues",
    "host-managed",
];

fn indexed(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix)
        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

fn options(spec: &str) -> impl Iterator<Item = (&str, &str)> {
    spec.split(',').filter_map(|kv| kv.split_once('='))
}

fn net(spec: &str) -> Value {
    let model = options(spec)
        .find(|(k, _)| *k == "model" || *k == "type")
        .map(|(_, v)| v)
        .or_else(|| {
            options(spec)
                .map(|(k, _)| k)
                .find(|k| !NET_OPTIONS.contains(k))
        });
    let bridge = options(spec).find(|(k, _)| *k == "bridge").map(|(_, v)| v);
    json!({ "model": model, "bridge": bridge })
}

fn disk(spec: &str) -> Option<Value> {
    options(spec)
        .find(|(k, _)| *k == "size")
        .map(|(_, size)| json!({ "size": size }))
}

pub fn allowlisted(config: &Value) -> Value {
    let Some(map) = config.as_object() else {
        return json!({});
    };
    let mut out = plugin_toolkit::serde_json::Map::new();
    for (key, value) in map {
        let kept = if PLAIN_KEYS.contains(&key.as_str()) {
            Some(value.clone())
        } else if indexed(key, "net") {
            value.as_str().map(net)
        } else if key == "rootfs" || DISK_PREFIXES.iter().any(|p| indexed(key, p)) {
            value.as_str().and_then(disk)
        } else {
            None
        };
        if let Some(v) = kept {
            out.insert(key.clone(), v);
        }
    }
    Value::Object(out)
}

pub fn guest_config(endpoint: &str, vmid: u64, raw: bool) -> Result<GuestConfig> {
    let (node, kind, ..) = guests(endpoint, None)?
        .into_iter()
        .find(|(_, _, id, _)| *id == vmid)
        .ok_or_else(|| anyhow!("guest {vmid} not found on {endpoint}"))?;
    let config: Value = plugin_toolkit::api::call(
        config_op(kind, "get"),
        endpoint,
        json!({ "node": node, "vmid": vmid }),
    )
    .map_err(|e| e.context(format!("{} {vmid} config", kind.as_str())))?;
    Ok(GuestConfig {
        endpoint: endpoint.to_string(),
        node,
        kind: kind.as_str().to_string(),
        vmid,
        allowlisted: !raw,
        lxc_isolation: (kind.as_str() == "lxc").then(|| lxc_isolation(&config)),
        config: if raw { config } else { allowlisted(&config) },
    })
}

pub fn guest_config_raw(
    endpoint: &str,
    vmid: u64,
    caller: Option<&CallerIdentity>,
) -> Result<GuestConfig> {
    crate::execute::require_admin("proxmox.guest.config_raw", caller)?;
    guest_config(endpoint, vmid, true)
}

/// Read a VM or LXC's PVE config by vmid; the node is resolved from cluster
/// resources. Returns only `cores`, `memory`, `sockets`, `ostype`, `onboot`,
/// `unprivileged`, `features`, `hostname`/`name`, each `net*` as its model and
/// bridge (no MAC) and each disk as its size, for every caller; the raw config
/// is `proxmox.guest.config_raw`. An LXC also gets `lxcIsolation`: its device
/// allow/deny rules in order, AppArmor profile, raw mount entries and mount
/// points (host paths reduced to a basename and a `sensitive`/`ordinary`
/// class), and whether `keyctl`, `nesting` and `fuse` are on plus the allowed `mount`
/// filesystems.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.config",
    execute_gated = false,
    role = "read",
    tool_callable = true,
    reaches = [
        "proxmox.get_resources_cluster_resources",
        "proxmox.get_vm_config_nodes_node_qemu_vmid_config",
        "proxmox.get_vm_config_nodes_node_lxc_vmid_config"
    ]
)]
async fn proxmox_guest_config(args: GuestConfigArgs, _ctx: &ToolCtx) -> Result<GuestConfig> {
    guest_config(&args.endpoint, args.vmid, false)
}

/// Read a VM or LXC's raw PVE config (cloud-init passwords, ssh keys, hook
/// scripts and all) by vmid. Admin only, and not callable through `tool.call`.
#[orca_tool(
    domain = "proxmox",
    verb = "guest.config_raw",
    execute_gated = false,
    role = "admin",
    reaches = [
        "proxmox.get_resources_cluster_resources",
        "proxmox.get_vm_config_nodes_node_qemu_vmid_config",
        "proxmox.get_vm_config_nodes_node_lxc_vmid_config"
    ]
)]
async fn proxmox_guest_config_raw(args: GuestConfigArgs, ctx: &ToolCtx) -> Result<GuestConfig> {
    guest_config_raw(&args.endpoint, args.vmid, ctx.caller().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::record_api_calls;

    fn routes(method: &str, path: &str) -> String {
        match (method, path) {
            (_, "/cluster/resources") => r#"[
                {"type":"lxc","node":"thor","vmid":112,"name":"sonarr"},
                {"type":"qemu","node":"odin","vmid":200,"name":"win"}
            ]"#
            .into(),
            ("GET", "/nodes/thor/lxc/112/config") => r#"{
                "hostname":"sonarr","unprivileged":1,"features":"nesting=1","cores":2,
                "memory":2048,"ostype":"debian","onboot":1,
                "description":"root pw is hunter2",
                "hookscript":"local:snippets/hook.sh",
                "lxc.apparmor.profile":"unconfined",
                "lxc.mount.entry":"/secret mnt none bind",
                "lxc":[["lxc.cgroup2.devices.allow","a"],["lxc.mount.entry","/dev/dri dev/dri none bind,optional 0 0"],["lxc.environment","TOKEN=hunter2"]],
                "net0":"name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=dhcp,type=veth",
                "rootfs":"local-lvm:vm-112-disk-0,size=8G",
                "mp0":"/mnt/media,mp=/media"
            }"#
            .into(),
            ("GET", "/nodes/odin/qemu/200/config") => r#"{
                "name":"win","cores":4,"sockets":1,
                "cipassword":"hunter2","sshkeys":"ssh-ed25519%20AAAA",
                "cicustom":"user=local:snippets/u.yml",
                "args":"-cpu host,kvm=off","smbios1":"uuid=1234,serial=abc",
                "net0":"virtio=BC:24:11:DD:EE:FF,bridge=vmbr1,firewall=1",
                "scsi0":"local-lvm:vm-200-disk-0,size=64G",
                "ide2":"none,media=cdrom"
            }"#
            .into(),
            _ => "null".into(),
        }
    }

    const SECRETS: &[&str] = &[
        "hunter2",
        "hook.sh",
        "unconfined",
        "/secret",
        "AAAA",
        "snippets/u.yml",
        "kvm=off",
        "serial=abc",
        "BC:24:11",
        "/mnt/media",
    ];

    #[test]
    fn lxc_config_is_read_from_the_resolved_node() {
        let (out, calls) = record_api_calls(routes, || guest_config("pve", 112, false));
        let out = out.unwrap();
        assert_eq!((out.node.as_str(), out.kind.as_str()), ("thor", "lxc"));
        assert!(out.allowlisted);
        assert_eq!(
            out.config,
            json!({
                "hostname": "sonarr",
                "unprivileged": 1,
                "features": "nesting=1",
                "cores": 2,
                "memory": 2048,
                "ostype": "debian",
                "onboot": 1,
                "net0": { "model": "veth", "bridge": "vmbr0" },
                "rootfs": { "size": "8G" }
            })
        );
        assert!(calls.iter().all(|c| c.0 == "GET"));
    }

    #[test]
    fn vm_config_uses_the_qemu_path() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 200, false));
        let out = out.unwrap();
        assert_eq!((out.node.as_str(), out.kind.as_str()), ("odin", "qemu"));
        assert_eq!(
            out.config,
            json!({
                "name": "win",
                "cores": 4,
                "sockets": 1,
                "net0": { "model": "virtio", "bridge": "vmbr1" },
                "scsi0": { "size": "64G" }
            })
        );
    }

    #[test]
    fn the_allowlisted_config_never_carries_secrets() {
        for vmid in [112, 200] {
            let (out, _) = record_api_calls(routes, || guest_config("pve", vmid, false));
            let text = out.unwrap().config.to_string();
            for secret in SECRETS {
                assert!(!text.contains(secret), "{vmid}: {secret} in {text}");
            }
            for key in [
                "cipassword",
                "description",
                "args",
                "hookscript",
                "cicustom",
                "sshkeys",
                "smbios1",
                "lxc",
                "mp0",
                "ide2",
            ] {
                assert!(
                    !text.contains(&format!("\"{key}")),
                    "{vmid}: {key} in {text}"
                );
            }
        }
    }

    #[test]
    fn an_lxc_gets_a_non_secret_isolation_summary() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 112, false));
        let out = out.unwrap();
        let iso = out.lxc_isolation.expect("lxc summary");
        assert_eq!(
            iso,
            json!({
                "unprivileged": true,
                "privileged": false,
                "capDrop": [],
                "capKeep": [],
                "seccompProfile": null,
                "mountAuto": [],
                "idmapCount": 0,
                "devices": [{ "action": "allow", "rule": "a" }],
                "apparmorProfile": "unconfined",
                "rawMountCount": 2,
                "rawMounts": [
                    { "name": "dri", "class": "sensitive" },
                    { "name": "secret", "class": "ordinary" }
                ],
                "mountPoints": [{
                    "key": "mp0", "target": "/media", "bind": true,
                    "readOnly": false, "class": "ordinary", "name": "media"
                }],
                "keyctl": false,
                "nesting": true,
                "fuse": false,
                "mount": []
            })
        );
        let text = iso.to_string();
        for leak in ["hunter2", "TOKEN", "/dev/dri", "/mnt/media"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
    }

    #[test]
    fn isolation_serializes_camel_case_keys() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 112, false));
        let v = plugin_toolkit::serde_json::to_value(out.unwrap()).unwrap();
        assert_eq!(v["lxcIsolation"]["apparmorProfile"], "unconfined");
        assert!(v["lxcIsolation"].get("apparmor_profile").is_none());
    }

    #[test]
    fn an_lxc_without_the_unprivileged_key_is_privileged() {
        let iso = lxc_isolation(&json!({ "hostname": "x" }));
        assert_eq!(iso["unprivileged"], false);
        assert_eq!(iso["privileged"], true);
        for value in [json!(1), json!("1"), json!(true)] {
            let iso = lxc_isolation(&json!({ "unprivileged": value }));
            assert_eq!(iso["unprivileged"], true);
            assert_eq!(iso["privileged"], false);
        }
        assert_eq!(
            lxc_isolation(&json!({ "unprivileged": 0 }))["privileged"],
            true
        );
    }

    #[test]
    fn isolation_reads_caps_seccomp_mount_auto_and_idmap() {
        let iso = lxc_isolation(&json!({
            "lxc": [
                ["lxc.cap.drop", "sys_module mknod"],
                ["lxc.cap.drop", "audit_write"],
                ["lxc.cap.keep", "net_admin"],
                ["lxc.seccomp.profile", "/usr/share/lxc/config/common.seccomp"],
                ["lxc.mount.auto", "proc:rw sys:rw"],
                ["lxc.idmap", "u 0 100000 65536"],
                ["lxc.idmap", "g 0 100000 65536"]
            ]
        }));
        assert_eq!(
            iso["capDrop"],
            json!(["sys_module", "mknod", "audit_write"])
        );
        assert_eq!(iso["capKeep"], json!(["net_admin"]));
        assert_eq!(
            iso["seccompProfile"],
            "/usr/share/lxc/config/common.seccomp"
        );
        assert_eq!(iso["mountAuto"], json!(["proc:rw", "sys:rw"]));
        assert_eq!(iso["idmapCount"], 2);
    }

    #[test]
    fn bare_indexed_keys_are_ignored() {
        assert!(!indexed("net", "net"));
        assert!(!indexed("mp", "mp"));
        assert!(!indexed("rootfs", "rootfs"));
        assert!(indexed("net0", "net"));
        let out = allowlisted(&json!({
            "net": "name=eth0,bridge=vmbr0,type=veth",
            "mp": "size=1G",
            "net0": "name=eth0,bridge=vmbr0,type=veth",
            "rootfs": "local-lvm:vm-1-disk-0,size=8G"
        }));
        assert_eq!(
            out,
            json!({
                "net0": { "model": "veth", "bridge": "vmbr0" },
                "rootfs": { "size": "8G" }
            })
        );
    }

    #[test]
    fn a_host_managed_net_without_a_type_has_no_model() {
        let out = allowlisted(&json!({
            "net0": "name=eth0,bridge=vmbr0,host-managed=1,ip=dhcp"
        }));
        assert_eq!(out["net0"], json!({ "model": null, "bridge": "vmbr0" }));
    }

    #[test]
    fn a_vm_has_no_lxc_summary() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 200, false));
        let out = out.unwrap();
        assert!(out.lxc_isolation.is_none());
        let v = plugin_toolkit::serde_json::to_value(out).unwrap();
        assert!(v.get("lxcIsolation").is_none());
    }

    #[test]
    fn host_paths_are_classified_and_reduced() {
        assert_eq!(host_path_class("/etc/ssh"), "sensitive");
        assert_eq!(host_path_class("/var/lib/docker/"), "sensitive");
        assert_eq!(host_path_class("/mnt/media"), "ordinary");
        assert_eq!(basename("/mnt/media/"), "media");
        assert_eq!(basename("/"), "/");
    }

    #[test]
    fn traversal_shapes_cannot_hide_a_sensitive_path() {
        for path in [
            "/mnt/../etc/shadow",
            "//etc/x",
            "/etc/./pve",
            "/mnt/../../etc",
            "../etc",
            "/var/lib/lxc/101",
            "/home/user",
            "/usr/bin",
        ] {
            assert_eq!(host_path_class(path), "sensitive", "{path}");
        }
        assert_eq!(host_path_class("/mnt/./media//x/../y"), "ordinary");
    }

    #[test]
    fn read_only_and_writable_binds_are_distinguishable() {
        let iso = lxc_isolation(&json!({
            "mp0": "/var/run,mp=/host-run",
            "mp1": "/var/run,mp=/host-run-ro,ro=1"
        }));
        assert_eq!(iso["mountPoints"][0]["readOnly"], false);
        assert_eq!(iso["mountPoints"][1]["readOnly"], true);
        assert_eq!(iso["mountPoints"][0]["class"], "sensitive");
    }

    #[test]
    fn fuse_and_mount_features_are_reported() {
        let iso = lxc_isolation(&json!({ "features": "fuse=1,mount=nfs;cifs,nesting=1" }));
        assert_eq!(iso["fuse"], true);
        assert_eq!(iso["mount"], json!(["nfs", "cifs"]));
        assert_eq!(iso["nesting"], true);
    }

    #[test]
    fn raw_config_is_returned_only_when_asked() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 200, true));
        let out = out.unwrap();
        assert!(!out.allowlisted);
        assert_eq!(out.config["cipassword"], "hunter2");
        assert_eq!(
            out.config["net0"],
            "virtio=BC:24:11:DD:EE:FF,bridge=vmbr1,firewall=1"
        );
    }

    #[test]
    fn the_non_raw_tool_is_allowlisted_for_every_caller() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 200, false));
        assert!(out.unwrap().allowlisted);
    }

    #[test]
    fn args_are_camel_case() {
        let args: GuestConfigArgs =
            plugin_toolkit::serde_json::from_value(json!({ "endpoint": "pve", "vmid": 112 }))
                .unwrap();
        assert_eq!((args.endpoint.as_str(), args.vmid), ("pve", 112));
        let out = record_api_calls(routes, || guest_config("pve", 112, false))
            .0
            .unwrap();
        let v = plugin_toolkit::serde_json::to_value(out).unwrap();
        assert_eq!(v["allowlisted"], true);
    }

    #[test]
    fn unknown_vmid_is_an_error() {
        let (out, _) = record_api_calls(routes, || guest_config("pve", 999, false));
        assert!(out.unwrap_err().to_string().contains("guest 999 not found"));
    }

    fn caller(role: &str) -> CallerIdentity {
        CallerIdentity {
            user_id: "u".into(),
            username: "op".into(),
            role: role.into(),
            can_mutate: role == "admin",
        }
    }

    fn config_body(body: &'static str) -> impl Fn(&str, &str) -> String + 'static {
        move |method, path| {
            if path.ends_with("/config") {
                body.into()
            } else {
                routes(method, path)
            }
        }
    }

    #[test]
    fn config_raw_refuses_a_non_admin_and_a_missing_caller() {
        for (who, want) in [
            (None, "no caller identity"),
            (Some(caller("read")), "requires role 'admin'"),
        ] {
            let (out, calls) =
                record_api_calls(routes, || guest_config_raw("pve", 200, who.as_ref()));
            let err = out.unwrap_err().to_string();
            assert!(err.contains(want), "{err}");
            assert!(!err.contains("hunter2"), "{err}");
            assert!(calls.is_empty());
        }
    }

    #[test]
    fn config_raw_returns_the_unfiltered_config_for_an_admin() {
        let admin = caller("admin");
        let (out, _) = record_api_calls(routes, || guest_config_raw("pve", 200, Some(&admin)));
        let out = out.unwrap();
        assert!(!out.allowlisted);
        assert_eq!(out.config["cipassword"], "hunter2");
    }

    #[test]
    fn a_config_api_error_is_a_clean_error() {
        let out = plugin_toolkit::capsink::with_cap_sink(
            Box::new(|_: &str, raw: &str| {
                let (method, path, _) = crate::test_support::api_call_route(raw);
                if path.ends_with("/config") {
                    Err("upstream HTTP 500".to_string())
                } else {
                    Ok(routes(&method, &path))
                }
            }),
            || guest_config("pve", 112, false),
        );
        let err = format!("{:#}", out.unwrap_err());
        assert!(err.contains("lxc 112 config"), "{err}");
        assert!(err.contains("upstream HTTP 500"), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
    }

    #[test]
    fn a_null_config_is_empty_and_an_lxc_is_privileged() {
        let (out, _) = record_api_calls(config_body("null"), || guest_config("pve", 112, false));
        let out = out.unwrap();
        assert_eq!(out.config, json!({}));
        let iso = out.lxc_isolation.expect("lxc summary");
        assert_eq!(iso["privileged"], true);
        assert_eq!(iso["unprivileged"], false);
        assert_eq!(iso["mountPoints"], json!([]));
    }

    #[test]
    fn a_non_object_config_yields_an_empty_allowlist() {
        for body in ["[1,2]", "\"hunter2\"", "42", "true"] {
            let (out, _) = record_api_calls(config_body(body), || guest_config("pve", 112, false));
            let out = out.unwrap();
            assert_eq!(out.config, json!({}), "{body}");
            assert!(!out.config.to_string().contains("hunter2"));
            assert_eq!(out.lxc_isolation.unwrap()["privileged"], true, "{body}");
        }
    }

    #[test]
    fn non_string_net_and_disk_values_are_dropped() {
        let cfg = json!({
            "net0": 5,
            "net1": { "bridge": "hunter2" },
            "net2": ["hunter2"],
            "rootfs": 7,
            "mp0": 9,
            "scsi0": null
        });
        assert_eq!(allowlisted(&cfg), json!({}));
        let iso = lxc_isolation(&cfg);
        assert_eq!(iso["mountPoints"], json!([]));
        assert!(!iso.to_string().contains("hunter2"));
    }

    #[test]
    fn a_malformed_net_string_never_echoes_its_value() {
        let out = allowlisted(&json!({ "net0": "hunter2" }));
        assert_eq!(out["net0"], json!({ "model": null, "bridge": null }));
        assert!(!out.to_string().contains("hunter2"));
    }

    #[test]
    fn only_the_allowlisted_tool_is_tool_callable() {
        let manifest: Vec<Value> =
            plugin_toolkit::serde_json::from_str(&plugin_toolkit::dispatch::tool_manifest_json())
                .unwrap();
        let find = |name: &str| {
            manifest
                .iter()
                .find(|t| t["name"] == name)
                .unwrap_or_else(|| panic!("{name} not registered"))
        };
        assert_eq!(find("proxmox.guest.config")["tool_callable"], true);
        assert_eq!(find("proxmox.guest.config")["role"], "read");
        assert_eq!(find("proxmox.guest.config_raw")["tool_callable"], false);
        assert_eq!(find("proxmox.guest.config_raw")["role"], "admin");
    }
}
