pub mod access;
mod api_path;
pub mod backup;
pub mod backup_jobs;
pub mod bind_mounts;
pub mod cluster;
pub mod cluster_roster_impl;
pub mod deploy;
pub mod diagnostics;
pub mod disk_grow;
pub mod execute;
pub mod guest_exec;
pub mod guest_file;
pub mod guest_mount;
pub mod guest_standard;
pub mod host_workloads;
pub mod lxc_guest;
pub mod memory;
pub mod mount_scan;
pub mod node_state;
pub mod overallocation;
pub mod responses;
pub mod shm_trap;
pub mod stale_snapshots;
pub mod thin_discard;
pub mod thin_pool;
pub mod tools;
pub mod topology;
pub mod unit_provider;

pub const API_SURFACE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/proxmox.api-surface.json"));

use plugin_toolkit::reqwest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub endpoint: String,
    pub base_url: String,
    pub token_id: String,
    pub token_secret: String,
    pub insecure: bool,
}

impl Config {
    pub fn new(
        base_url: impl Into<String>,
        token_id: impl Into<String>,
        token_secret: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: String::new(),
            base_url: base_url.into(),
            token_id: token_id.into(),
            token_secret: token_secret.into(),
            insecure: false,
        }
    }

    pub fn insecure(mut self, on: bool) -> Self {
        self.insecure = on;
        self
    }

    pub fn endpoint(mut self, name: impl Into<String>) -> Self {
        self.endpoint = name.into();
        self
    }

    fn auth_header_value(&self) -> String {
        format!("PVEAPIToken={}={}", self.token_id, self.token_secret)
    }

    pub fn build_reqwest_client(&self) -> Result<reqwest::Client, ProxmoxError> {
        plugin_toolkit::api_client::ApiClientBuilder::new()
            .header("authorization", self.auth_header_value())
            .and_then(|b| b.insecure(self.insecure).build())
            .map_err(|e| ProxmoxError::Malformed(format!("reqwest build: {e}")))
    }
}

#[derive(Debug, Error)]
pub enum ProxmoxError {
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("unsupported action '{0}' (expected start | stop | shutdown | reboot)")]
    BadAction(String),
    #[error("unsupported guest kind '{0}' (expected qemu | lxc)")]
    BadGuestKind(String),
    #[error("malformed proxmox response: {0}")]
    Malformed(String),
    #[error("proxmox transport: {0}")]
    Transport(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ProxmoxAction {
    Start,
    Stop,
    Shutdown,
    Reboot,
}

impl ProxmoxAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxmoxAction::Start => "start",
            ProxmoxAction::Stop => "stop",
            ProxmoxAction::Shutdown => "shutdown",
            ProxmoxAction::Reboot => "reboot",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestKind {
    Qemu,
    Lxc,
}

impl GuestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GuestKind::Qemu => "qemu",
            GuestKind::Lxc => "lxc",
        }
    }
}

impl std::str::FromStr for GuestKind {
    type Err = ProxmoxError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "qemu" | "vm" => Ok(GuestKind::Qemu),
            "lxc" | "container" => Ok(GuestKind::Lxc),
            other => Err(ProxmoxError::BadGuestKind(other.to_string())),
        }
    }
}

impl std::str::FromStr for ProxmoxAction {
    type Err = ProxmoxError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "start" => Ok(ProxmoxAction::Start),
            "stop" => Ok(ProxmoxAction::Stop),
            "shutdown" => Ok(ProxmoxAction::Shutdown),
            "reboot" => Ok(ProxmoxAction::Reboot),
            other => Err(ProxmoxError::BadAction(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxmoxActionResult {
    pub node: String,
    pub vmid: u64,
    pub action: String,
    pub upid: Option<String>,
    pub status: u16,
}

pub async fn fetch_guest_config(
    http: &reqwest::Client,
    base_url: &str,
    node: &str,
    kind: GuestKind,
    vmid: u64,
) -> Result<responses::GuestConfigResponse, ProxmoxError> {
    if node.is_empty() {
        return Err(ProxmoxError::Missing("node"));
    }
    let url = format!(
        "{}/nodes/{}/{}/{}/config",
        base_url.trim_end_matches('/'),
        backup::enc(node),
        kind.as_str(),
        vmid
    );
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| ProxmoxError::Transport(e.to_string()))?;
    let body = resp
        .text()
        .await
        .map_err(|e| ProxmoxError::Transport(e.to_string()))?;
    serde_json::from_str::<responses::GuestConfigResponse>(&body)
        .map_err(|e| ProxmoxError::Malformed(format!("guest_config: typed parse: {e}")))
}

pub fn run_lifecycle(
    endpoint: &str,
    node: &str,
    kind: GuestKind,
    vmid: u64,
    action: ProxmoxAction,
) -> anyhow::Result<String> {
    plugin_toolkit::api::call(
        &lifecycle_op(kind, action),
        endpoint,
        serde_json::json!({ "node": node, "vmid": vmid }),
    )
    .map_err(|e| e.context(format!("{} {} {vmid}", kind.as_str(), action.as_str())))
}

pub fn lifecycle_op(kind: GuestKind, action: ProxmoxAction) -> String {
    let (k, a) = (kind.as_str(), action.as_str());
    format!("proxmox.post_vm_{a}_nodes_node_{k}_vmid_status_{a}")
}

pub fn destroy_op(kind: GuestKind) -> String {
    format!(
        "proxmox.delete_destroy_vm_nodes_node_{}_vmid",
        kind.as_str()
    )
}

pub fn args(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, args(v)))
                .collect(),
        ),
        other => other,
    }
}

pub fn fetch_journal(
    endpoint: &str,
    node: &str,
    q: responses::JournalQuery,
) -> Result<responses::JournalResponse, ProxmoxError> {
    if node.is_empty() {
        return Err(ProxmoxError::Missing("node"));
    }
    let lines = plugin_toolkit::api::call::<Vec<String>>(
        "proxmox.get_journal_nodes_node_journal",
        endpoint,
        args(serde_json::json!({
            "node": node,
            "lastentries": q.lastentries,
            "since": q.since,
            "until": q.until,
        })),
    )
    .map_err(|e| ProxmoxError::Transport(format!("journal: {e}")))?;
    Ok(responses::JournalResponse { data: lines })
}

#[cfg(test)]
pub(crate) mod test_support {
    use serde_json::Value;

    pub fn api_call_route(raw: &str) -> (String, String, Value) {
        let call: Value = serde_json::from_str(raw).unwrap();
        let surface: Value = serde_json::from_slice(crate::API_SURFACE).unwrap();
        let op = surface["ops"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tool"] == call["op"])
            .unwrap_or_else(|| panic!("unknown api op {}", call["op"]));
        let mut path = op["path"].as_str().unwrap().to_string();
        let mut rest = serde_json::Map::new();
        if let Some(args) = call["args"].as_object() {
            for (k, v) in args {
                let placeholder = format!("{{{k}}}");
                if path.contains(&placeholder) {
                    let v = v.as_str().map_or_else(|| v.to_string(), str::to_string);
                    path = path.replace(&placeholder, &v);
                } else {
                    rest.insert(k.clone(), v.clone());
                }
            }
        }
        (
            op["method"].as_str().unwrap().to_ascii_uppercase(),
            path,
            Value::Object(rest),
        )
    }

    pub fn record_api_calls<T>(
        reply: impl Fn(&str, &str) -> String + 'static,
        f: impl FnOnce() -> T,
    ) -> (T, Vec<(String, String, Value)>) {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let out = plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, raw: &str| {
                assert_eq!(cap, "api.call");
                let (method, path, rest) = api_call_route(raw);
                let body = reply(&method, &path);
                log.lock().unwrap().push((method, path, rest));
                Ok(body)
            }),
            f,
        );
        let calls = seen.lock().unwrap().clone();
        (out, calls)
    }

    pub fn api_call_reply(http_reply: &str) -> Result<String, String> {
        let r: Value = serde_json::from_str(http_reply).unwrap();
        let status = r["status"].as_u64().unwrap();
        let bytes: Vec<u8> = serde_json::from_value(r["body"].clone()).unwrap();
        if !(200..300).contains(&status) {
            return Err(format!("upstream HTTP {status}"));
        }
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        Ok(body["data"].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_reaches_name_real_surface_ops() {
        let surface: serde_json::Value = serde_json::from_slice(API_SURFACE).unwrap();
        let ops: Vec<&str> = surface["ops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["tool"].as_str().unwrap())
            .collect();
        let declared = unit_provider::reaches()
            .into_iter()
            .chain(guest_exec::REACHES.map(String::from))
            .chain(diagnostics::REACHES.map(String::from))
            .chain(backup::backend_defs().into_iter().flat_map(|d| d.reaches))
            .chain(tool_reaches(include_str!("backup_jobs.rs")))
            .chain(tool_reaches(include_str!("thin_discard.rs")))
            .chain(deploy::reaches(GuestKind::Qemu))
            .chain(deploy::reaches(GuestKind::Lxc))
            .chain(tool_reaches(include_str!("tools.rs")))
            .chain(tool_reaches(include_str!("access.rs")))
            .chain(lifecycle_permutations())
            .chain(KINDS.map(destroy_op));
        for op in declared {
            assert!(ops.contains(&op.as_str()), "{op} is not an api-surface op");
        }
    }

    const KINDS: [GuestKind; 2] = [GuestKind::Qemu, GuestKind::Lxc];

    fn lifecycle_permutations() -> Vec<String> {
        use ProxmoxAction::*;
        KINDS
            .iter()
            .flat_map(|&k| [Start, Stop, Shutdown, Reboot].map(|a| lifecycle_op(k, a)))
            .collect()
    }

    fn tool_reaches(src: &str) -> Vec<String> {
        src.split("reaches = [")
            .skip(1)
            .flat_map(|rest| {
                rest[..rest.find(']').unwrap()]
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| s.starts_with("proxmox."))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn declared_lifecycle_and_destroy_lists_cover_every_permutation() {
        let mut lifecycle = lifecycle_permutations();
        lifecycle.sort();
        let mut declared: Vec<String> = unit_provider::LIFECYCLE_OPS.map(String::from).to_vec();
        declared.sort();
        assert_eq!(declared, lifecycle);
        let mut action = tool_reaches(include_str!("tools.rs"));
        action.retain(|op| op.contains("_status_"));
        action.sort();
        assert_eq!(action, lifecycle);
        let mut destroy = KINDS.map(destroy_op).to_vec();
        destroy.sort();
        let mut declared = unit_provider::DESTROY_OPS.map(String::from).to_vec();
        declared.sort();
        assert_eq!(declared, destroy);
        assert!(!tool_reaches(include_str!("access.rs")).is_empty());
    }

    #[test]
    fn lifecycle_posts_to_the_guest_status_path_without_a_body() {
        let (upid, calls) = test_support::record_api_calls(
            |_, _| "\"UPID:n1:1\"".to_string(),
            || run_lifecycle("pve", "n1", GuestKind::Lxc, 116, ProxmoxAction::Stop),
        );
        assert_eq!(upid.unwrap(), "UPID:n1:1");
        assert_eq!(
            calls,
            vec![(
                "POST".to_string(),
                "/nodes/n1/lxc/116/status/stop".to_string(),
                serde_json::json!({})
            )]
        );
    }

    #[test]
    fn guest_kind_parses() {
        assert!(matches!(
            "qemu".parse::<GuestKind>().unwrap(),
            GuestKind::Qemu
        ));
        assert!(matches!(
            "vm".parse::<GuestKind>().unwrap(),
            GuestKind::Qemu
        ));
        assert!(matches!(
            "lxc".parse::<GuestKind>().unwrap(),
            GuestKind::Lxc
        ));
        assert!("foo".parse::<GuestKind>().is_err());
    }

    #[test]
    fn action_parses_known_strings() {
        assert!(matches!(
            "start".parse::<ProxmoxAction>().unwrap(),
            ProxmoxAction::Start
        ));
        assert!(matches!(
            "shutdown".parse::<ProxmoxAction>().unwrap(),
            ProxmoxAction::Shutdown
        ));
        assert!("foo".parse::<ProxmoxAction>().is_err());
    }

    #[test]
    fn reqwest_client_attaches_pve_auth_header() {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let cap = captured.clone();
        let reply = serde_json::json!({
            "status": 200,
            "headers": [],
            "body": Vec::<u8>::from(b"ok".as_slice()),
        })
        .to_string();

        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |c: &str, json: &str| {
                assert_eq!(c, "http.request");
                cap.lock().unwrap().push(json.to_string());
                Ok(reply.clone())
            }),
            || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let cfg = Config::new(
                        "https://pve.test",
                        "user@pve!auto",
                        "deadbeef-1111-2222-3333-444444444444",
                    );
                    let http = cfg.build_reqwest_client().unwrap();
                    let r = http.get("https://pve.test/probe").send().await.unwrap();
                    assert_eq!(r.status().as_u16(), 200);
                });
            },
        );

        let requests = captured.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].contains("PVEAPIToken=user@pve!auto=deadbeef-1111-2222-3333-444444444444"),
            "captured request missing PVE auth header: {}",
            requests[0]
        );
    }
}
