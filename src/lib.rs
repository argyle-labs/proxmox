//! Proxmox VE API client. API-token auth only for the MVP — ticket/cookie
//! flow can be added later when a password-based caller appears.
//!
//! Token format follows Proxmox's documented header:
//!   Authorization: PVEAPIToken=USER@REALM!TOKENID=UUID
//!
//! Typed API ops route through orca core's executor via
//! `plugin_toolkit::api::call`, keyed by the `proxmox.*` ops in the
//! api-surface table. `fetch_guest_config` stays a raw-URL helper because the
//! upstream schema models indexed keys (`netN`, `mpN`) as a single `[n]` field.

pub mod access;
pub mod backup;
pub mod backup_jobs;
pub mod bind_mounts;
pub mod cluster;
pub mod cluster_roster_impl;
pub mod containers_adapter;
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
    /// Registered endpoint name; the key `api::call` resolves routes and auth by.
    pub endpoint: String,
    pub base_url: String,
    /// `user@realm!tokenid` — the part before the `=` in the auth header.
    pub token_id: String,
    /// The UUID secret — the part after the `=`.
    pub token_secret: String,
    /// Skip TLS verification (homelab self-signed certs).
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

    /// Build the underlying `reqwest::Client` with the PVE API-token
    /// header pre-attached and TLS verification toggled per `insecure`.
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

/// Allowed lifecycle actions on VMs and containers. Constraining the set up
/// front keeps callers from forwarding arbitrary strings to the Proxmox API.
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

/// Guest kind — used by snapshot ops that work for both VMs and containers.
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
    /// Proxmox returns a UPID (Unique Process ID) for async tasks.
    pub upid: Option<String>,
    pub status: u16,
}

/// Pull a guest config (qemu or lxc) and parse it into the typed
/// `responses::GuestConfigResponse` shape so callers can walk
/// `netN` + `mpN` keys via the BTreeMap.
///
/// Why this exists outside `api::call`: the upstream OpenAPI schema models
/// indexed config keys as `net[n]` / `mp[n]` placeholders, which don't
/// describe `net0` / `net1` / ... etc. Hitting the raw endpoint
/// preserves the indexed-key shape. The `reqwest::Client` carries the
/// PVE auth header from `Config::build_reqwest_client`.
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

/// Run a lifecycle action against one guest; returns the task UPID.
pub fn run_lifecycle(
    endpoint: &str,
    node: &str,
    kind: GuestKind,
    vmid: u64,
    action: ProxmoxAction,
) -> anyhow::Result<String> {
    let (k, a) = (kind.as_str(), action.as_str());
    plugin_toolkit::api::call(
        &format!("proxmox.post_vm_{a}_nodes_node_{k}_vmid_status_{a}"),
        endpoint,
        serde_json::json!({ "node": node, "vmid": vmid }),
    )
    .map_err(|e| e.context(format!("{k} {a} {vmid}")))
}

/// Drop null object members, recursively: an absent optional is omitted on
/// the wire, and the core executor's schema check rejects explicit nulls.
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

/// Pull the systemd journal for one node and wrap the `Vec<String>` payload
/// into the `responses::JournalResponse` envelope the tool surface returns.
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

    /// The `(method, url-path)` an `api.call` payload resolves to under the
    /// api-surface table, so HTTP-recorded fixtures can answer it.
    pub fn api_call_route(raw: &str) -> (String, String) {
        let call: Value = serde_json::from_str(raw).unwrap();
        let surface: Value = serde_json::from_slice(crate::API_SURFACE).unwrap();
        let op = surface["ops"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tool"] == call["op"])
            .unwrap_or_else(|| panic!("unknown api op {}", call["op"]));
        let mut path = op["path"].as_str().unwrap().to_string();
        if let Some(args) = call["args"].as_object() {
            for (k, v) in args {
                let v = v.as_str().map_or_else(|| v.to_string(), str::to_string);
                path = path.replace(&format!("{{{k}}}"), &v);
            }
        }
        (op["method"].as_str().unwrap().to_ascii_uppercase(), path)
    }

    /// Turn a recorded `http.request` reply into what core's executor hands
    /// back over `api.call`: the peeled `data` on 2xx, an error otherwise.
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
            .chain([diagnostics::ENABLE_AGENT_OP.to_string()]);
        for op in declared {
            assert!(ops.contains(&op.as_str()), "{op} is not an api-surface op");
        }
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
        // The cap-backed client seeds default headers onto every request, so
        // one call is enough to prove the PVE token header is attached. We
        // capture the `http.request` JSON the shim routes through the sink and
        // assert the auth header value is present.
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
