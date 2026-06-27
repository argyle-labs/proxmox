//! Typed responses for every `proxmox::Client` method.
//!
//! Single source of truth for the upstream Proxmox API envelope shape.
//! `topology.rs`, `containers_adapter.rs`, and `tools.rs` reach into this
//! module instead of redefining envelopes locally or doing the
//! round-trip-through-a-JSON-string hack.
//!
//! Every response wraps Proxmox's `{ "data": ... }` envelope. Missing
//! scalars default via `#[serde(default)]` so a thin reply doesn't
//! fail-shut the whole tick — the reconciler treats absent fields as
//! "no signal," not "crash."
//!
//! These types derive `JsonSchema` because the `tools.rs` surface
//! returns them directly to CLI/REST/MCP; the schema is what populates
//! the OpenAPI spec + clap parsers + MCP tool definitions.

use plugin_toolkit::prelude::{JsonSchema, Serialize};
use serde::Deserialize;
use std::collections::BTreeMap;

// ── /nodes ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct NodeListResponse {
    #[serde(default)]
    pub data: Vec<NodeEntry>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct NodeEntry {
    pub node: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub uptime: Option<u64>,
    #[serde(default)]
    pub cpu: Option<f64>,
    #[serde(default)]
    pub mem: Option<u64>,
    #[serde(default)]
    pub maxmem: Option<u64>,
    #[serde(default)]
    pub level: Option<String>,
}

// ── /nodes/{node}/status ────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct NodeStatusResponse {
    #[serde(default)]
    pub data: NodeStatus,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct NodeStatus {
    #[serde(default)]
    pub uptime: u64,
    #[serde(default)]
    pub cpu: f64,
    #[serde(default)]
    pub loadavg: Vec<String>,
    #[serde(default)]
    pub memory: MemInfo,
    #[serde(default)]
    pub rootfs: DiskInfo,
    #[serde(default)]
    pub swap: MemInfo,
    #[serde(default)]
    pub pveversion: Option<String>,
    #[serde(default)]
    pub kversion: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct MemInfo {
    #[serde(default)]
    pub used: u64,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub free: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct DiskInfo {
    #[serde(default)]
    pub used: u64,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub avail: u64,
}

// ── /cluster/resources?type=vm ──────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ClusterResourcesResponse {
    #[serde(default)]
    pub data: Vec<ClusterResourceEntry>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ClusterResourceEntry {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub vmid: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub uptime: Option<u64>,
    #[serde(default)]
    pub cpu: Option<f64>,
    #[serde(default)]
    pub mem: Option<u64>,
    #[serde(default)]
    pub maxmem: Option<u64>,
    #[serde(default)]
    pub tags: Option<String>,
}

impl ClusterResourcesResponse {
    /// Iterator over `qemu` + `lxc` rows with non-empty node + non-zero vmid.
    pub fn guests(&self) -> impl Iterator<Item = &ClusterResourceEntry> {
        self.data
            .iter()
            .filter(|e| (e.kind == "qemu" || e.kind == "lxc") && !e.node.is_empty() && e.vmid != 0)
    }

    pub fn vms(&self) -> impl Iterator<Item = &ClusterResourceEntry> {
        self.guests().filter(|e| e.kind == "qemu")
    }

    pub fn lxcs(&self) -> impl Iterator<Item = &ClusterResourceEntry> {
        self.guests().filter(|e| e.kind == "lxc")
    }
}

// ── /nodes/{node}/qemu | /nodes/{node}/lxc ──────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct GuestListResponse {
    #[serde(default)]
    pub data: Vec<GuestListEntry>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct GuestListEntry {
    #[serde(default)]
    pub vmid: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub uptime: Option<u64>,
    #[serde(default)]
    pub cpu: Option<f64>,
    #[serde(default)]
    pub mem: Option<u64>,
    #[serde(default)]
    pub maxmem: Option<u64>,
    #[serde(default)]
    pub tags: Option<String>,
}

// ── /nodes/{node}/{kind}/{vmid}/status/current ──────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct GuestStatusResponse {
    #[serde(default)]
    pub data: GuestStatus,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct GuestStatus {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub vmid: u64,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub uptime: Option<u64>,
    #[serde(default)]
    pub cpu: Option<f64>,
    #[serde(default)]
    pub cpus: Option<u32>,
    #[serde(default)]
    pub mem: Option<u64>,
    #[serde(default)]
    pub maxmem: Option<u64>,
    #[serde(default)]
    pub tags: Option<String>,
    #[serde(default)]
    pub lock: Option<String>,
}

// ── /nodes/{node}/{kind}/{vmid}/config ──────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct GuestConfigResponse {
    #[serde(default)]
    pub data: GuestConfigData,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct GuestConfigData {
    #[serde(flatten, default)]
    pub fields: BTreeMap<String, ConfigField>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum ConfigField {
    /// Numeric scalar (`onboot: 1`, `memory: 4096`, …).
    Num(i64),
    /// Floating-point scalar — Proxmox occasionally returns these.
    Float(f64),
    /// String form of every other shape (`netN`, `mp0`, `hostname`, …).
    Str(String),
}

impl GuestConfigData {
    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.fields.get(key)? {
            ConfigField::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn get_int(&self, key: &str) -> Option<i64> {
        match self.fields.get(key)? {
            ConfigField::Num(n) => Some(*n),
            ConfigField::Float(f) => Some(*f as i64),
            ConfigField::Str(s) => s.parse().ok(),
        }
    }

    /// `onboot=1` → restart policy `Always`. Absent / non-numeric → false.
    pub fn onboot(&self) -> bool {
        self.get_int("onboot").unwrap_or(0) != 0
    }

    /// Extract every `netN` MAC into a lowercased vector. Used by both
    /// the topology collector and any code pinning parent-of via NIC MAC.
    pub fn macs(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (k, v) in &self.fields {
            if !k.starts_with("net") {
                continue;
            }
            let ConfigField::Str(s) = v else {
                continue;
            };
            if let Some(mac) = extract_mac(s) {
                out.push(mac);
            }
        }
        out
    }
}

// ── /nodes/{node}/{kind}/{vmid}/snapshot ────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct SnapshotListResponse {
    #[serde(default)]
    pub data: Vec<SnapshotEntry>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct SnapshotEntry {
    pub name: String,
    #[serde(default)]
    pub snaptime: Option<u64>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub vmstate: Option<u8>,
}

// ── /cluster/backup ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct BackupListResponse {
    #[serde(default)]
    pub data: Vec<BackupJob>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct BackupJob {
    pub id: String,
    #[serde(default)]
    pub schedule: String,
    #[serde(default)]
    pub storage: String,
    #[serde(default)]
    pub enabled: u8,
    #[serde(default)]
    pub all: Option<u8>,
    #[serde(default)]
    pub vmid: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

// ── /nodes/{node}/journal ───────────────────────────────────────────────────

/// Optional filters for `Client::journal`. All `None` → default window.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct JournalQuery {
    /// Unix timestamp lower bound.
    #[serde(default)]
    pub since: Option<u64>,
    /// Unix timestamp upper bound.
    #[serde(default)]
    pub until: Option<u64>,
    /// Cap on lines returned from the tail.
    #[serde(default)]
    pub lastentries: Option<u32>,
    /// Narrow to one unit / service name.
    #[serde(default)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct JournalResponse {
    /// Journal lines, oldest first. Proxmox returns
    /// `{ "data": ["line1", "line2", ...] }`.
    #[serde(default)]
    pub data: Vec<String>,
}

// ── /nodes/{node}/lxc/{vmid}/exec ───────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ExecResponse {
    #[serde(default)]
    pub data: ExecResult,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ExecResult {
    #[serde(default, rename = "exit-code")]
    pub exit_code: i32,
    #[serde(default, rename = "out-data")]
    pub stdout: String,
    #[serde(default, rename = "err-data")]
    pub stderr: String,
}

// ── Task UPID (snapshot_create, lxc_exec, lifecycle) ────────────────────────

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct UpidResponse {
    /// Proxmox returns the new task's UPID as a bare string in `data`.
    #[serde(default)]
    pub data: Option<String>,
}

// ── MAC extraction (shared) ────────────────────────────────────────────────

/// Find the first `aa:bb:cc:dd:ee:ff`-shaped MAC anywhere in `line`.
/// Bounded scan — Proxmox `netN` strings are short.
pub fn extract_mac(line: &str) -> Option<String> {
    let lower = line.to_lowercase();
    let bytes = lower.as_bytes();
    if bytes.len() < 17 {
        return None;
    }
    for start in 0..=bytes.len() - 17 {
        let win = &lower[start..start + 17];
        if is_mac(win) {
            if start > 0 && lower.as_bytes()[start - 1].is_ascii_hexdigit() {
                continue;
            }
            return Some(win.to_string());
        }
    }
    None
}

fn is_mac(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        if (i + 1) % 3 == 0 {
            if *b != b':' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // Abstract host names per [[feedback-no-hostnames-or-ips-in-repo]].
    // Fixtures are JSON string literals parsed via `from_str`.

    #[test]
    fn cluster_resources_filters_to_qemu_and_lxc() {
        let raw = r#"{"data":[
            {"type":"qemu","node":"hyp1","vmid":100,"name":"vm-a"},
            {"type":"lxc","node":"hyp1","vmid":110,"name":"ct-b"},
            {"type":"storage","node":"hyp1"},
            {"type":"qemu","node":"","vmid":200,"name":"no-node"},
            {"type":"lxc","node":"hyp1","vmid":0,"name":"zero-vmid"}
        ]}"#;
        let resp: ClusterResourcesResponse = serde_json::from_str(raw).unwrap();
        let guests: Vec<_> = resp.guests().collect();
        assert_eq!(guests.len(), 2);
        assert_eq!(resp.vms().count(), 1);
        assert_eq!(resp.lxcs().count(), 1);
    }

    #[test]
    fn guest_config_extracts_macs_and_onboot() {
        let raw = r#"{"data":{
            "hostname":"x",
            "onboot":1,
            "net0":"name=eth0,bridge=vmbr0,hwaddr=BC:24:11:F8:0F:AC,ip=dhcp",
            "net1":"virtio=AA:BB:CC:DD:EE:02,bridge=vmbr1",
            "memory":4096
        }}"#;
        let resp: GuestConfigResponse = serde_json::from_str(raw).unwrap();
        assert!(resp.data.onboot());
        assert_eq!(
            resp.data.macs(),
            vec!["bc:24:11:f8:0f:ac", "aa:bb:cc:dd:ee:02"]
        );
    }

    #[test]
    fn guest_config_get_str_and_int_work_for_mixed_shapes() {
        let raw = r#"{"data":{
            "hostname":"x",
            "onboot":0,
            "memory":"2048",
            "cores":4
        }}"#;
        let resp: GuestConfigResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.data.get_str("hostname"), Some("x"));
        assert_eq!(resp.data.get_int("memory"), Some(2048));
        assert_eq!(resp.data.get_int("cores"), Some(4));
        assert!(!resp.data.onboot());
    }

    #[test]
    fn journal_lines_round_trip() {
        let raw = r#"{"data": ["line a", "line b", "line c"]}"#;
        let resp: JournalResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.data, vec!["line a", "line b", "line c"]);
    }

    #[test]
    fn extract_mac_finds_embedded_mac() {
        assert_eq!(
            extract_mac("name=eth0,bridge=vmbr0,hwaddr=BC:24:11:F8:0F:AC,ip=dhcp"),
            Some("bc:24:11:f8:0f:ac".to_string())
        );
    }

    #[test]
    fn extract_mac_returns_none_for_no_mac() {
        assert!(extract_mac("memory=4096,cores=4").is_none());
    }
}
