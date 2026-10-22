//! QEMU guest-agent backend for the `guest_exec` capability (VM path).
//!
//! Implements the orca-side [`GuestExec`] trait over the QEMU guest agent's
//! `agent/exec` + `agent/exec-status` + `agent/file-write` endpoints. This is the
//! **VM path only** — a running QEMU VM with the guest agent enabled (`agent: 1`)
//! and `qemu-guest-agent` installed + running inside it (see
//! [`crate::diagnostics`] for the readiness diagnosis/repair). The LXC path
//! (node-local `pct exec`) is a separate provider in a later slice.
//!
//! ## Async exec, run as a blocking call
//!
//! The guest agent's `exec` is asynchronous: the POST returns a `pid`, and the
//! caller must poll `exec-status` until `exited` before the output + exit code are
//! available. [`GuestExec::exec`] hides that: it starts the process, then polls on
//! the request's [`ExecRequest::poll_interval_ms`] cadence until the process exits
//! or the [`ExecRequest::timeout_ms`] deadline elapses, capping each captured
//! stream at [`ExecRequest::max_output_bytes`]. The loop *policy* (interval /
//! deadline / cap) is core-owned data carried on the request; this backend only
//! runs the mechanical loop.
//!
//! ## Secret safety
//!
//! `command` argv lands in the guest `/proc`, the guest-agent logs, and the PVE
//! task log — never a secret there. Sensitive input rides
//! [`ExecRequest::input_data`] (the agent's `input-data`, i.e. stdin) or a
//! [`GuestExec::write_file`] to a mode-restricted path. The orca-side types redact
//! those payloads from `Debug`; this backend never logs them.

use plugin_toolkit::contract::BoxFuture;
use plugin_toolkit::contract::guest_exec::{
    ExecOutput, ExecRequest, GuestExec, GuestRef, WriteFileRequest,
};

use anyhow::{Context, Result, anyhow, bail};
use plugin_toolkit::api;
use plugin_toolkit::serde_json::json;
use serde::Deserialize;
use std::time::{Duration, Instant};

/// Registry name this backend registers under (the `guest_exec` provider key).
const PROVIDER: &str = "proxmox";

const EXEC_OP: &str = "proxmox.post_exec_nodes_node_qemu_vmid_agent_exec";
const EXEC_STATUS_OP: &str = "proxmox.get_exec_status_nodes_node_qemu_vmid_agent_exec_status";
const FILE_WRITE_OP: &str = "proxmox.post_file_write_nodes_node_qemu_vmid_agent_file_write";

pub const REACHES: [&str; 3] = [EXEC_OP, EXEC_STATUS_OP, FILE_WRITE_OP];

const INPUT_DATA_MAX: usize = 65536;
const FILE_CONTENT_MAX: usize = 61440;

#[derive(Deserialize)]
struct ExecStarted {
    pid: i64,
}

#[derive(Deserialize)]
struct ExecStatus {
    exited: bool,
    exitcode: Option<i64>,
    signal: Option<i64>,
    #[serde(rename = "out-data")]
    out_data: Option<String>,
    #[serde(rename = "err-data")]
    err_data: Option<String>,
    #[serde(rename = "out-truncated")]
    out_truncated: Option<bool>,
    #[serde(rename = "err-truncated")]
    err_truncated: Option<bool>,
}

/// Typed `guest_exec` facet for the `Plugin` builder. The builder drives it over
/// the wire via `contract::guest_exec::dispatch_op`.
pub struct ProxmoxGuestExec;

impl GuestExec for ProxmoxGuestExec {
    fn name(&self) -> &str {
        PROVIDER
    }

    fn exec(&self, guest: GuestRef, req: ExecRequest) -> BoxFuture<'_, Result<ExecOutput>> {
        Box::pin(async move { exec(guest, req).await })
    }

    fn write_file(&self, guest: GuestRef, req: WriteFileRequest) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { write_file(guest, req).await })
    }
}

fn resolve_guest(guest: &GuestRef) -> Result<(String, String, i64)> {
    let scope = guest.scope.as_deref().ok_or_else(|| {
        anyhow!("guest_exec: `scope` (PVE endpoint) is required for the proxmox backend")
    })?;
    let node = guest
        .node
        .as_deref()
        .ok_or_else(|| {
            anyhow!("guest_exec: `node` (PVE node) is required for the proxmox backend")
        })?
        .to_string();
    let vmid: i64 = guest
        .id
        .parse()
        .with_context(|| format!("guest_exec: guest id '{}' is not a valid vmid", guest.id))?;
    Ok((scope.to_string(), node, vmid))
}

/// Start `req.command` in the guest, then poll `exec-status` to completion.
async fn exec(guest: GuestRef, req: ExecRequest) -> Result<ExecOutput> {
    let (endpoint, node, vmid) = resolve_guest(&guest)?;

    let input_data = match req.input_data.as_ref() {
        Some(bytes) => {
            let s = String::from_utf8(bytes.clone()).map_err(|_| {
                anyhow!("guest_exec: input_data must be valid UTF-8 for the guest agent")
            })?;
            if s.chars().count() > INPUT_DATA_MAX {
                bail!(
                    "guest_exec: input_data rejected by guest agent: longer than {INPUT_DATA_MAX} characters"
                );
            }
            Some(s)
        }
        None => None,
    };

    let pid = start_exec(&endpoint, &node, vmid, &req.command, input_data)
        .with_context(|| format!("guest agent exec (vmid {vmid} on '{node}')"))?;

    let deadline = Instant::now() + Duration::from_millis(req.timeout_ms());
    let interval = Duration::from_millis(req.poll_interval_ms());
    let cap = req.max_output_bytes() as usize;

    loop {
        let status = exec_status(&endpoint, &node, vmid, pid)
            .with_context(|| format!("guest agent exec-status (pid {pid}, vmid {vmid})"))?;

        if status.exited {
            let (stdout, out_cap_trunc) = cap_str(status.out_data.unwrap_or_default(), cap);
            let (stderr, err_cap_trunc) = cap_str(status.err_data.unwrap_or_default(), cap);
            return Ok(ExecOutput {
                exit_code: status.exitcode,
                signal: status.signal,
                stdout,
                stderr,
                timed_out: false,
                stdout_truncated: status.out_truncated.unwrap_or(false) || out_cap_trunc,
                stderr_truncated: status.err_truncated.unwrap_or(false) || err_cap_trunc,
            });
        }

        if Instant::now() >= deadline {
            // Deadline elapsed before the process exited: return what the agent has
            // captured so far. The process keeps running in the guest — orca does
            // not have a guest-agent kill primitive here (a later slice can add
            // one); the deadline is a *read* budget, not a hard kill.
            let (stdout, out_cap_trunc) = cap_str(status.out_data.unwrap_or_default(), cap);
            let (stderr, err_cap_trunc) = cap_str(status.err_data.unwrap_or_default(), cap);
            return Ok(ExecOutput {
                exit_code: None,
                signal: None,
                stdout,
                stderr,
                timed_out: true,
                stdout_truncated: status.out_truncated.unwrap_or(false) || out_cap_trunc,
                stderr_truncated: status.err_truncated.unwrap_or(false) || err_cap_trunc,
            });
        }

        plugin_toolkit::time::sleep(interval).await;
    }
}

fn start_exec(
    endpoint: &str,
    node: &str,
    vmid: i64,
    command: &[String],
    input_data: Option<String>,
) -> Result<i64> {
    let started: ExecStarted = api::call(
        EXEC_OP,
        endpoint,
        crate::args(json!({
            "node": node,
            "vmid": vmid,
            "body": { "command": command, "input-data": input_data },
        })),
    )?;
    Ok(started.pid)
}

fn exec_status(endpoint: &str, node: &str, vmid: i64, pid: i64) -> Result<ExecStatus> {
    api::call(
        EXEC_STATUS_OP,
        endpoint,
        json!({ "node": node, "vmid": vmid, "pid": pid }),
    )
}

/// Truncate `s` to at most `cap` bytes on a UTF-8 char boundary, reporting whether
/// anything was dropped.
fn cap_str(s: String, cap: usize) -> (String, bool) {
    if s.len() <= cap {
        return (s, false);
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

async fn write_file(guest: GuestRef, req: WriteFileRequest) -> Result<()> {
    let (endpoint, node, vmid) = resolve_guest(&guest)?;

    let content = String::from_utf8(req.contents.clone()).map_err(|_| {
        anyhow!("guest_exec: write_file contents must be valid UTF-8 (binary/base64 writes are a later slice)")
    })?;
    if content.chars().count() > FILE_CONTENT_MAX {
        bail!("guest_exec: file contents rejected by guest agent (cap {FILE_CONTENT_MAX} chars)");
    }

    api::call::<plugin_toolkit::serde_json::Value>(
        FILE_WRITE_OP,
        &endpoint,
        json!({
            "node": node,
            "vmid": vmid,
            "body": { "content": content, "file": req.path },
        }),
    )
    .with_context(|| {
        format!(
            "guest agent file-write '{}' (vmid {vmid} on '{node}')",
            req.path
        )
    })?;

    // mode/owner are not native to file-write — apply them with chained exec. The
    // path is not a secret; the mode/owner values are not secrets.
    if let Some(mode) = req.mode.as_deref() {
        run_ok(
            &endpoint,
            &node,
            vmid,
            vec!["chmod".to_string(), mode.to_string(), req.path.clone()],
        )
        .await
        .with_context(|| format!("guest_exec: chmod {mode} '{}'", req.path))?;
    }
    if let Some(owner) = req.owner.as_deref() {
        run_ok(
            &endpoint,
            &node,
            vmid,
            vec!["chown".to_string(), owner.to_string(), req.path.clone()],
        )
        .await
        .with_context(|| format!("guest_exec: chown {owner} '{}'", req.path))?;
    }
    Ok(())
}

/// Run a short command in the guest and require a zero exit code — the chained
/// `chmod`/`chown` helper. Uses the module's default loop policy.
async fn run_ok(endpoint: &str, node: &str, vmid: i64, command: Vec<String>) -> Result<()> {
    let pid = start_exec(endpoint, node, vmid, &command, None)
        .with_context(|| format!("guest agent exec {command:?}"))?;

    let deadline = Instant::now()
        + Duration::from_millis(plugin_toolkit::contract::guest_exec::DEFAULT_TIMEOUT_MS);
    let interval =
        Duration::from_millis(plugin_toolkit::contract::guest_exec::DEFAULT_POLL_INTERVAL_MS);
    loop {
        let status = exec_status(endpoint, node, vmid, pid)
            .with_context(|| format!("guest agent exec-status (pid {pid})"))?;
        if status.exited {
            if status.exitcode == Some(0) {
                return Ok(());
            }
            bail!(
                "command {command:?} exited with code {:?}: {}",
                status.exitcode,
                status.err_data.unwrap_or_default()
            );
        }
        if Instant::now() >= deadline {
            bail!("command {command:?} did not exit within the deadline");
        }
        plugin_toolkit::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_str_truncates_on_char_boundary() {
        let (s, trunc) = cap_str("héllo".to_string(), 2);
        // 'h' is 1 byte, 'é' is 2 bytes; cap=2 splits mid-'é' → backs off to 1.
        assert_eq!(s, "h");
        assert!(trunc);

        let (s, trunc) = cap_str("hello".to_string(), 100);
        assert_eq!(s, "hello");
        assert!(!trunc);
    }

    #[test]
    fn exec_sends_command_and_stdin_in_the_body_and_pid_in_the_query() {
        let (pid, calls) = crate::test_support::record_api_calls(
            |method, _| match method {
                "POST" => r#"{"pid":7}"#.to_string(),
                _ => r#"{"exited":true,"exitcode":0}"#.to_string(),
            },
            || {
                let pid = start_exec("pve", "n1", 101, &["ls".to_string()], Some("x".into()))?;
                exec_status("pve", "n1", 101, pid).map(|_| pid)
            },
        );
        assert_eq!(pid.unwrap(), 7);
        assert_eq!(
            calls,
            vec![
                (
                    "POST".to_string(),
                    "/nodes/n1/qemu/101/agent/exec".to_string(),
                    json!({ "body": { "command": ["ls"], "input-data": "x" } })
                ),
                (
                    "GET".to_string(),
                    "/nodes/n1/qemu/101/agent/exec-status".to_string(),
                    json!({ "pid": 7 })
                ),
            ]
        );
    }

    #[test]
    fn exec_without_stdin_omits_input_data() {
        let (_, calls) = crate::test_support::record_api_calls(
            |_, _| r#"{"pid":1}"#.to_string(),
            || start_exec("pve", "n1", 101, &["true".to_string()], None),
        );
        assert_eq!(calls[0].2, json!({ "body": { "command": ["true"] } }));
    }

    #[test]
    fn provider_name_is_stable() {
        assert_eq!(ProxmoxGuestExec.name(), "proxmox");
    }
}
