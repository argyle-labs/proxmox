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

use crate::generated::{self, types as gtypes};
use crate::tools::resolve_config;
use anyhow::{Context, Result, anyhow, bail};
use std::time::{Duration, Instant};

/// Registry name this backend registers under (the `guest_exec` provider key).
const PROVIDER: &str = "proxmox";

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

/// Resolve a [`GuestRef`] into the `(client, node, vmid)` the generated
/// guest-agent calls need. proxmox reads `scope` as the PVE endpoint, `node` as
/// the PVE node, and `id` as the vmid.
async fn resolve_guest(guest: &GuestRef) -> Result<(generated::Client, String, i64)> {
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
    let client = resolve_config(scope).await?.build_generated_client()?;
    Ok((client, node, vmid))
}

/// Start `req.command` in the guest, then poll `exec-status` to completion.
async fn exec(guest: GuestRef, req: ExecRequest) -> Result<ExecOutput> {
    let (client, node, vmid) = resolve_guest(&guest).await?;

    // stdin: the sanctioned channel for sensitive input. The agent caps input-data
    // at 65536 chars — the generated newtype's `TryFrom` enforces it.
    let input_data = match req.input_data.as_ref() {
        Some(bytes) => {
            let s = String::from_utf8(bytes.clone()).map_err(|_| {
                anyhow!("guest_exec: input_data must be valid UTF-8 for the guest agent")
            })?;
            Some(
                gtypes::PostExecNodesNodeQemuVmidAgentExecBodyInputData::try_from(s)
                    .map_err(|e| anyhow!("guest_exec: input_data rejected by guest agent: {e}"))?,
            )
        }
        None => None,
    };

    let body = gtypes::PostExecNodesNodeQemuVmidAgentExecBody {
        command: req.command.clone(),
        input_data,
    };
    let pid = client
        .post_exec_nodes_node_qemu_vmid_agent_exec(&node, vmid, &body)
        .await
        .map_err(|e| anyhow!("guest agent exec (vmid {vmid} on '{node}'): {e}"))?
        .into_inner()
        .pid;

    let deadline = Instant::now() + Duration::from_millis(req.timeout_ms());
    let interval = Duration::from_millis(req.poll_interval_ms());
    let cap = req.max_output_bytes() as usize;

    loop {
        let status = client
            .get_exec_status_nodes_node_qemu_vmid_agent_exec_status(&node, vmid, pid)
            .await
            .map_err(|e| anyhow!("guest agent exec-status (pid {pid}, vmid {vmid}): {e}"))?
            .into_inner();

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

/// Write a file into the guest, then apply `mode`/`owner` via chained exec.
///
/// The guest agent's `file-write` sets **content only** — it has no mode/owner
/// field (verified against the spec: the body is `{content, encode, file}`). So a
/// requested `mode`/`owner` is applied with a follow-up `chmod`/`chown` exec. The
/// content is sent raw with `encode` defaulted (PVE base64-encodes it QMP-side);
/// the agent caps it at 61440 chars, enforced by the generated newtype's
/// `TryFrom`. Binary (non-UTF-8) or larger-than-cap writes are rejected here —
/// chunked/base64 writes are a later slice.
async fn write_file(guest: GuestRef, req: WriteFileRequest) -> Result<()> {
    let (client, node, vmid) = resolve_guest(&guest).await?;

    let content_str = String::from_utf8(req.contents.clone()).map_err(|_| {
        anyhow!("guest_exec: write_file contents must be valid UTF-8 (binary/base64 writes are a later slice)")
    })?;
    let content =
        gtypes::PostFileWriteNodesNodeQemuVmidAgentFileWriteBodyContent::try_from(content_str)
            .map_err(|e| {
                anyhow!("guest_exec: file contents rejected by guest agent (cap 61440 chars): {e}")
            })?;

    let body = gtypes::PostFileWriteNodesNodeQemuVmidAgentFileWriteBody {
        content,
        // `None` → PVE default `encode=true`: it base64-encodes the content QMP-side.
        encode: None,
        file: req.path.clone(),
    };
    client
        .post_file_write_nodes_node_qemu_vmid_agent_file_write(&node, vmid, &body)
        .await
        .map_err(|e| {
            anyhow!(
                "guest agent file-write '{}' (vmid {vmid} on '{node}'): {e}",
                req.path
            )
        })?;

    // mode/owner are not native to file-write — apply them with chained exec. The
    // path is not a secret; the mode/owner values are not secrets.
    if let Some(mode) = req.mode.as_deref() {
        run_ok(
            &client,
            &node,
            vmid,
            vec!["chmod".to_string(), mode.to_string(), req.path.clone()],
        )
        .await
        .with_context(|| format!("guest_exec: chmod {mode} '{}'", req.path))?;
    }
    if let Some(owner) = req.owner.as_deref() {
        run_ok(
            &client,
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
async fn run_ok(
    client: &generated::Client,
    node: &str,
    vmid: i64,
    command: Vec<String>,
) -> Result<()> {
    let body = gtypes::PostExecNodesNodeQemuVmidAgentExecBody {
        command: command.clone(),
        input_data: None,
    };
    let pid = client
        .post_exec_nodes_node_qemu_vmid_agent_exec(node, vmid, &body)
        .await
        .map_err(|e| anyhow!("guest agent exec {command:?}: {e}"))?
        .into_inner()
        .pid;

    let deadline = Instant::now()
        + Duration::from_millis(plugin_toolkit::contract::guest_exec::DEFAULT_TIMEOUT_MS);
    let interval =
        Duration::from_millis(plugin_toolkit::contract::guest_exec::DEFAULT_POLL_INTERVAL_MS);
    loop {
        let status = client
            .get_exec_status_nodes_node_qemu_vmid_agent_exec_status(node, vmid, pid)
            .await
            .map_err(|e| anyhow!("guest agent exec-status (pid {pid}): {e}"))?
            .into_inner();
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
    fn provider_name_is_stable() {
        assert_eq!(ProxmoxGuestExec.name(), "proxmox");
    }
}
