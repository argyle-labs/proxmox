//! LXC adapter for Proxmox VE via the HTTPS API.
//!
//! Per [[project-adapter-backends-api-first]]: the legacy `LxcProxmoxAdapter`
//! shells `pct list` and reads `/etc/pve/lxc/<vmid>.conf` directly, which
//! only works when orca runs ON a Proxmox host and bypasses Proxmox auth
//! entirely. This adapter talks the documented API
//! (`https://<node>:8006/api2/json`) through the progenitor-generated
//! `proxmox::generated::Client`, with PVE API-token auth. Works
//! remotely, respects Proxmox permissions, and gives cluster-aware
//! enumeration via `/cluster/resources?type=vm`.
//!
//! The `Container.host` field is the Proxmox node name for every
//! container this adapter returns. The breaker keys on
//! `(host, runtime, container_id)`, so multi-node enumeration flows
//! through unchanged.

use plugin_toolkit::async_trait::async_trait;
use plugin_toolkit::containers::{
    AdapterError, Container, ContainerState, ListFilter, Liveness, LogTail, RestartPolicy,
    RuntimeAdapter, RuntimeKind, WedgeRecoverer,
};
use std::time::Duration;

use crate::generated::{self, types as gtypes};
use crate::{GuestKind, ProxmoxAction, fetch_guest_config};

/// Budget for the liveness probe. Tight on purpose — the reconciler
/// can call this every tick on every running LXC, so a hung probe
/// would block forward progress on the whole tick.
const PROBE_TIMEOUT_SECS: u64 = 5;

/// How long to wait after a `Stop` for the container to report
/// `stopped`, and after a `Start` for it to report `running`.
const RECOVERY_POLL_BUDGET_SECS: u64 = 15;

/// Poll cadence while waiting on status transitions.
const RECOVERY_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// LXC adapter that routes every operation through one Proxmox API
/// endpoint. Multi-endpoint orchestration (different clusters) lives
/// at the reconciler-entry level: one adapter per endpoint, both
/// registered.
pub struct LxcProxmoxApiAdapter {
    client: generated::Client,
    http: reqwest::Client,
    base_url: String,
    /// Display name for the endpoint — surfaced in tracing / error
    /// context, not in the typed surface.
    endpoint_name: String,
}

impl LxcProxmoxApiAdapter {
    pub fn new(
        client: generated::Client,
        http: reqwest::Client,
        base_url: impl Into<String>,
        endpoint_name: impl Into<String>,
    ) -> Self {
        Self {
            client,
            http,
            base_url: base_url.into(),
            endpoint_name: endpoint_name.into(),
        }
    }

    /// Endpoint label this adapter was constructed with.
    pub fn endpoint_name(&self) -> &str {
        &self.endpoint_name
    }
}

#[async_trait]
impl RuntimeAdapter for LxcProxmoxApiAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Lxc
    }

    async fn list(&self, filter: &ListFilter) -> Result<Vec<Container>, AdapterError> {
        let rows = self.fetch_lxc_rows().await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let container = self.build_container(&row).await?;
            if labels_match(&container.labels, &filter.labels) {
                out.push(container);
            }
        }
        Ok(out)
    }

    async fn inspect(&self, id: &str) -> Result<Container, AdapterError> {
        let _: u64 = id
            .parse()
            .map_err(|_| AdapterError::NotFound(format!("vmid `{id}` is not a u64")))?;
        let all = self.list(&ListFilter::default()).await?;
        all.into_iter()
            .find(|c| c.id == id)
            .ok_or_else(|| AdapterError::NotFound(format!("lxc vmid `{id}`")))
    }

    async fn start(&self, id: &str) -> Result<(), AdapterError> {
        self.lifecycle(id, ProxmoxAction::Start).await
    }

    async fn stop(&self, id: &str) -> Result<(), AdapterError> {
        // The Proxmox API distinguishes `shutdown` (graceful) from
        // `stop` (hard). Map `RuntimeAdapter::stop` to `shutdown` to
        // match the docker adapter's graceful default.
        self.lifecycle(id, ProxmoxAction::Shutdown).await
    }

    async fn restart(&self, id: &str) -> Result<(), AdapterError> {
        self.lifecycle(id, ProxmoxAction::Reboot).await
    }

    async fn logs(&self, _id: &str, _tail: LogTail) -> Result<String, AdapterError> {
        Err(AdapterError::Refused(
            "LxcProxmoxApiAdapter::logs requires the syslog endpoint (not yet wired)".into(),
        ))
    }

    /// Liveness probe.
    ///
    /// For recognized media guests (Plex, Jellyfin) the probe hits the real
    /// service surface over HTTP — `pct exec true` only proves PID 1 is alive,
    /// not that the media server is actually serving. A guest whose mount came
    /// back but whose service is still hung would read "Live" under the exec
    /// probe and never get recovered; the service probe closes that gap (per
    /// [[feedback-self-healing-is-mandatory]]: probes do real I/O against the
    /// surface that matters).
    ///
    /// For everything else it falls back to the local-subprocess probe:
    /// `pct exec <vmid> -- true` with a tight timeout. See
    /// [[feedback-api-first-liveness-exception]].
    async fn probe_liveness(&self, container: &Container) -> Liveness {
        if container.runtime != RuntimeKind::Lxc {
            return Liveness::NotApplicable;
        }

        if let Some((host, port)) = media_service_endpoint(container) {
            return probe_http_service(&self.http, &host, port).await;
        }

        let mut cmd = tokio::process::Command::new("pct");
        cmd.arg("exec").arg(&container.id).arg("--").arg("true");
        cmd.kill_on_drop(true);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => return Liveness::Unknown,
        };
        match tokio::time::timeout(Duration::from_secs(PROBE_TIMEOUT_SECS), child.wait()).await {
            Ok(Ok(status)) if status.success() => Liveness::Live,
            Ok(Ok(_)) => Liveness::Unknown,
            Ok(Err(_)) => Liveness::Unknown,
            Err(_) => {
                drop(child.start_kill());
                Liveness::Wedged
            }
        }
    }

    fn wedge_recoverer(&self) -> Option<&dyn WedgeRecoverer> {
        Some(self)
    }
}

#[async_trait]
impl WedgeRecoverer for LxcProxmoxApiAdapter {
    /// API-only recovery: hard `Stop` then `Start`, polling status
    /// between transitions. `Stop` is the hard variant — `Shutdown`
    /// would hang on exactly the wedged PID-1 case this exists to
    /// recover.
    async fn attempt_unwedge(&self, container: &Container) -> Result<(), AdapterError> {
        let vmid: u64 = container
            .id
            .parse()
            .map_err(|_| AdapterError::NotFound(format!("vmid `{}` is not a u64", container.id)))?;
        let node = container.host.clone();

        // Mounts-local recovery FIRST: the dominant LXC wedge cause is a stale
        // NFS handle on the PVE host that leaves PID 1 in uninterruptible
        // sleep, so an API stop/start alone never unsticks it. Probe every
        // network mount on this host (empty watch list = all), force-release
        // and remount any that are stale, THEN proceed to the API lifecycle.
        //
        // Per the brief: recovery errors here are non-fatal. A stuck mount we
        // couldn't fix shouldn't abort the lifecycle restart, which may still
        // succeed (or surface the real failure). Log and continue.
        //
        // Iterate every storage backend that advertises `RecoverStale` rather
        // than naming `nfs` directly: the network-share self-heal lives behind
        // the `storage` domain seam, so smb (and any future backend) is picked
        // up automatically once registered.
        for backend in plugin_toolkit::storage::backends() {
            if !backend.supports(plugin_toolkit::storage::Capability::RecoverStale) {
                continue;
            }
            match backend
                .recover_stale(&[], Duration::from_secs(PROBE_TIMEOUT_SECS))
                .await
            {
                Ok(r) if r.no_stale_found => {
                    tracing::debug!(
                        endpoint = %self.endpoint_name,
                        node = %node,
                        vmid,
                        backend = %backend.name(),
                        "unwedge: no stale or missing network mounts found, proceeding to lifecycle restart"
                    );
                }
                Ok(r) => {
                    tracing::info!(
                        endpoint = %self.endpoint_name,
                        node = %node,
                        vmid,
                        backend = %backend.name(),
                        recovered = ?r.recovered,
                        still_stale = ?r.still_stale,
                        remounted = ?r.remounted,
                        still_missing = ?r.still_missing,
                        errors = ?r.errors,
                        "unwedge: network-mount recovery attempted"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        endpoint = %self.endpoint_name,
                        node = %node,
                        vmid,
                        backend = %backend.name(),
                        error = %e,
                        "unwedge: stale-mount recovery could not enumerate mounts, continuing to lifecycle restart"
                    );
                }
            }
        }

        self.do_lifecycle(&node, vmid, ProxmoxAction::Stop).await?;
        wait_for_status(&self.client, &node, vmid, "stopped").await?;

        self.do_lifecycle(&node, vmid, ProxmoxAction::Start).await?;
        wait_for_status(&self.client, &node, vmid, "running").await?;

        Ok(())
    }
}

/// Poll the LXC current-status endpoint until `data.status` matches
/// `expected`, up to [`RECOVERY_POLL_BUDGET_SECS`].
async fn wait_for_status(
    client: &generated::Client,
    node: &str,
    vmid: u64,
    expected: &str,
) -> Result<(), AdapterError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(RECOVERY_POLL_BUDGET_SECS);
    loop {
        let st = client
            .get_vm_status_nodes_node_lxc_vmid_status_current(node, vmid as i64)
            .await
            .map_err(|e| AdapterError::Transport(format!("status {vmid}: {e}")))?
            .into_inner();
        if st.status.to_string() == expected {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AdapterError::Refused(format!(
                "container {vmid} did not reach `{expected}` within {RECOVERY_POLL_BUDGET_SECS}s"
            )));
        }
        tokio::time::sleep(RECOVERY_POLL_INTERVAL).await;
    }
}

impl LxcProxmoxApiAdapter {
    /// Fetch the cluster resource list and return only LXC rows.
    async fn fetch_lxc_rows(&self) -> Result<Vec<LxcRow>, AdapterError> {
        let items = self
            .client
            .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
            .await
            .map_err(|e| AdapterError::Transport(format!("cluster resources: {e}")))?
            .into_inner();
        Ok(items
            .into_iter()
            .filter_map(|r| {
                if !matches!(
                    r.type_,
                    gtypes::GetResourcesClusterResourcesResponseItemType::Lxc
                ) {
                    return None;
                }
                let node = r.node?;
                let vmid = r.vmid?;
                if vmid <= 0 {
                    return None;
                }
                Some(LxcRow {
                    vmid: vmid as u64,
                    node,
                    name: r.name,
                    status: r.status,
                })
            })
            .collect())
    }

    async fn build_container(&self, row: &LxcRow) -> Result<Container, AdapterError> {
        // Per-container config fetch populates restart_policy from
        // `onboot`. Raw URL because progenitor can't model indexed
        // keys; see `fetch_guest_config` rationale.
        let cfg = fetch_guest_config(
            &self.http,
            &self.base_url,
            &row.node,
            GuestKind::Lxc,
            row.vmid,
        )
        .await
        .map_err(|e| AdapterError::Transport(format!("guest_config: {e}")))?;
        let restart_policy = if cfg.data.onboot() {
            RestartPolicy::Always
        } else {
            RestartPolicy::No
        };

        let name = row
            .name
            .clone()
            .unwrap_or_else(|| format!("ct-{}", row.vmid));
        let state = row
            .status
            .as_deref()
            .map(map_proxmox_status)
            .unwrap_or(ContainerState::Unknown);

        Ok(Container {
            id: row.vmid.to_string(),
            name,
            runtime: RuntimeKind::Lxc,
            host: row.node.clone(),
            state,
            restart_policy,
            image: None,
            labels: Vec::new(),
            mounts: Vec::new(),
            ports: Vec::new(),
            started_at: None,
            finished_at: None,
            restart_count: 0,
            exit_code: None,
            startup: None,
        })
    }

    async fn lifecycle(&self, id: &str, action: ProxmoxAction) -> Result<(), AdapterError> {
        let vmid: u64 = id
            .parse()
            .map_err(|_| AdapterError::NotFound(format!("vmid `{id}` is not a u64")))?;
        let rows = self.fetch_lxc_rows().await?;
        let node = rows
            .into_iter()
            .find(|r| r.vmid == vmid)
            .map(|r| r.node)
            .ok_or_else(|| AdapterError::NotFound(format!("lxc vmid `{vmid}` not in cluster")))?;
        self.do_lifecycle(&node, vmid, action).await
    }

    async fn do_lifecycle(
        &self,
        node: &str,
        vmid: u64,
        action: ProxmoxAction,
    ) -> Result<(), AdapterError> {
        let vmid_i = vmid as i64;
        let res = match action {
            ProxmoxAction::Start => self
                .client
                .post_vm_start_nodes_node_lxc_vmid_status_start(node, vmid_i, &Default::default())
                .await
                .map(|_| ()),
            ProxmoxAction::Stop => self
                .client
                .post_vm_stop_nodes_node_lxc_vmid_status_stop(node, vmid_i, &Default::default())
                .await
                .map(|_| ()),
            ProxmoxAction::Shutdown => self
                .client
                .post_vm_shutdown_nodes_node_lxc_vmid_status_shutdown(
                    node,
                    vmid_i,
                    &Default::default(),
                )
                .await
                .map(|_| ()),
            ProxmoxAction::Reboot => self
                .client
                .post_vm_reboot_nodes_node_lxc_vmid_status_reboot(node, vmid_i, &Default::default())
                .await
                .map(|_| ()),
        };
        res.map_err(|e| AdapterError::Transport(format!("{} {vmid}: {e}", action.as_str())))
    }
}

#[derive(Debug, Clone)]
struct LxcRow {
    vmid: u64,
    node: String,
    name: Option<String>,
    status: Option<String>,
}

/// HTTP probe budget for the media service surface. Same tight bound as the
/// exec probe — the reconciler may call this every tick.
const SERVICE_PROBE_TIMEOUT_SECS: u64 = 5;

/// Well-known service ports for recognized media guests, used as the fallback
/// when the container model carries no published-port mapping (LXC guests
/// frequently don't expose `ports` through the cluster-resources API).
const PLEX_PORT: u16 = 32400;
const JELLYFIN_PORT: u16 = 8096;

/// Identify a recognized media guest and resolve the `(host, port)` to probe.
///
/// Detection is by name/image substring (`plex` / `jellyfin`). The host is the
/// Proxmox node the guest runs on (`container.host`) — the published port lives
/// on the node's network namespace. Port preference: an explicitly published
/// `host_port` whose `container_port` matches the service's well-known port,
/// otherwise the well-known port itself. Returns `None` for non-media guests so
/// the caller falls back to the exec probe.
fn media_service_endpoint(container: &Container) -> Option<(String, u16)> {
    let hay = format!(
        "{} {}",
        container.name.to_ascii_lowercase(),
        container
            .image
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
    );
    let well_known = if hay.contains("plex") {
        PLEX_PORT
    } else if hay.contains("jellyfin") {
        JELLYFIN_PORT
    } else {
        return None;
    };
    if container.host.is_empty() {
        return None;
    }
    let port = container
        .ports
        .iter()
        .find(|p| p.container_port == well_known)
        .map(|p| p.host_port)
        .unwrap_or(well_known);
    Some((container.host.clone(), port))
}

/// Probe a media service's HTTP surface. Any HTTP response (even 401/403 — Plex
/// returns 401 on `/` unauthenticated) proves the service is serving, so a
/// completed request within budget is `Live`. A timeout is `Wedged`; a connect
/// error or other transport failure is `Unknown` (do-not-act — could be a
/// transient blip the reconciler shouldn't escalate on).
async fn probe_http_service(http: &reqwest::Client, host: &str, port: u16) -> Liveness {
    let url = format!("http://{host}:{port}/");
    let fut = http.get(&url).send();
    match tokio::time::timeout(Duration::from_secs(SERVICE_PROBE_TIMEOUT_SECS), fut).await {
        Ok(Ok(_)) => Liveness::Live,
        Ok(Err(_)) => Liveness::Unknown,
        Err(_) => Liveness::Wedged,
    }
}

fn map_proxmox_status(s: &str) -> ContainerState {
    match s {
        "running" => ContainerState::Running,
        "stopped" => ContainerState::Exited,
        "paused" => ContainerState::Paused,
        _ => ContainerState::Unknown,
    }
}

fn labels_match(have: &[(String, String)], wanted: &[(String, String)]) -> bool {
    wanted
        .iter()
        .all(|w| have.iter().any(|h| h.0 == w.0 && h.1 == w.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::containers::{ContainerPort, RestartPolicy};

    /// reqwest 0.13 (rustls/ring, no aws-lc) panics `No provider set` when a
    /// `reqwest::Client` is built before a process-default crypto provider is
    /// installed. The daemon installs ring at startup; unit tests must do the
    /// same. Idempotent — `install_default` errors if already set, ignored.
    fn ensure_crypto_provider() {
        _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn container(name: &str, image: Option<&str>, host: &str) -> Container {
        Container {
            id: "100".into(),
            name: name.into(),
            runtime: RuntimeKind::Lxc,
            host: host.into(),
            state: ContainerState::Running,
            restart_policy: RestartPolicy::No,
            image: image.map(Into::into),
            labels: Vec::new(),
            mounts: Vec::new(),
            ports: Vec::new(),
            started_at: None,
            finished_at: None,
            restart_count: 0,
            exit_code: None,
            startup: None,
        }
    }

    #[test]
    fn media_endpoint_detects_plex_by_name_well_known_port() {
        let c = container("plex-media", None, "node1");
        let (host, port) = media_service_endpoint(&c).expect("plex should match");
        assert_eq!(host, "node1");
        assert_eq!(port, PLEX_PORT);
    }

    #[test]
    fn media_endpoint_detects_jellyfin_by_image() {
        let c = container(
            "media-ct",
            Some("lscr.io/linuxserver/jellyfin:latest"),
            "node2",
        );
        let (_, port) = media_service_endpoint(&c).expect("jellyfin should match");
        assert_eq!(port, JELLYFIN_PORT);
    }

    #[test]
    fn media_endpoint_prefers_published_host_port_for_service() {
        let mut c = container("plex", None, "node3");
        c.ports.push(ContainerPort {
            host_port: 40000,
            container_port: PLEX_PORT,
            protocol: "tcp".into(),
        });
        // An unrelated mapping must not be picked.
        c.ports.push(ContainerPort {
            host_port: 9999,
            container_port: 9999,
            protocol: "tcp".into(),
        });
        let (_, port) = media_service_endpoint(&c).unwrap();
        assert_eq!(port, 40000);
    }

    #[test]
    fn media_endpoint_none_for_non_media_guest() {
        assert!(media_service_endpoint(&container("postgres", Some("postgres:16"), "n")).is_none());
    }

    #[test]
    fn media_endpoint_none_when_host_unknown() {
        // No host to probe → fall back to exec probe, not a bogus HTTP target.
        assert!(media_service_endpoint(&container("plex", None, "")).is_none());
    }

    #[tokio::test]
    async fn http_probe_unknown_on_connect_failure() {
        // Port 1 on localhost: connection refused → Unknown (do-not-act),
        // not a false Wedged that would trigger a needless restart.
        ensure_crypto_provider();
        let http = reqwest::Client::new();
        let live = probe_http_service(&http, "127.0.0.1", 1).await;
        assert_eq!(live, Liveness::Unknown);
    }
}
