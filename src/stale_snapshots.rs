//! Stale guest snapshots — a `diagnostics` provider surface.
//!
//! On LVM-thin a snapshot pins every block its volume has rewritten since, so
//! an old one holds pool space that grows with the guest's churn and that no
//! trim reclaims. Snapshots taken before an upgrade are routinely forgotten
//! once the upgrade lands.
//!
//! No repair: deleting a snapshot discards a restore point, which is the
//! operator's call.

use plugin_toolkit::contract::diagnostics::{Finding, Severity};
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::backup::{enc, raw_get_data};
use crate::generated::{self, types as gtypes};
use crate::tools::for_each_enabled_endpoint;

/// Snapshots older than this are flagged.
pub const STALE_SNAPSHOT_DAYS: u64 = 14;

const PROVIDER: &str = "proxmox";
/// PVE lists the live state as a pseudo-snapshot with this name.
const CURRENT: &str = "current";

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub name: String,
    pub snaptime: u64,
}

/// Snapshots in a `/nodes/{node}/{kind}/{vmid}/snapshot` listing taken more
/// than `max_age_secs` before `now`.
pub fn stale_snapshots(listing: &Value, now: u64, max_age_secs: u64) -> Vec<Snapshot> {
    listing
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| {
                    let name = i.get("name")?.as_str()?;
                    let snaptime = i.get("snaptime")?.as_u64()?;
                    (name != CURRENT && now.saturating_sub(snaptime) > max_age_secs).then(|| {
                        Snapshot {
                            name: name.to_string(),
                            snaptime,
                        }
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn finding_stale_snapshot(
    scope: &str,
    node: &str,
    kind: &str,
    vmid: u64,
    guest: &str,
    snap: &Snapshot,
    now: u64,
) -> Finding {
    let days = now.saturating_sub(snap.snaptime) / 86_400;
    Finding {
        id: format!("stale-snapshot::{scope}::{node}::{vmid}::{}", snap.name),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!(
            "Snapshot '{}' of '{guest}' ({kind} {vmid}) is {days} days old",
            snap.name
        ),
        detail: format!(
            "Snapshot '{}' of {kind} {vmid} on node '{node}' was taken {days} days ago. On thin \
             storage it holds every block the guest has rewritten since, and trim cannot reclaim \
             them. Delete it if it is no longer a restore point you need.",
            snap.name
        ),
        repair: None,
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn diagnose_endpoint(cfg: &crate::Config, endpoint: &str) -> Result<Vec<Finding>> {
    use gtypes::GetResourcesClusterResourcesResponseItemType as Kind;
    let http = cfg.build_reqwest_client()?;
    let client = generated::Client::new_with_client(&cfg.base_url, http.clone());
    let items = client
        .get_resources_cluster_resources(None)
        .await
        .map_err(|e| anyhow::anyhow!("cluster resources: {e}"))?
        .into_inner();
    let scope = crate::cluster::fetch_cluster_status(&client)
        .await
        .ok()
        .and_then(|s| s.name)
        .unwrap_or_else(|| endpoint.to_string());

    let now = now_secs();
    let mut findings = Vec::new();
    for item in items {
        let kind = match item.type_ {
            Kind::Qemu => "qemu",
            Kind::Lxc => "lxc",
            _ => continue,
        };
        let (Some(node), Some(vmid)) = (item.node, item.vmid) else {
            continue;
        };
        let vmid = vmid as u64;
        let path = format!("nodes/{}/{kind}/{vmid}/snapshot", enc(&node));
        let listing = match raw_get_data(&http, &cfg.base_url, &path).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(endpoint, node = %node, vmid, error = %e,
                    "stale snapshots: snapshot listing failed");
                continue;
            }
        };
        let guest = item.name.unwrap_or_else(|| vmid.to_string());
        for snap in stale_snapshots(&listing, now, STALE_SNAPSHOT_DAYS * 86_400) {
            findings.push(finding_stale_snapshot(
                &scope, &node, kind, vmid, &guest, &snap, now,
            ));
        }
    }
    Ok(findings)
}

/// Stale snapshots on every enabled endpoint, deduplicated across endpoints of
/// one cluster.
pub async fn diagnose_stale_snapshots() -> Vec<Finding> {
    let mut findings =
        for_each_enabled_endpoint("diagnostics.stale_snapshots", |cfg, ep| async move {
            diagnose_endpoint(&cfg, &ep.name).await
        })
        .await;
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    const DAY: u64 = 86_400;

    #[test]
    fn flags_only_snapshots_past_the_age_and_never_current() {
        let now = 100 * DAY;
        let listing = json!([
            {"name": "preupg1270", "snaptime": now - 60 * DAY},
            {"name": "recent", "snaptime": now - DAY},
            {"name": "current", "running": 1},
            {"name": "no-time"},
        ]);
        let stale = stale_snapshots(&listing, now, STALE_SNAPSHOT_DAYS * DAY);
        assert_eq!(
            stale,
            vec![Snapshot {
                name: "preupg1270".into(),
                snaptime: now - 60 * DAY
            }]
        );
    }

    #[test]
    fn non_array_listing_is_empty() {
        assert!(stale_snapshots(&json!(null), 0, 0).is_empty());
    }

    #[test]
    fn finding_names_the_guest_snapshot_and_age() {
        let now = 100 * DAY;
        let snap = Snapshot {
            name: "preupg1270".into(),
            snaptime: now - 60 * DAY,
        };
        let f = finding_stale_snapshot("lab", "frigg", "lxc", 117, "gitea", &snap, now);
        assert_eq!(f.id, "stale-snapshot::lab::frigg::117::preupg1270");
        assert!(f.title.contains("60 days old"), "{}", f.title);
        assert!(f.repair.is_none());
    }
}
