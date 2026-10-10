//! LVM-thin pool over-commitment.
//!
//! A thin pool lets the virtual sizes of its volumes add up to more than the
//! pool holds. Once real allocation reaches the pool size every volume on it
//! stalls or corrupts, so the sum of virtual sizes is kept under the pool size
//! minus [`SAFETY_MARGIN_PCT`].
//!
//! * [`diagnose_thin_pools`] flags pools already over that line.
//! * [`check_grow`] is the guard any disk grow runs first: it refuses a grow
//!   that would push the pool over the line.
//!
//! Provisioned totals come from the storage content listing, which does not
//! list LVM snapshots, so a pool holding snapshots is more committed than
//! reported.

use std::collections::HashMap;

use plugin_toolkit::contract::diagnostics::{Finding, Severity};
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::backup::{enc, raw_get_data};
use crate::generated::{self, types as gtypes};
use crate::tools::for_each_enabled_endpoint;

/// Share of the pool kept free of provisioned volumes.
pub const SAFETY_MARGIN_PCT: f64 = 5.0;

const PROVIDER: &str = "proxmox";
const THIN_PLUGIN: &str = "lvmthin";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PoolCommit {
    pub node: String,
    pub storage: String,
    pub size_bytes: u64,
    /// Blocks actually allocated in the pool.
    pub used_bytes: u64,
    /// Sum of the virtual sizes of every volume on the pool.
    pub provisioned_bytes: u64,
}

impl PoolCommit {
    /// Largest provisioned total the pool accepts.
    pub fn limit_bytes(&self) -> u64 {
        (self.size_bytes as f64 * (1.0 - SAFETY_MARGIN_PCT / 100.0)) as u64
    }

    pub fn over_committed(&self) -> bool {
        self.provisioned_bytes > self.limit_bytes()
    }
}

/// Sum of volume sizes in a `/nodes/{node}/storage/{storage}/content` listing.
pub fn provisioned_bytes(content: &Value) -> u64 {
    content
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.get("size").and_then(Value::as_u64))
                .sum()
        })
        .unwrap_or(0)
}

/// Refuse a grow of `grow_bytes` that would take the pool's provisioned total
/// past [`PoolCommit::limit_bytes`].
pub fn check_grow(pool: &PoolCommit, grow_bytes: u64) -> std::result::Result<(), String> {
    let after = pool.provisioned_bytes.saturating_add(grow_bytes);
    let limit = pool.limit_bytes();
    if after <= limit {
        return Ok(());
    }
    Err(format!(
        "growing by {:.1} GiB would provision {:.1} GiB on thin pool '{}' (node '{}'), over its \
         {:.1} GiB limit ({:.1} GiB pool less {SAFETY_MARGIN_PCT}% margin); largest safe grow is \
         {:.1} GiB",
        gib(grow_bytes),
        gib(after),
        pool.storage,
        pool.node,
        gib(limit),
        gib(pool.size_bytes),
        gib(limit.saturating_sub(pool.provisioned_bytes)),
    ))
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1u64 << 30) as f64
}

pub fn finding_over_committed(scope: &str, p: &PoolCommit) -> Finding {
    let pct = |n: u64| {
        if p.size_bytes == 0 {
            0.0
        } else {
            n as f64 * 100.0 / p.size_bytes as f64
        }
    };
    let severity = if p.provisioned_bytes > p.size_bytes {
        Severity::Crit
    } else {
        Severity::Warn
    };
    Finding {
        id: format!("thin-pool-overcommit::{scope}::{}::{}", p.node, p.storage),
        provider: PROVIDER.to_string(),
        severity,
        title: format!(
            "Thin pool '{}' on node '{}' is {:.0}% provisioned",
            p.storage,
            p.node,
            pct(p.provisioned_bytes)
        ),
        detail: format!(
            "Volumes on thin pool '{}' (node '{}') total {:.1} GiB against a {:.1} GiB pool \
             ({:.1} GiB allocated, {:.0}%). Above {:.1} GiB ({SAFETY_MARGIN_PCT}% margin) the \
             pool can fill while guests still see free space, and a full thin pool stalls or \
             corrupts every volume on it. Shrink or move volumes, or enlarge the pool.",
            p.storage,
            p.node,
            gib(p.provisioned_bytes),
            gib(p.size_bytes),
            gib(p.used_bytes),
            pct(p.used_bytes),
            gib(p.limit_bytes()),
        ),
        repair: None,
    }
}

/// `(node, storage) → (size, used)` for every lvmthin storage in a
/// `/cluster/resources` payload.
fn thin_pools(
    items: Vec<gtypes::GetResourcesClusterResourcesResponseItem>,
) -> HashMap<(String, String), (u64, u64)> {
    use gtypes::GetResourcesClusterResourcesResponseItemType as Kind;
    items
        .into_iter()
        .filter(|i| i.type_ == Kind::Storage && i.plugintype.as_deref() == Some(THIN_PLUGIN))
        .filter_map(|i| {
            let size = i.maxdisk.filter(|s| *s > 0)?;
            Some(((i.node?, i.storage?), (size, i.disk.unwrap_or(0))))
        })
        .collect()
}

async fn diagnose_endpoint(cfg: &crate::Config, endpoint: &str) -> Result<Vec<Finding>> {
    let http = cfg.build_reqwest_client()?;
    let client = generated::Client::new_with_client(&cfg.base_url, http.clone());
    let pools = thin_pools(
        client
            .get_resources_cluster_resources(None)
            .await
            .map_err(|e| anyhow::anyhow!("cluster resources: {e}"))?
            .into_inner(),
    );
    let scope = crate::cluster::fetch_cluster_status(&client)
        .await
        .ok()
        .and_then(|s| s.name)
        .unwrap_or_else(|| endpoint.to_string());

    let mut findings = Vec::new();
    for ((node, storage), (size, used)) in pools {
        let path = format!("nodes/{}/storage/{}/content", enc(&node), enc(&storage));
        let content = match raw_get_data(&http, &cfg.base_url, &path).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(endpoint, node = %node, storage = %storage, error = %e,
                    "thin pool: storage content listing failed");
                continue;
            }
        };
        let p = PoolCommit {
            node,
            storage,
            size_bytes: size,
            used_bytes: used,
            provisioned_bytes: provisioned_bytes(&content),
        };
        if p.over_committed() {
            findings.push(finding_over_committed(&scope, &p));
        }
    }
    Ok(findings)
}

/// Over-committed thin pools on every enabled endpoint, deduplicated across
/// endpoints of one cluster.
pub async fn diagnose_thin_pools() -> Vec<Finding> {
    let mut findings = for_each_enabled_endpoint("diagnostics.thin_pool", |cfg, ep| async move {
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

    const GIB: u64 = 1 << 30;

    fn pool(size_gib: u64, provisioned_gib: u64) -> PoolCommit {
        PoolCommit {
            node: "frigg".into(),
            storage: "local-lvm".into(),
            size_bytes: size_gib * GIB,
            used_bytes: size_gib * GIB / 4,
            provisioned_bytes: provisioned_gib * GIB,
        }
    }

    #[test]
    fn sums_every_volume_size_and_skips_sizeless_entries() {
        let content = json!([
            {"volid": "local-lvm:vm-100-disk-0", "size": 10 * GIB, "used": GIB},
            {"volid": "local-lvm:vm-101-disk-0", "size": 5 * GIB},
            {"volid": "local-lvm:base-900-disk-0"},
        ]);
        assert_eq!(provisioned_bytes(&content), 15 * GIB);
        assert_eq!(provisioned_bytes(&json!(null)), 0);
    }

    #[test]
    fn freyr_grow_that_overcommitted_the_pool_is_refused() {
        // 2026-08-30: 701 GiB provisioned on an 816 GiB pool, grown by 300 GiB.
        let p = pool(816, 551);
        let err = check_grow(&p, 300 * GIB).unwrap_err();
        assert!(err.contains("local-lvm"), "{err}");
        assert!(err.contains("largest safe grow is 224.2 GiB"), "{err}");
        // A 220 GiB grow (to 771 GiB) stays under the 775.2 GiB limit.
        assert!(check_grow(&p, 220 * GIB).is_ok());
    }

    #[test]
    fn grow_up_to_the_margin_is_allowed_and_one_byte_more_is_not() {
        let p = pool(100, 50);
        let room = p.limit_bytes() - p.provisioned_bytes;
        assert!(check_grow(&p, room).is_ok());
        assert!(check_grow(&p, room + 1).is_err());
    }

    #[test]
    fn overcommit_severity_escalates_past_the_pool_size() {
        assert!(!pool(100, 94).over_committed());
        let near = pool(100, 97);
        assert!(near.over_committed());
        assert_eq!(finding_over_committed("c", &near).severity, Severity::Warn);
        let over = pool(816, 851);
        let f = finding_over_committed("c", &over);
        assert_eq!(f.severity, Severity::Crit);
        assert_eq!(f.id, "thin-pool-overcommit::c::frigg::local-lvm");
    }
}
