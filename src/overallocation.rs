//! Node vCPU commitment — a `diagnostics` provider surface.
//!
//! vCPU over-subscription is normal: cores time-slice, so only a steep ratio
//! earns an `Info` nudge. Memory commitment is judged in [`crate::memory`].

use crate::GuestKind;
use crate::responses::{ClusterResource, ResourceType, cluster_resources};
use crate::tools::for_each_enabled_endpoint;
use plugin_toolkit::contract::diagnostics::{Finding, Severity};
use std::collections::HashMap;

/// vCPUs committed per physical core before an `Info` nudge. Deliberately
/// steep: mild over-subscription is correct practice, not a defect.
pub const VCPU_RATIO_INFO: f64 = 4.0;

const PROVIDER: &str = "proxmox";

/// One node's physical capacity.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeCapacity {
    pub node: String,
    pub phys_mem_bytes: u64,
    pub phys_cpus: f64,
}

/// One *running* guest's allocation. Stopped guests reserve nothing and are
/// filtered out before assessment.
#[derive(Debug, Clone, PartialEq)]
pub struct GuestAlloc {
    pub name: String,
    pub kind: GuestKind,
    pub mem_bytes: u64,
    pub vcpus: f64,
}

/// What one node has committed, split by how binding each commitment is.
#[derive(Debug, Clone, PartialEq)]
pub struct Commitment {
    pub node: String,
    pub phys_mem_bytes: u64,
    pub phys_cpus: f64,
    /// Memory reserved by QEMU VMs — unreclaimable.
    pub reserved_mem_bytes: u64,
    /// Memory *capped* for LXC guests — opportunistic, usually far under-used.
    pub capped_mem_bytes: u64,
    pub vcpus_committed: f64,
    pub guest_count: usize,
}

impl Commitment {
    pub fn total_mem_bytes(&self) -> u64 {
        self.reserved_mem_bytes
            .saturating_add(self.capped_mem_bytes)
    }

    /// Share of physical memory reserved by VMs alone.
    pub fn reserved_pct(&self) -> f64 {
        pct(self.reserved_mem_bytes, self.phys_mem_bytes)
    }

    /// Share of physical memory committed in total (VM reserved + LXC caps).
    pub fn total_pct(&self) -> f64 {
        pct(self.total_mem_bytes(), self.phys_mem_bytes)
    }

    /// Committed vCPUs per physical core.
    pub fn vcpu_ratio(&self) -> f64 {
        if self.phys_cpus <= 0.0 {
            return 0.0;
        }
        self.vcpus_committed / self.phys_cpus
    }
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64 / whole as f64) * 100.0
}

/// Pure: fold a node's running guests into its commitment totals.
pub fn assess(node: &NodeCapacity, guests: &[GuestAlloc]) -> Commitment {
    let mut c = Commitment {
        node: node.node.clone(),
        phys_mem_bytes: node.phys_mem_bytes,
        phys_cpus: node.phys_cpus,
        reserved_mem_bytes: 0,
        capped_mem_bytes: 0,
        vcpus_committed: 0.0,
        guest_count: guests.len(),
    };
    for g in guests {
        match g.kind {
            GuestKind::Qemu => {
                c.reserved_mem_bytes = c.reserved_mem_bytes.saturating_add(g.mem_bytes)
            }
            GuestKind::Lxc => c.capped_mem_bytes = c.capped_mem_bytes.saturating_add(g.mem_bytes),
        }
        c.vcpus_committed += g.vcpus;
    }
    c
}

/// Pure: turn a commitment into findings. Empty when the node is within limits.
pub fn findings_for(c: &Commitment) -> Vec<Finding> {
    let mut out = Vec::new();
    if c.phys_mem_bytes == 0 {
        return out; // node capacity unknown — say nothing rather than guess.
    }
    if c.vcpu_ratio() > VCPU_RATIO_INFO {
        out.push(finding_vcpu(c));
    }
    out
}

fn finding_vcpu(c: &Commitment) -> Finding {
    Finding {
        id: format!("capacity-vcpu::{}", c.node),
        provider: PROVIDER.to_string(),
        // Info, not Warn: CPU time-slices. This is a nudge, not a fault.
        severity: Severity::Info,
        title: format!(
            "PVE node '{}' has {:.1}x more vCPUs committed than physical cores",
            c.node,
            c.vcpu_ratio()
        ),
        detail: format!(
            "Node '{}' commits {:.0} vCPUs across {} running guests on {:.0} physical cores \
             ({:.1}x). Some CPU over-subscription is correct — cores time-slice, and most guests \
             idle — so this is a nudge rather than a fault. At this ratio, though, guests will \
             contend for runtime under concurrent load, which shows up as latency and stalled \
             builds rather than as an outright failure. Worth checking that no single guest is \
             sized far beyond what it uses.",
            c.node,
            c.vcpus_committed,
            c.guest_count,
            c.phys_cpus,
            c.vcpu_ratio()
        ),
        repair: None,
    }
}

/// Fan out across every enabled endpoint, fold each node's running guests into
/// a [`Commitment`], and emit findings. One `/cluster/resources` call per
/// endpoint returns both the nodes and their guests, so this costs a single
/// round trip.
pub async fn diagnose_overallocation() -> Vec<Finding> {
    for_each_enabled_endpoint("diagnostics.capacity", |cfg, _ep| async move {
        let items = cluster_resources(&cfg.endpoint, None)?;

        let (nodes, by_node) = partition_resources(items);
        Ok(nodes
            .iter()
            .flat_map(|n| {
                let guests = by_node.get(&n.node).map(Vec::as_slice).unwrap_or(&[]);
                findings_for(&assess(n, guests))
            })
            .collect())
    })
    .await
}

/// Split a `/cluster/resources` payload into node capacities and the running
/// guests on each. Stopped guests and templates reserve nothing, so they are
/// dropped here rather than being weighed and discounted later.
fn partition_resources(
    items: Vec<ClusterResource>,
) -> (Vec<NodeCapacity>, HashMap<String, Vec<GuestAlloc>>) {
    use ResourceType as Kind;

    let mut nodes = Vec::new();
    let mut by_node: HashMap<String, Vec<GuestAlloc>> = HashMap::new();

    for item in items {
        let kind = match item.type_ {
            Kind::Node => {
                if let Some(name) = item.node.clone() {
                    nodes.push(NodeCapacity {
                        node: name,
                        phys_mem_bytes: item.maxmem.unwrap_or(0).max(0) as u64,
                        phys_cpus: item.maxcpu.unwrap_or(0.0),
                    });
                }
                continue;
            }
            Kind::Qemu => GuestKind::Qemu,
            Kind::Lxc => GuestKind::Lxc,
            _ => continue,
        };
        if item.template.unwrap_or(false) || item.status.as_deref() != Some("running") {
            continue;
        }
        let Some(node) = item.node.clone() else {
            continue;
        };
        by_node.entry(node).or_default().push(GuestAlloc {
            name: item
                .name
                .clone()
                .or_else(|| item.vmid.map(|v| format!("vmid-{v}")))
                .unwrap_or_else(|| item.id.clone()),
            kind,
            mem_bytes: item.maxmem.unwrap_or(0).max(0) as u64,
            vcpus: item.maxcpu.unwrap_or(0.0),
        });
    }

    (nodes, by_node)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(name: &str, gib_mem: f64, vcpus: f64) -> GuestAlloc {
        GuestAlloc {
            name: name.to_string(),
            kind: GuestKind::Qemu,
            mem_bytes: (gib_mem * 1024.0 * 1024.0 * 1024.0) as u64,
            vcpus,
        }
    }

    fn ct(name: &str, gib_mem: f64, vcpus: f64) -> GuestAlloc {
        GuestAlloc {
            name: name.to_string(),
            kind: GuestKind::Lxc,
            mem_bytes: (gib_mem * 1024.0 * 1024.0 * 1024.0) as u64,
            vcpus,
        }
    }

    fn node(name: &str, gib_mem: f64, cpus: f64) -> NodeCapacity {
        NodeCapacity {
            node: name.to_string(),
            phys_mem_bytes: (gib_mem * 1024.0 * 1024.0 * 1024.0) as u64,
            phys_cpus: cpus,
        }
    }

    /// vCPU over-subscription alone must never fire: 24 vCPUs on 20 cores is
    /// ordinary and correct. A check that flags this is noise.
    #[test]
    fn mild_vcpu_oversubscription_is_not_a_finding() {
        let n = node("thor", 64.0, 20.0);
        let guests = vec![vm("a", 4.0, 12.0), ct("b", 4.0, 12.0)];
        let c = assess(&n, &guests);

        assert!(c.vcpu_ratio() > 1.0, "sanity: this is over-subscribed");
        assert!(
            findings_for(&c).is_empty(),
            "1.2x vCPU with memory headroom must be silent"
        );
    }

    #[test]
    fn steep_vcpu_oversubscription_is_info_only() {
        let n = node("small", 64.0, 4.0);
        let guests = vec![ct("busy", 2.0, 40.0)];
        let c = assess(&n, &guests);

        let f = findings_for(&c);
        assert_eq!(f.len(), 1);
        assert_eq!(
            f[0].severity,
            Severity::Info,
            "CPU time-slices — never Warn"
        );
        assert_eq!(f[0].id, "capacity-vcpu::small");
    }

    #[test]
    fn a_healthy_node_produces_nothing() {
        let n = node("frigg", 62.6, 16.0);
        let c = assess(&n, &[vm("a", 12.0, 4.0), ct("b", 8.0, 4.0)]);
        assert!(findings_for(&c).is_empty());
    }

    /// Unknown capacity must not produce a divide-by-zero finding or a 0%
    /// claim — an endpoint that did not report node memory says nothing.
    #[test]
    fn unknown_node_capacity_is_silent() {
        let n = node("mystery", 0.0, 0.0);
        let c = assess(&n, &[vm("a", 8.0, 4.0)]);
        assert_eq!(c.total_pct(), 0.0);
        assert_eq!(c.vcpu_ratio(), 0.0);
        assert!(findings_for(&c).is_empty());
    }

    #[test]
    fn assess_splits_reserved_from_capped() {
        let n = node("n", 32.0, 8.0);
        let c = assess(&n, &[vm("v", 4.0, 2.0), ct("c", 6.0, 3.0)]);

        assert_eq!(c.reserved_mem_bytes, (4.0 * 1024.0f64.powi(3)) as u64);
        assert_eq!(c.capped_mem_bytes, (6.0 * 1024.0f64.powi(3)) as u64);
        assert_eq!(c.total_mem_bytes(), (10.0 * 1024.0f64.powi(3)) as u64);
        assert_eq!(c.vcpus_committed, 5.0);
        assert_eq!(c.guest_count, 2);
    }
}
