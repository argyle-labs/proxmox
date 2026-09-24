//! Node capacity commitment — a `diagnostics` provider surface.
//!
//! A PVE node happily lets you allocate more memory to its guests than it
//! physically has. Nothing warns you; it works right up until a spike, and then
//! something gets OOM-killed with no explanation. That is how thor was found
//! sitting at 34 GiB committed on a 31 GiB box — by a human running `pvesh`
//! while chasing an unrelated slow CI job.
//!
//! **The two resources are not the same problem, and treating them alike is
//! what makes a check like this useless:**
//!
//! * **vCPU over-subscription is normal.** Handing 36 vCPUs to guests on a
//!   16-core node is the entire point of virtualization — cores time-slice.
//!   Flagging that at >100% would fire on every healthy node forever, so it is
//!   only an `Info` nudge, and only at a genuinely steep ratio.
//! * **Memory over-commitment is real**, because memory does not time-slice.
//!
//! **And the two guest kinds do not commit memory the same way:**
//!
//! * A **QEMU VM** *reserves* its memory. It is gone from the node whether the
//!   guest touches it or not.
//! * An **LXC** memory value is a cgroup *cap*, not a reservation. Ten
//!   containers capped at 8 GiB each on a 32 GiB node is fine if they idle at
//!   500 MiB.
//!
//! So this reports two separate numbers. *Reserved* (VMs alone) crossing the
//! node's physical memory is the dangerous one — it cannot be reclaimed by
//! anything. *Total commitment* (VMs + LXC caps) crossing it means the node
//! works only as long as the containers stay under their caps: real, worth
//! knowing, not an emergency.
//!
//! No repair. Resizing a guest is a capacity decision with a blast radius —
//! orca reports the number and lets a human choose. See [`finding_*`].

use crate::GuestKind;
use crate::generated::{self, types as gtypes};
use crate::tools::for_each_enabled_endpoint;
use plugin_toolkit::contract::diagnostics::{Finding, Severity};
use std::collections::HashMap;

/// Reserved (VM) memory at or above this share of physical is `Crit`: VM memory
/// cannot be reclaimed, so there is no headroom left for anything.
pub const RESERVED_CRIT_PCT: f64 = 90.0;

/// Total commitment (VM reserved + LXC caps) above this share of physical is
/// `Warn`. 100% is the honest line — past it the node only survives because
/// containers are under their caps.
pub const TOTAL_COMMIT_WARN_PCT: f64 = 100.0;

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

fn gib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0 * 1024.0)
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
    if c.reserved_pct() >= RESERVED_CRIT_PCT {
        out.push(finding_reserved(c));
    }
    if c.total_pct() > TOTAL_COMMIT_WARN_PCT {
        out.push(finding_total(c));
    }
    if c.vcpu_ratio() > VCPU_RATIO_INFO {
        out.push(finding_vcpu(c));
    }
    out
}

fn finding_reserved(c: &Commitment) -> Finding {
    Finding {
        id: format!("capacity-reserved::{}", c.node),
        provider: PROVIDER.to_string(),
        severity: Severity::Crit,
        title: format!(
            "PVE node '{}' has {:.0}% of its memory reserved by VMs",
            c.node,
            c.reserved_pct()
        ),
        detail: format!(
            "Running QEMU VMs on node '{}' reserve {:.1} GiB of its {:.1} GiB physical memory \
             ({:.0}%). VM memory is a hard reservation — unlike an LXC cap it is consumed whether \
             the guest touches it or not, and the node cannot reclaim it under pressure. At this \
             level there is effectively no headroom left for the host itself, for LXC guests, or \
             for a migration onto this node. If the node has no swap, the next spike is an \
             OOM kill with no warning. Reduce a VM's memory, move one to another node, or convert \
             it to an LXC so its memory becomes a cap instead of a reservation.",
            c.node,
            gib(c.reserved_mem_bytes),
            gib(c.phys_mem_bytes),
            c.reserved_pct()
        ),
        // Resizing or relocating a guest is a capacity decision with real blast
        // radius. Report the number; let a human choose.
        repair: None,
    }
}

fn finding_total(c: &Commitment) -> Finding {
    Finding {
        id: format!("capacity-commit::{}", c.node),
        provider: PROVIDER.to_string(),
        severity: Severity::Warn,
        title: format!(
            "PVE node '{}' is over-allocated: {:.0}% of memory committed",
            c.node,
            c.total_pct()
        ),
        detail: format!(
            "Node '{}' has {:.1} GiB committed across {} running guests but only {:.1} GiB \
             physically ({:.0}%). That splits into {:.1} GiB reserved by QEMU VMs and {:.1} GiB \
             of LXC memory caps. This is not necessarily broken: LXC memory is a cgroup cap, not \
             a reservation, so the node stays healthy as long as the containers sit under their \
             caps. It does mean there is no headroom — if the containers ever claim what they are \
             allowed, the node is short, and with no swap that surfaces as an OOM kill rather \
             than as slowness. Either right-size the caps to what the guests actually use, or \
             move a guest to a node with room.",
            c.node,
            gib(c.total_mem_bytes()),
            c.guest_count,
            gib(c.phys_mem_bytes),
            c.total_pct(),
            gib(c.reserved_mem_bytes),
            gib(c.capped_mem_bytes)
        ),
        repair: None,
    }
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
        let http = cfg.build_reqwest_client()?;
        let client = generated::Client::new_with_client(&cfg.base_url, http);
        let items = client
            .get_resources_cluster_resources(None)
            .await
            .map_err(|e| anyhow::anyhow!("cluster resources: {e}"))?
            .into_inner();

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
    items: Vec<gtypes::GetResourcesClusterResourcesResponseItem>,
) -> (Vec<NodeCapacity>, HashMap<String, Vec<GuestAlloc>>) {
    use gtypes::GetResourcesClusterResourcesResponseItemType as Kind;

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

    /// The real shape that motivated this check (measured 2026-09-22): thor,
    /// 20 cores / 31.1 GiB, committing 34 GiB. Over-committed in total, but
    /// only 21 GiB of that is VM-reserved — so it warns, it does not crit.
    #[test]
    fn thor_warns_on_total_commit_but_not_on_reserved() {
        let n = node("thor", 31.1, 20.0);
        let guests = vec![
            vm("freyr", 12.0, 8.0),
            vm("haos-17.1", 3.0, 2.0),
            vm("proxmox-backup-server", 6.0, 2.0),
            ct("mimir", 8.0, 6.0),
            ct("unifi", 3.0, 2.0),
            ct("zwave-js-ui", 1.0, 2.0),
            ct("mqtt", 0.5, 1.0),
            ct("alpine-zigbee2mqtt", 0.5, 1.0),
        ];
        let c = assess(&n, &guests);

        assert!(
            c.total_pct() > 100.0,
            "expected over-commit, got {:.1}%",
            c.total_pct()
        );
        assert!(
            c.reserved_pct() < RESERVED_CRIT_PCT,
            "VM-reserved is only 21 GiB of 31 — must not crit, got {:.1}%",
            c.reserved_pct()
        );

        let f = findings_for(&c);
        assert_eq!(f.len(), 1, "exactly one finding expected: {f:#?}");
        assert_eq!(f[0].severity, Severity::Warn);
        assert_eq!(f[0].id, "capacity-commit::thor");
        // The split is the point of the message — both halves must be stated.
        assert!(f[0].detail.contains("reserved by QEMU VMs"));
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

    /// VMs alone eating the node is the dangerous case — unreclaimable.
    #[test]
    fn vm_reserved_at_or_above_threshold_is_crit() {
        let n = node("tight", 32.0, 16.0);
        let c = assess(&n, &[vm("hog", 30.0, 4.0)]);

        assert!(c.reserved_pct() >= RESERVED_CRIT_PCT);
        let f = findings_for(&c);
        assert_eq!(f[0].severity, Severity::Crit);
        assert_eq!(f[0].id, "capacity-reserved::tight");
        assert!(f[0].detail.contains("hard reservation"));
    }

    /// The same memory total is a crit as VMs and silent as containers. This is
    /// the distinction the whole module exists for.
    #[test]
    fn identical_memory_totals_differ_by_guest_kind() {
        let n = node("n", 32.0, 16.0);
        let as_vms = findings_for(&assess(&n, &[vm("a", 15.0, 2.0), vm("b", 15.0, 2.0)]));
        let as_cts = findings_for(&assess(&n, &[ct("a", 15.0, 2.0), ct("b", 15.0, 2.0)]));

        assert_eq!(as_vms.len(), 1);
        assert_eq!(as_vms[0].severity, Severity::Crit);
        assert!(
            as_cts.is_empty(),
            "30 GiB of LXC *caps* on 32 GiB is not over-committed: {as_cts:#?}"
        );
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
