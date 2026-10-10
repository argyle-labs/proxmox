//! Planning a guest replacement: which settings of the old guest a new one
//! inherits. Identity (vmid, name), storage volumes, and generated
//! per-instance values stay with each guest; settings that define what the
//! guest is for carry over. Moving users, groups, and in-guest data is a
//! later slice.

use std::collections::BTreeMap;

use plugin_toolkit::prelude::*;

/// Keys never copied: identity, per-instance values, and storage the new guest
/// gets its own copy of.
const KEEP_OWN: &[&str] = &[
    "digest",
    "name",
    "hostname",
    "vmgenid",
    "smbios1",
    "meta",
    "lock",
    "parent",
    "template",
    "rootfs",
    "unprivileged",
    "ostype",
    "arch",
];

/// Prefixes of indexed keys never copied: disks and unused volumes.
const KEEP_OWN_PREFIX: &[&str] = &[
    "unused", "scsi", "sata", "ide", "virtio", "efidisk", "tpmstate",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CarryPlan {
    /// Settings to write to the new guest.
    pub copy: BTreeMap<String, String>,
    /// Settings the new guest keeps for itself; listed so nothing is dropped silently.
    pub skipped: Vec<String>,
    /// `mpN` values that point at a guest volume, not a host path. They need
    /// a data move, not a config copy.
    pub volumes_to_move: Vec<String>,
}

fn keep_own(key: &str) -> bool {
    KEEP_OWN.contains(&key)
        || KEEP_OWN_PREFIX.iter().any(|p| {
            key.strip_prefix(p)
                .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
        })
}

/// `net*` values with the MAC removed (LXC `hwaddr=`, QEMU `model=MAC`), so
/// PVE generates a new one.
fn without_mac(value: &str) -> String {
    value
        .split(',')
        .filter_map(|p| match p.split_once('=') {
            Some(("hwaddr", _)) => None,
            Some((model, mac)) if mac.len() == 17 && mac.matches(':').count() == 5 => {
                Some(model.to_string())
            }
            _ => Some(p.to_string()),
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn carry_over(old: &BTreeMap<String, String>) -> CarryPlan {
    let mut plan = CarryPlan {
        copy: BTreeMap::new(),
        skipped: Vec::new(),
        volumes_to_move: Vec::new(),
    };
    for (k, v) in old {
        if keep_own(k) {
            plan.skipped.push(k.clone());
        } else if k.starts_with("mp") && !v.starts_with('/') {
            plan.volumes_to_move.push(k.clone());
        } else if k.starts_with("net") {
            plan.copy.insert(k.clone(), without_mac(v));
        } else {
            plan.copy.insert(k.clone(), v.clone());
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_purpose_skips_identity_and_routes_volumes_to_a_move() {
        let old: BTreeMap<String, String> = [
            ("hostname", "freyr"),
            ("cores", "4"),
            ("memory", "8192"),
            (
                "net0",
                "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=dhcp",
            ),
            ("mp0", "/mnt/media,mp=/media"),
            ("mp1", "local-lvm:vm-102-disk-1,mp=/data,size=50G"),
            ("rootfs", "local-lvm:vm-102-disk-0,size=8G"),
            ("unused0", "local-lvm:vm-102-disk-2"),
            ("tags", "media"),
            ("digest", "abc"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let p = carry_over(&old);
        assert_eq!(p.copy["net0"], "name=eth0,bridge=vmbr0,ip=dhcp");
        assert_eq!(p.copy["mp0"], "/mnt/media,mp=/media");
        assert_eq!(p.copy["cores"], "4");
        assert!(p.copy.contains_key("tags"));
        assert_eq!(p.volumes_to_move, vec!["mp1".to_string()]);
        assert_eq!(p.skipped, vec!["digest", "hostname", "rootfs", "unused0"]);
    }

    #[test]
    fn qemu_disks_stay_and_netmodel_mac_is_dropped() {
        assert!(keep_own("scsi0") && keep_own("efidisk0") && !keep_own("scsihw"));
        assert_eq!(
            without_mac("virtio=BC:24:11:00:00:01,bridge=vmbr0"),
            "virtio,bridge=vmbr0"
        );
    }
}
