//! Parse LXC mountpoint entries into [`plugin_toolkit::mount_audit::MountSpec`].
//!
//! The fact-gathering half of orca#563 Gap 3. orca owns the judgement — whether
//! an uncapped bind mount on the hypervisor root means "a guest can fill the
//! host" is a severity rule that must not be reimplemented per plugin — but only
//! a node-local plugin can gather the facts: the `mp` lines in
//! `/etc/pve/lxc/<vmid>.conf`, and whether a mount's host source shares a
//! filesystem with `/`.
//!
//! That last one is the whole point of the check. A bind mount cannot be
//! quota'd, so a guest writes straight into the host filesystem bounded only by
//! its free space. frigg CT113 carries
//! `mp2: /srv/jellyfin-transcode,mp=/transcode` with no cap, and
//! `/srv/jellyfin-transcode` lives on `pve-root` — so one long transcode does not
//! fill a container, it fills the hypervisor and takes down every guest on the
//! node. It measures 0 bytes at rest, which is exactly why no level-based check
//! has ever flagged it.

use std::os::unix::fs::MetadataExt;

use plugin_toolkit::mount_audit::{MountKind, MountSpec};

/// One parsed `mp<N>:` entry, before the host-filesystem comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMount {
    /// Config key (`mp0`, `mp2`, …), used to build the reported id.
    pub key: String,
    /// The volume field: a host path for a bind mount, `storage:volume`
    /// otherwise.
    pub source: String,
    /// In-guest mountpoint from `mp=`.
    pub target: String,
    /// `size=` in bytes when present. Absent on bind mounts, which cannot carry
    /// one — that absence is the risk the audit classifies.
    pub size_bytes: Option<u64>,
    /// `ro=1`.
    pub read_only: bool,
}

/// Parse a Proxmox size suffix (`32G`, `512M`, `1T`, bare bytes) into bytes.
///
/// Returns `None` for anything unrecognised rather than guessing: a
/// misparsed cap would report a capped mount as unbounded and cry wolf, and a
/// wolf-crying check is one an operator learns to ignore.
fn parse_size(v: &str) -> Option<u64> {
    let v = v.trim();
    let (num, mult) = match v.chars().last()? {
        'T' | 't' => (&v[..v.len() - 1], 1u64 << 40),
        'G' | 'g' => (&v[..v.len() - 1], 1u64 << 30),
        'M' | 'm' => (&v[..v.len() - 1], 1u64 << 20),
        'K' | 'k' => (&v[..v.len() - 1], 1u64 << 10),
        '0'..='9' => (v, 1),
        _ => return None,
    };
    num.trim().parse::<f64>().ok().and_then(|n| {
        if n.is_finite() && n >= 0.0 {
            Some((n * mult as f64) as u64)
        } else {
            None
        }
    })
}

/// Extract every `mp<N>:` mountpoint from an `/etc/pve/lxc/<vmid>.conf`.
///
/// Format: `mp0: <volume>,mp=/in/guest,size=32G,ro=1,...` — comma-separated
/// `key=value` options after the volume, which is positional and first.
/// `rootfs:` is deliberately NOT included: it always has its own volume and size,
/// so it is not the unbounded-scratch shape.
pub fn parse_mountpoints(conf: &str) -> Vec<RawMount> {
    let mut out = Vec::new();
    for line in conf.lines() {
        let line = line.trim();
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        // `mp` followed by digits only — never `mp_something`, and never rootfs.
        if !(key.starts_with("mp") && key.len() > 2 && key[2..].chars().all(|c| c.is_ascii_digit()))
        {
            continue;
        }
        let mut parts = rest.trim().split(',');
        let Some(source) = parts.next().map(str::trim) else {
            continue;
        };
        if source.is_empty() {
            continue;
        }
        let mut target = String::new();
        let mut size_bytes = None;
        let mut read_only = false;
        for opt in parts {
            let Some((k, v)) = opt.split_once('=') else {
                continue;
            };
            match k.trim() {
                "mp" => target = v.trim().to_string(),
                "size" => size_bytes = parse_size(v),
                "ro" => read_only = v.trim() == "1",
                _ => {}
            }
        }
        // No `mp=` means no in-guest mountpoint; not a usable entry to report.
        if target.is_empty() {
            continue;
        }
        out.push(RawMount {
            key: key.to_string(),
            source: source.to_string(),
            target,
            size_bytes,
            read_only,
        });
    }
    out
}

/// Classify how a mount is backed, from its volume field.
///
/// A leading `/` is a host bind mount. Anything of the form `storage:volume` is a
/// managed volume, which bounds itself. Network shares reach a guest through a
/// host mount (so they appear as binds); the audit treats bind-on-network as a
/// bind, which is correct — the bound resource is the host's mountpoint.
pub fn kind_of(source: &str) -> MountKind {
    if source.starts_with('/') {
        MountKind::Bind
    } else if source.contains(':') {
        MountKind::Volume
    } else {
        // Neither a path nor `storage:volume` — unrecognised. Volume is the
        // conservative call: it yields no unbounded finding, so an unparsed
        // format stays silent instead of inventing an alert.
        MountKind::Volume
    }
}

/// Device id of the filesystem hosting `path`, following symlinks.
fn dev_of(path: &str) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.dev())
}

/// Build the audit input for one guest.
///
/// `root_dev` is the device of the node's `/`, passed in so a caller stats it
/// once per sweep rather than per mount, and so tests can drive the comparison
/// without touching a real filesystem.
///
/// A source that cannot be stat'ed yields `on_host_root_fs: false` — unknown must
/// not be reported as the most severe case. `consumed` is always `None`: this
/// plugin cannot tell whether anything inside a guest reads a mount, and orca's
/// audit reports unused only on `Some(false)`, so `None` correctly stays silent.
pub fn specs_for_guest(vmid: u64, conf: &str, root_dev: Option<u64>) -> Vec<MountSpec> {
    parse_mountpoints(conf)
        .into_iter()
        .map(|m| {
            let kind = kind_of(&m.source);
            let on_host_root_fs = kind == MountKind::Bind
                && match (root_dev, dev_of(&m.source)) {
                    (Some(r), Some(d)) => r == d,
                    _ => false,
                };
            MountSpec {
                id: format!("{vmid}:{}", m.key),
                source: m.source,
                target: m.target,
                kind,
                size_limit_bytes: m.size_bytes,
                read_only: m.read_only,
                on_host_root_fs,
                consumed: None,
            }
        })
        .collect()
}

/// Device of the node root, for [`specs_for_guest`].
pub fn root_device() -> Option<u64> {
    dev_of("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// frigg CT113, verbatim from the node.
    const CT113: &str = "\
arch: amd64
hostname: jellyfin
memory: 8192
mp0: /mnt/backups/jellyfin,mp=/mnt/backups
mp1: /mnt/data,mp=/mnt/data
mp2: /srv/jellyfin-transcode,mp=/transcode
rootfs: local-lvm:vm-113-disk-0,size=64G,mountoptions=discard
";

    #[test]
    fn parses_the_real_ct113_mountpoints_and_skips_rootfs() {
        let got = parse_mountpoints(CT113);
        assert_eq!(got.len(), 3, "rootfs must not be included: {got:?}");
        assert_eq!(got[2].key, "mp2");
        assert_eq!(got[2].source, "/srv/jellyfin-transcode");
        assert_eq!(got[2].target, "/transcode");
        assert_eq!(got[2].size_bytes, None, "the missing cap IS the defect");
        assert!(!got[2].read_only);
    }

    /// The severity hinge: same mount, on the node root vs elsewhere.
    #[test]
    fn a_bind_mount_on_the_root_device_is_marked_and_off_it_is_not() {
        // `/` is guaranteed to exist and stat, in any test environment.
        let root = dev_of("/").expect("root must stat");
        let conf = "mp0: /,mp=/host-root\n";
        let on = specs_for_guest(113, conf, Some(root));
        assert!(on[0].on_host_root_fs, "source IS the root fs");

        // A deliberately wrong root device: same mount must not be flagged.
        let off = specs_for_guest(113, conf, Some(root.wrapping_add(1)));
        assert!(!off[0].on_host_root_fs);
    }

    /// Unknown must not become the most severe case.
    #[test]
    fn an_unstattable_source_is_not_assumed_to_be_on_the_root_fs() {
        let conf = "mp0: /nonexistent/path/that/cannot/exist,mp=/x\n";
        let got = specs_for_guest(1, conf, dev_of("/"));
        assert!(!got[0].on_host_root_fs);
        // And it is still reported as a bind mount, so the uncapped finding holds.
        assert_eq!(got[0].kind, MountKind::Bind);
    }

    #[test]
    fn a_managed_volume_is_not_a_bind_mount() {
        let conf = "mp0: local-lvm:vm-113-disk-1,mp=/data,size=32G\n";
        let got = specs_for_guest(113, conf, dev_of("/"));
        assert_eq!(got[0].kind, MountKind::Volume);
        assert_eq!(got[0].size_limit_bytes, Some(32 << 30));
        assert!(
            !got[0].on_host_root_fs,
            "a volume is never host-root scratch"
        );
    }

    #[test]
    fn read_only_and_size_options_are_parsed() {
        let conf = "mp0: /mnt/data,mp=/mnt/data,ro=1\nmp1: /srv/x,mp=/x,size=512M\n";
        let got = parse_mountpoints(conf);
        assert!(got[0].read_only);
        assert_eq!(got[0].size_bytes, None);
        assert!(!got[1].read_only);
        assert_eq!(got[1].size_bytes, Some(512 << 20));
    }

    #[test]
    fn size_suffixes_parse_and_junk_does_not() {
        assert_eq!(parse_size("1T"), Some(1 << 40));
        assert_eq!(parse_size("32G"), Some(32 << 30));
        assert_eq!(parse_size("512M"), Some(512 << 20));
        assert_eq!(parse_size("8k"), Some(8 << 10));
        assert_eq!(parse_size("4096"), Some(4096));
        // Unrecognised must be None, not a wrong number — a misparsed cap would
        // report a capped mount as unbounded.
        assert_eq!(parse_size("lots"), None);
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("G"), None);
    }

    /// `mp` must match only `mp<digits>`, never a lookalike key.
    #[test]
    fn only_numbered_mp_keys_are_mountpoints() {
        let conf = "\
mp: /a,mp=/a
mpx: /b,mp=/b
mp_extra: /c,mp=/c
lxc.mount.entry: tmpfs dev/shm tmpfs size=6g 0 0
mp10: /d,mp=/d
";
        let got = parse_mountpoints(conf);
        assert_eq!(got.len(), 1, "got {got:?}");
        assert_eq!(got[0].key, "mp10");
    }

    #[test]
    fn an_entry_without_an_in_guest_mountpoint_is_skipped() {
        assert_eq!(parse_mountpoints("mp0: /srv/x\n"), vec![]);
        assert_eq!(parse_mountpoints("mp0: ,mp=/x\n"), vec![]);
    }

    #[test]
    fn a_conf_with_no_mountpoints_yields_nothing() {
        assert_eq!(parse_mountpoints("arch: amd64\nmemory: 512\n"), vec![]);
        assert_eq!(parse_mountpoints(""), vec![]);
    }

    /// End-to-end through orca's classifier: the CT113 shape must come out as the
    /// top risk once the root-device comparison says so.
    #[test]
    fn the_ct113_transcode_mount_classifies_as_the_top_risk() {
        use plugin_toolkit::mount_audit::{Risk, audit};
        let root = dev_of("/").expect("root must stat");
        // Model the node condition: the scratch source sits on the root fs.
        let conf = "mp2: /,mp=/transcode\n";
        let findings = audit(&specs_for_guest(113, conf, Some(root)));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, Risk::UnboundedOnHostRootFs);
        assert_eq!(findings[0].id, "113:mp2");
    }

    /// The read-only shares (CT113 mp0/mp1 style) must not produce noise, or the
    /// check fires on nearly every guest the fleet has.
    #[test]
    fn capped_and_readonly_mounts_produce_no_findings() {
        use plugin_toolkit::mount_audit::audit;
        let conf = "mp0: /mnt/data,mp=/mnt/data,ro=1\nmp1: local-lvm:vm-1-disk-1,mp=/d,size=8G\n";
        assert_eq!(audit(&specs_for_guest(1, conf, dev_of("/"))), vec![]);
    }
}
