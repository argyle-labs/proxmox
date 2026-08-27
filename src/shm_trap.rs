//! LXC shm-trap detection — a `diagnostics` finding for the "tmpfs bigger than
//! the memory cgroup" misconfiguration that OOM-kills whatever runs in the CT.
//!
//! A Proxmox LXC gets a memory cgroup limit (`memory: N` MB). Any tmpfs mount
//! inside the CT — most commonly `/dev/shm`, declared as a raw
//! `lxc.mount.entry: tmpfs dev/shm tmpfs ... size=Ng` — is charged against that
//! same cgroup. When a tmpfs is sized LARGER than the memory limit, filling it
//! (e.g. a Plex/Jellyfin transcode writing segments to `/dev/shm`) pushes the
//! CT past its cgroup limit and the kernel OOM-kills the process, which the
//! service supervisor then restarts: a crash-loop. See
//! [[media-lxc-shm-tmpfs-exceeds-cgroup-oom-trap]] (mimir/njord/jellyfin,
//! 2026-08-19).
//!
//! Detection is pure and node-local: parse `/etc/pve/lxc/<vmid>.conf` for the
//! `memory:` cap and every `lxc.mount.entry` tmpfs `size=`, and flag any tmpfs
//! whose size alone meets or exceeds the cap (it can never be filled without
//! OOM). The raw `lxc.mount.entry` lines are NOT exposed by the PVE config API,
//! so this reads the conf file directly — which only works on a cluster node
//! (`/etc/pve` is the shared pmxcfs mount).
//!
//! Not covered here: a `mp*` bind-mount whose HOST source is a tmpfs (e.g.
//! jellyfin's `mp2: /srv/jellyfin-transcode`). That can't be judged from the CT
//! conf alone — the host mount table is needed — so it's out of scope for this
//! pure check.

/// A tmpfs mount declared in an LXC config, with its ceiling in MiB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmpfsMount {
    /// Mount target as written in the conf (e.g. `dev/shm`).
    pub target: String,
    /// Declared `size=` ceiling, in MiB.
    pub size_mb: u64,
}

/// The memory-relevant slice of an LXC config.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LxcMemProfile {
    /// `memory:` cgroup limit in MiB, if present.
    pub memory_mb: Option<u64>,
    /// Every `lxc.mount.entry` tmpfs with a `size=`.
    pub tmpfs: Vec<TmpfsMount>,
}

/// One detected trap: a tmpfs sized at/over the CT's memory cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShmTrap {
    pub target: String,
    pub tmpfs_mb: u64,
    pub memory_mb: u64,
}

/// Parse a `size=` value like `6g`, `512m`, `1024k`, or a bare byte count into
/// MiB (rounded down; a sub-MiB size floors to 0). Returns `None` if the value
/// can't be parsed.
fn parse_size_mb(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (num, mult): (&str, u64) = match raw.chars().last().unwrap().to_ascii_lowercase() {
        'g' => (&raw[..raw.len() - 1], 1024),
        'm' => (&raw[..raw.len() - 1], 1),
        'k' => return raw[..raw.len() - 1].parse::<u64>().ok().map(|k| k / 1024),
        c if c.is_ascii_digit() => (raw, 0), // bare bytes
        _ => return None,
    };
    if mult == 0 {
        // bare byte count
        return num.parse::<u64>().ok().map(|b| b / (1024 * 1024));
    }
    num.parse::<u64>().ok().map(|n| n * mult)
}

/// Extract the `size=` field from a tmpfs `lxc.mount.entry` option list.
/// e.g. `nodev,nosuid,size=6g,mode=1777,create=dir` → `Some(6144)`.
fn tmpfs_size_from_opts(opts: &str) -> Option<u64> {
    opts.split(',')
        .find_map(|kv| kv.trim().strip_prefix("size="))
        .and_then(parse_size_mb)
}

/// Parse the memory cap + tmpfs mounts out of an `/etc/pve/lxc/<vmid>.conf`.
///
/// The `memory:` key is MiB. A tmpfs mount looks like:
/// `lxc.mount.entry: tmpfs dev/shm tmpfs nodev,nosuid,size=6g,... 0 0`
/// — fields after `lxc.mount.entry:` are: fs_spec, mountpoint, fstype, options,
/// dump, pass. We only record entries with fstype `tmpfs` AND a `size=`.
pub fn parse_lxc_conf(conf: &str) -> LxcMemProfile {
    let mut profile = LxcMemProfile::default();
    for line in conf.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("memory:") {
            profile.memory_mb = v.trim().parse::<u64>().ok();
            continue;
        }
        let Some(entry) = line.strip_prefix("lxc.mount.entry:") else {
            continue;
        };
        let f: Vec<&str> = entry.split_whitespace().collect();
        // fs_spec, mountpoint, fstype, options, ...
        if f.len() >= 4
            && f[0] == "tmpfs"
            && f[2] == "tmpfs"
            && let Some(size_mb) = tmpfs_size_from_opts(f[3])
        {
            profile.tmpfs.push(TmpfsMount {
                target: f[1].to_string(),
                size_mb,
            });
        }
    }
    profile
}

/// Classify a profile into any shm-traps: tmpfs mounts whose ceiling meets or
/// exceeds the memory cap. A tmpfs == the cap is already a trap (filling it
/// leaves zero headroom for the process itself → OOM), so the test is `>=`.
/// With no `memory:` cap (unlimited) there is no trap.
pub fn classify_traps(profile: &LxcMemProfile) -> Vec<ShmTrap> {
    let Some(mem) = profile.memory_mb else {
        return Vec::new();
    };
    profile
        .tmpfs
        .iter()
        .filter(|t| t.size_mb >= mem)
        .map(|t| ShmTrap {
            target: t.target.clone(),
            tmpfs_mb: t.size_mb,
            memory_mb: mem,
        })
        .collect()
}

/// Suggested safe tmpfs size for a trap: leave headroom for the process. Half
/// the memory cap, floored at 256 MiB, never above `mem - 256`. This is the
/// value the repair rewrites `size=` to.
pub fn suggested_shm_mb(memory_mb: u64) -> u64 {
    let half = memory_mb / 2;
    let ceiling = memory_mb.saturating_sub(256);
    half.clamp(256, ceiling.max(256))
}

/// Rewrite the `size=` of the tmpfs `lxc.mount.entry` whose mountpoint is
/// `target`, to `new_mb` MiB (emitted as `<n>m`). Returns the new conf text and
/// whether anything changed. Only the matching tmpfs line is touched; all other
/// lines are preserved byte-for-byte.
pub fn rewrite_tmpfs_size(conf: &str, target: &str, new_mb: u64) -> (String, bool) {
    let mut changed = false;
    let mut out = String::with_capacity(conf.len());
    for line in conf.lines() {
        let trimmed = line.trim();
        let is_match = trimmed
            .strip_prefix("lxc.mount.entry:")
            .map(|e| {
                let f: Vec<&str> = e.split_whitespace().collect();
                f.len() >= 4 && f[0] == "tmpfs" && f[1] == target && f[2] == "tmpfs"
            })
            .unwrap_or(false);
        if is_match && line.contains("size=") {
            let rewritten = rewrite_size_opt(line, new_mb);
            changed |= rewritten != line;
            out.push_str(&rewritten);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    (out, changed)
}

/// Replace the `size=<val>` value in a single line with `<new_mb>m`, in place.
/// `size=` can sit anywhere in the line (it's inside the space-delimited option
/// field, e.g. `... tmpfs size=6g,mode=1777 0 0`), so match on the substring
/// and rewrite only the value token (up to the next `,` or whitespace).
fn rewrite_size_opt(line: &str, new_mb: u64) -> String {
    let Some(idx) = line.find("size=") else {
        return line.to_string();
    };
    let val_start = idx + "size=".len();
    let rest = &line[val_start..];
    let val_len = rest
        .find(|c: char| c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    format!("{}{new_mb}m{}", &line[..val_start], &rest[val_len..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_parsing_handles_units_and_bytes() {
        assert_eq!(parse_size_mb("6g"), Some(6144));
        assert_eq!(parse_size_mb("512m"), Some(512));
        assert_eq!(parse_size_mb("1048576k"), Some(1024));
        assert_eq!(parse_size_mb("2G"), Some(2048));
        assert_eq!(parse_size_mb("1073741824"), Some(1024)); // bare bytes
        assert_eq!(parse_size_mb("bogus"), None);
        assert_eq!(parse_size_mb(""), None);
    }

    #[test]
    fn size_field_extracted_from_option_list() {
        assert_eq!(
            tmpfs_size_from_opts("nodev,nosuid,size=6g,mode=1777,create=dir"),
            Some(6144)
        );
        assert_eq!(tmpfs_size_from_opts("nodev,nosuid,mode=1777"), None);
    }

    // mimir CT110 as it actually was on 2026-08-19: 6 GiB /dev/shm in a 4 GiB CT.
    const MIMIR_CONF: &str = "\
arch: amd64
cores: 6
memory: 4096
swap: 512
rootfs: local-lvm:vm-110-disk-0,size=32G
lxc.mount.entry: tmpfs dev/shm tmpfs nodev,nosuid,size=6g,mode=1777,create=dir 0 0
";

    #[test]
    fn parses_mimir_and_flags_the_trap() {
        let p = parse_lxc_conf(MIMIR_CONF);
        assert_eq!(p.memory_mb, Some(4096));
        assert_eq!(
            p.tmpfs,
            vec![TmpfsMount {
                target: "dev/shm".into(),
                size_mb: 6144
            }]
        );
        let traps = classify_traps(&p);
        assert_eq!(traps.len(), 1);
        assert_eq!(traps[0].target, "dev/shm");
        assert_eq!((traps[0].tmpfs_mb, traps[0].memory_mb), (6144, 4096));
    }

    #[test]
    fn njord_ratio_is_worse_but_same_trap() {
        // njord CT115: 4 GiB shm in a 2 GiB CT.
        let conf = "memory: 2048\n\
            lxc.mount.entry: tmpfs dev/shm tmpfs nodev,nosuid,size=4g,mode=1777,create=dir 0 0\n";
        let traps = classify_traps(&parse_lxc_conf(conf));
        assert_eq!(traps.len(), 1);
        assert_eq!(traps[0].tmpfs_mb, 4096);
    }

    #[test]
    fn healthy_config_has_no_trap() {
        // shm sized under the cap → fine.
        let conf = "memory: 8192\n\
            lxc.mount.entry: tmpfs dev/shm tmpfs nodev,nosuid,size=4g,mode=1777,create=dir 0 0\n";
        assert!(classify_traps(&parse_lxc_conf(conf)).is_empty());
    }

    #[test]
    fn tmpfs_equal_to_cap_is_a_trap() {
        // Equal leaves zero headroom for the process itself.
        let conf = "memory: 4096\n\
            lxc.mount.entry: tmpfs dev/shm tmpfs size=4g,mode=1777 0 0\n";
        assert_eq!(classify_traps(&parse_lxc_conf(conf)).len(), 1);
    }

    #[test]
    fn no_memory_cap_means_no_trap() {
        let conf = "lxc.mount.entry: tmpfs dev/shm tmpfs size=64g 0 0\n";
        assert!(classify_traps(&parse_lxc_conf(conf)).is_empty());
    }

    #[test]
    fn suggested_size_leaves_headroom() {
        assert_eq!(suggested_shm_mb(8192), 4096);
        assert_eq!(suggested_shm_mb(4096), 2048);
        assert_eq!(suggested_shm_mb(1024), 512);
        // tiny CT: never below 256, never above mem-256
        assert_eq!(suggested_shm_mb(512), 256);
    }

    #[test]
    fn rewrite_resizes_only_the_matching_tmpfs_line() {
        let (out, changed) = rewrite_tmpfs_size(MIMIR_CONF, "dev/shm", 2048);
        assert!(changed);
        assert!(out.contains("size=2048m"));
        assert!(!out.contains("size=6g"));
        // untouched lines preserved
        assert!(out.contains("memory: 4096"));
        assert!(out.contains("rootfs: local-lvm:vm-110-disk-0,size=32G"));
        // idempotent: re-running finds nothing to change
        let (_, changed2) = rewrite_tmpfs_size(&out, "dev/shm", 2048);
        assert!(!changed2);
    }

    #[test]
    fn rewrite_leaves_other_tmpfs_targets_alone() {
        let conf = "memory: 4096\n\
            lxc.mount.entry: tmpfs dev/shm tmpfs size=6g,mode=1777 0 0\n\
            lxc.mount.entry: tmpfs run tmpfs size=1g 0 0\n";
        let (out, _) = rewrite_tmpfs_size(conf, "dev/shm", 2048);
        assert!(out.contains("tmpfs dev/shm tmpfs size=2048m,mode=1777"));
        assert!(out.contains("tmpfs run tmpfs size=1g")); // untouched
    }
}
