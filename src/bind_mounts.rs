//! LXC app state that vzdump misses.
//!
//! vzdump (and so PBS) never includes an LXC bind mount (`mpN: /host/path,…`),
//! and includes a volume mount only with `backup=1`. An app whose live state
//! sits in a bind mount therefore has no backup at all, however healthy its
//! vzdump job looks: zigbee2mqtt's live `/etc/zigbee2mqtt` is a bind mount,
//! while the `/opt/zigbee2mqtt/data` inside the rootfs is stale.
//!
//! This module:
//!
//! * resolves every `mpN` of a container from its config (node-local, from
//!   `/etc/pve/lxc/<vmid>.conf`, where the bind sources are host paths);
//! * maps the container to an app through [`APP_PROFILES`] and locates each of
//!   the app's data paths: rootfs, a volume mount, or a bind mount;
//! * assigns each a [`Method`]. Data in a bind mount is always
//!   [`Method::HostCapture`], never [`Method::Vzdump`], the only method that can
//!   land on PBS;
//! * contributes the `lxc-bind` backup kind, which copies those host paths, and
//!   the `bind-uncovered` diagnostic.
//!
//! Reading a bind source usually needs root (container-owned files map to
//! uid 100000+). [`HostTree`] is the seam: [`UnprivilegedTree`] copies what the
//! plugin user can read and fails naming orca#762 (the privileged host-read
//! seam) on anything it cannot.

use std::path::{Path, PathBuf};

use plugin_toolkit::contract::diagnostics::{Finding, Severity};
use plugin_toolkit::prelude::*;

use plugin_toolkit::mount_audit::MountKind;

use crate::mount_scan::{RawMount, kind_of, parse_mountpoints};

const PROVIDER: &str = "proxmox";
const PVE_LXC_DIR: &str = "/etc/pve/lxc";

/// Where one app keeps the state a backup must capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppProfile {
    pub app: &'static str,
    /// Lowercase substrings of the container's hostname that identify the app.
    pub matches: &'static [&'static str],
    /// In-container paths holding the app's state.
    pub data_paths: &'static [&'static str],
    pub note: Option<&'static str>,
}

/// Per-app data paths. First match wins, so a name that contains another
/// app's name (`zigbee2mqtt` contains `mqtt`) is listed first.
pub const APP_PROFILES: &[AppProfile] = &[
    AppProfile {
        app: "zigbee2mqtt",
        matches: &["zigbee2mqtt", "z2m"],
        data_paths: &["/etc/zigbee2mqtt"],
        note: Some("the live config is /etc/zigbee2mqtt; /opt/zigbee2mqtt/data is stale"),
    },
    AppProfile {
        app: "zwave-js-ui",
        matches: &["zwave"],
        data_paths: &["/var/lib/zwave-store"],
        note: None,
    },
    AppProfile {
        app: "plex",
        matches: &["plex"],
        data_paths: &[
            "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Plug-in Support/Databases",
            "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml",
        ],
        note: Some("metadata and cache under the Plex root are rebuildable and left out"),
    },
    AppProfile {
        app: "jellyfin",
        matches: &["jellyfin"],
        data_paths: &["/var/lib/jellyfin", "/etc/jellyfin"],
        note: None,
    },
    AppProfile {
        app: "gitea",
        matches: &["gitea"],
        data_paths: &["/var/lib/gitea", "/etc/gitea"],
        note: Some(
            "a file copy of a live instance is not transactionally consistent; `gitea dump` is",
        ),
    },
    AppProfile {
        app: "adguard",
        matches: &["adguard"],
        data_paths: &["/opt/AdGuardHome/AdGuardHome.yaml", "/opt/AdGuardHome/data"],
        note: None,
    },
    AppProfile {
        app: "caddy",
        matches: &["caddy"],
        data_paths: &["/etc/caddy", "/var/lib/caddy"],
        note: None,
    },
    AppProfile {
        app: "unifi",
        matches: &["unifi"],
        data_paths: &["/var/lib/unifi"],
        note: None,
    },
    AppProfile {
        app: "mosquitto",
        matches: &["mqtt", "mosquitto"],
        data_paths: &["/etc/mosquitto", "/var/lib/mosquitto"],
        note: None,
    },
];

pub fn app_for(hostname: &str) -> Option<&'static AppProfile> {
    let h = hostname.to_ascii_lowercase();
    APP_PROFILES
        .iter()
        .find(|p| p.matches.iter().any(|m| h.contains(m)))
}

/// Where a path lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Location {
    Rootfs,
    Volume {
        key: String,
        volid: String,
        /// `backup=1` is set, so vzdump includes it.
        in_vzdump: bool,
    },
    Bind {
        key: String,
        /// The path on the node that holds the data.
        host_path: String,
    },
}

/// How a path gets backed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// The guest's vzdump archive, to any backup storage including PBS.
    Vzdump,
    /// The `lxc-bind` kind copies the host path. Never PBS: PBS only receives
    /// vzdump archives, and vzdump skips bind mounts.
    HostCapture,
    /// Nothing captures it.
    Uncovered,
}

/// The only place a [`Location`] is mapped to a [`Method`].
pub fn method_for(loc: &Location) -> Method {
    match loc {
        Location::Rootfs => Method::Vzdump,
        Location::Volume {
            in_vzdump: true, ..
        } => Method::Vzdump,
        Location::Volume { .. } => Method::Uncovered,
        Location::Bind { .. } => Method::HostCapture,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DataPathPlan {
    pub path: String,
    pub location: Location,
    pub method: Method,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MountPlan {
    pub key: String,
    pub source: String,
    pub target: String,
    pub bind: bool,
    pub read_only: bool,
    /// App data paths inside this mount.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub app_paths: Vec<String>,
    /// `HostCapture` only when app state lives here; a bind with no known app
    /// state is bulk data and stays `Uncovered` (backups are config-only).
    pub method: Method,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GuestPlan {
    pub node: String,
    pub vmid: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub data_paths: Vec<DataPathPlan>,
    pub mounts: Vec<MountPlan>,
}

impl GuestPlan {
    /// The `(mount key, in-container path, host path)` the `lxc-bind` kind
    /// copies.
    pub fn host_captures(&self) -> Vec<(&str, &str, &str)> {
        self.data_paths
            .iter()
            .filter_map(|d| match &d.location {
                Location::Bind { key, host_path } => {
                    Some((key.as_str(), d.path.as_str(), host_path.as_str()))
                }
                _ => None,
            })
            .collect()
    }
}

/// `rest` of `path` below `mount`, comparing whole components.
fn below<'a>(path: &'a str, mount: &str) -> Option<&'a str> {
    let mount = mount.trim_end_matches('/');
    if mount.is_empty() {
        return Some(path.trim_start_matches('/'));
    }
    let rest = path.strip_prefix(mount)?;
    if rest.is_empty() {
        Some("")
    } else {
        rest.strip_prefix('/')
    }
}

/// Pure: where `path` lives given the container's mounts. The deepest mount
/// containing it wins, as it does in the container.
pub fn locate(path: &str, mounts: &[RawMount]) -> Location {
    let best = mounts
        .iter()
        .filter_map(|m| below(path, &m.target).map(|rest| (m, rest)))
        .max_by_key(|(m, _)| m.target.trim_end_matches('/').len());
    match best {
        None => Location::Rootfs,
        Some((m, rest)) if kind_of(&m.source) == MountKind::Bind => Location::Bind {
            key: m.key.clone(),
            host_path: if rest.is_empty() {
                m.source.clone()
            } else {
                format!("{}/{rest}", m.source.trim_end_matches('/'))
            },
        },
        Some((m, _)) => Location::Volume {
            key: m.key.clone(),
            volid: m.source.clone(),
            in_vzdump: m.backup,
        },
    }
}

fn hostname_of(conf: &str) -> Option<String> {
    conf.lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .find_map(|l| l.trim().strip_prefix("hostname:"))
        .map(|v| v.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Only the live config: `[snapshot]` and `[pve:pending]` sections follow it.
fn live_section(conf: &str) -> String {
    conf.lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Pure: the backup plan for one container from its config text.
pub fn plan_guest(node: &str, vmid: u64, conf: &str) -> GuestPlan {
    let mounts = parse_mountpoints(&live_section(conf));
    let name = hostname_of(conf).unwrap_or_else(|| format!("ct-{vmid}"));
    let profile = app_for(&name);
    let data_paths: Vec<DataPathPlan> = profile
        .map(|p| p.data_paths)
        .unwrap_or_default()
        .iter()
        .map(|path| {
            let location = locate(path, &mounts);
            DataPathPlan {
                path: path.to_string(),
                method: method_for(&location),
                location,
            }
        })
        .collect();
    let mount_plans = mounts
        .iter()
        .map(|m| {
            let bind = kind_of(&m.source) == MountKind::Bind;
            let app_paths: Vec<String> = data_paths
                .iter()
                .filter(|d| match &d.location {
                    Location::Bind { key, .. } | Location::Volume { key, .. } => *key == m.key,
                    Location::Rootfs => false,
                })
                .map(|d| d.path.clone())
                .collect();
            let method = match (bind, app_paths.is_empty(), m.backup) {
                (true, false, _) => Method::HostCapture,
                (true, true, _) | (false, _, false) => Method::Uncovered,
                (false, _, true) => Method::Vzdump,
            };
            MountPlan {
                key: m.key.clone(),
                source: m.source.clone(),
                target: m.target.clone(),
                bind,
                read_only: m.read_only,
                app_paths,
                method,
            }
        })
        .collect();
    GuestPlan {
        node: node.to_string(),
        vmid,
        name,
        app: profile.map(|p| p.app.to_string()),
        note: profile.and_then(|p| p.note).map(str::to_string),
        data_paths,
        mounts: mount_plans,
    }
}

/// Every container configured on this node, planned. Empty off a PVE node.
pub fn local_plans() -> Vec<GuestPlan> {
    let Ok(entries) = std::fs::read_dir(PVE_LXC_DIR) else {
        return Vec::new();
    };
    let node = crate::diagnostics::local_node();
    let mut plans: Vec<GuestPlan> = entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("conf") {
                return None;
            }
            let vmid: u64 = path.file_stem()?.to_str()?.parse().ok()?;
            let conf = std::fs::read_to_string(&path).ok()?;
            Some(plan_guest(&node, vmid, &conf))
        })
        .collect();
    plans.sort_by_key(|p| p.vmid);
    plans
}

// ── host capture seam ───────────────────────────────────────────────────────

/// Copies host trees in and out of a backup payload.
pub trait HostTree {
    /// Whether `path` can be read now; `false` means a capture would fail.
    fn readable(&self, path: &Path) -> bool;
    /// Copy `src` (file or directory) to `dest`; returns files copied.
    fn capture(&self, src: &Path, dest: &Path) -> Result<u64>;
    /// Copy `src` back over `dest`; returns files copied.
    fn restore(&self, src: &Path, dest: &Path) -> Result<u64>;
}

/// Plain `std::fs` as the plugin user. Ownership and modes beyond the
/// permission bits are not preserved, which only a root copy can do.
pub struct UnprivilegedTree;

const NEEDS_ROOT: &str =
    "needs root: host-side bind capture waits on orca's privileged host-read seam (orca#762)";

fn io_err(op: &str, path: &Path, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow!("{op} {}: {NEEDS_ROOT}", path.display())
    } else {
        anyhow!("{op} {}: {e}", path.display())
    }
}

fn copy_tree(src: &Path, dest: &Path) -> Result<u64> {
    let meta = std::fs::symlink_metadata(src).map_err(|e| io_err("stat", src, e))?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(src).map_err(|e| io_err("readlink", src, e))?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io_err("create", parent, e))?;
        }
        if std::fs::symlink_metadata(dest).is_ok() {
            std::fs::remove_file(dest).map_err(|e| io_err("replace", dest, e))?;
        }
        std::os::unix::fs::symlink(&target, dest).map_err(|e| io_err("symlink", dest, e))?;
        return Ok(1);
    }
    if meta.is_dir() {
        std::fs::create_dir_all(dest).map_err(|e| io_err("create", dest, e))?;
        let mut n = 0;
        for entry in std::fs::read_dir(src).map_err(|e| io_err("list", src, e))? {
            let entry = entry.map_err(|e| io_err("list", src, e))?;
            n += copy_tree(&entry.path(), &dest.join(entry.file_name()))?;
        }
        return Ok(n);
    }
    if !meta.is_file() {
        // Sockets, fifos and devices hold no state worth restoring.
        return Ok(0);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_err("create", parent, e))?;
    }
    std::fs::copy(src, dest).map_err(|e| io_err("copy", src, e))?;
    Ok(1)
}

impl HostTree for UnprivilegedTree {
    fn readable(&self, path: &Path) -> bool {
        match std::fs::metadata(path) {
            Ok(m) if m.is_dir() => std::fs::read_dir(path).is_ok(),
            Ok(_) => std::fs::File::open(path).is_ok(),
            Err(_) => false,
        }
    }

    fn capture(&self, src: &Path, dest: &Path) -> Result<u64> {
        copy_tree(src, dest)
    }

    fn restore(&self, src: &Path, dest: &Path) -> Result<u64> {
        copy_tree(src, dest)
    }
}

/// Payload location of one captured path: `<mount key>/<in-container path>`,
/// so two paths in one mount never collide.
fn payload_path(dir: &Path, key: &str, path: &str) -> PathBuf {
    dir.join(key).join(path.trim_start_matches('/'))
}

/// Copy every host-captured path of `plan` into `dir`, with the plan itself as
/// `plan.json`. Fails on the first path that cannot be copied.
pub fn capture(tree: &dyn HostTree, plan: &GuestPlan, dir: &Path) -> Result<u64> {
    let captures = plan.host_captures();
    if captures.is_empty() {
        bail!(
            "CT {} ('{}') has no app state in a bind mount to capture",
            plan.vmid,
            plan.name
        );
    }
    let manifest = serde_json::to_vec_pretty(plan)?;
    std::fs::write(dir.join("plan.json"), manifest).map_err(|e| anyhow!("write plan.json: {e}"))?;
    let mut n = 0;
    for (key, path, host) in captures {
        n += tree
            .capture(Path::new(host), &payload_path(dir, key, path))
            .with_context(|| format!("CT {} {key} {path}", plan.vmid))?;
    }
    Ok(n)
}

/// Copy captured paths back to the host paths the current plan resolves them
/// to. A path whose mount moved since the backup is restored to its new host
/// location, since the plan is recomputed from the live config.
pub fn restore(tree: &dyn HostTree, plan: &GuestPlan, dir: &Path) -> Result<u64> {
    let mut n = 0;
    for (key, path, host) in plan.host_captures() {
        let src = payload_path(dir, key, path);
        if std::fs::symlink_metadata(&src).is_err() {
            continue;
        }
        n += tree
            .restore(&src, Path::new(host))
            .with_context(|| format!("CT {} {key} {path}", plan.vmid))?;
    }
    Ok(n)
}

// ── lxc-bind backup kind ────────────────────────────────────────────────────

pub fn kind_instances(plans: &[GuestPlan]) -> Vec<String> {
    plans
        .iter()
        .filter(|p| !p.host_captures().is_empty())
        .map(|p| format!("{}/{}", p.node, p.vmid))
        .collect()
}

/// The plan for `"<node>/<vmid>"`, which must be a container on this node: the
/// bind sources are paths on the node that owns it.
pub fn local_plan(instance: &str) -> Result<GuestPlan> {
    let (node, vmid) = instance
        .split_once('/')
        .ok_or_else(|| anyhow!("lxc-bind: malformed instance '{instance}' (want <node>/<vmid>)"))?;
    let vmid: u64 = vmid
        .parse()
        .map_err(|_| anyhow!("lxc-bind: non-numeric vmid in '{instance}'"))?;
    let local = crate::diagnostics::local_node();
    if node != local {
        bail!(
            "lxc-bind: CT {vmid}'s bind sources live on node '{node}'; this plugin runs on '{local}'"
        );
    }
    let path = format!("{PVE_LXC_DIR}/{vmid}.conf");
    let conf = std::fs::read_to_string(&path).map_err(|e| anyhow!("lxc-bind: read {path}: {e}"))?;
    Ok(plan_guest(node, vmid, &conf))
}

// ── diagnostic ──────────────────────────────────────────────────────────────

/// Pure: findings for one container. `readable` reports whether the plugin can
/// read a host path now, which is what decides whether `lxc-bind` covers it.
pub fn findings_for(plan: &GuestPlan, readable: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let who = format!("CT {} ('{}')", plan.vmid, plan.name);
    for m in &plan.mounts {
        let id = format!("bind-uncovered::{}::{}::{}", plan.node, plan.vmid, m.key);
        let app = plan.app.as_deref().unwrap_or("app");
        match m.method {
            Method::HostCapture => {
                let hosts: Vec<(&str, &str)> = plan
                    .data_paths
                    .iter()
                    .filter_map(|d| match &d.location {
                        Location::Bind { key, host_path } if *key == m.key => {
                            Some((d.path.as_str(), host_path.as_str()))
                        }
                        _ => None,
                    })
                    .collect();
                let blocked: Vec<String> = hosts
                    .iter()
                    .filter(|(_, h)| !readable(h))
                    .map(|(p, h)| format!("{p} (host {h})"))
                    .collect();
                if blocked.is_empty() {
                    continue;
                }
                out.push(Finding {
                    id,
                    provider: PROVIDER.to_string(),
                    severity: Severity::Warn,
                    title: format!(
                        "{who} keeps {app} state in bind mount {} ({}) that no backup captures",
                        m.key, m.source
                    ),
                    detail: format!(
                        "vzdump, and so PBS, never includes a bind mount, so this state is in no \
                         guest backup: {}. The lxc-bind backup kind copies it from the node, but \
                         the plugin cannot read it as its own user; that capture {NEEDS_ROOT}.{}",
                        blocked.join(", "),
                        plan.note
                            .as_deref()
                            .map(|n| format!(" Note: {n}."))
                            .unwrap_or_default()
                    ),
                    repair: None,
                });
            }
            Method::Uncovered if m.bind => out.push(Finding {
                id,
                provider: PROVIDER.to_string(),
                severity: Severity::Info,
                title: format!(
                    "{who} bind mount {} ({} -> {}) is not covered by any backup",
                    m.key, m.source, m.target
                ),
                detail: format!(
                    "vzdump never includes a bind mount, and no known app state lives in this \
                     one, so nothing backs it up{}. If it holds state, add the app's data paths \
                     to the proxmox plugin's per-app table so the lxc-bind kind captures them; \
                     if it is bulk data, back it up where it is stored.",
                    if m.read_only {
                        " (it is mounted read-only, so the container only reads it)"
                    } else {
                        ""
                    }
                ),
                repair: None,
            }),
            Method::Uncovered => {
                let severity = if m.app_paths.is_empty() {
                    Severity::Info
                } else {
                    Severity::Warn
                };
                out.push(Finding {
                    id,
                    provider: PROVIDER.to_string(),
                    severity,
                    title: format!(
                        "{who} volume {} ({}) is excluded from vzdump",
                        m.key, m.target
                    ),
                    detail: format!(
                        "Mount {} has no `backup=1`, so vzdump skips it{}. Set it with \
                         `pct set {} -{} <current value>,backup=1` if it should be in the guest \
                         backup.",
                        m.key,
                        if m.app_paths.is_empty() {
                            String::new()
                        } else {
                            format!(" and with it {} state: {}", app, m.app_paths.join(", "))
                        },
                        plan.vmid,
                        m.key
                    ),
                    repair: None,
                });
            }
            Method::Vzdump => {}
        }
    }
    out
}

/// Node-local sweep over `/etc/pve/lxc`. Empty off a PVE node.
pub fn diagnose_bind_mounts() -> Vec<Finding> {
    let tree = UnprivilegedTree;
    local_plans()
        .iter()
        .flat_map(|p| findings_for(p, &|h| tree.readable(Path::new(h))))
        .collect()
}

// ── proxmox.lxc_data.plan ───────────────────────────────────────────────────

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct LxcDataPlanArgs {
    /// Limit to one container.
    #[arg(long)]
    #[serde(default)]
    pub ctid: Option<u64>,
}

/// Per container on this node: its mounts, the app's data paths, where each
/// lives (rootfs / volume / bind) and how it is backed up (vzdump / lxc-bind
/// host capture / uncovered). Read-only; empty off a PVE node.
#[orca_tool(
    domain = "proxmox",
    verb = "lxc_data.plan",
    execute_gated = false,
    role = "read"
)]
async fn proxmox_lxc_data_plan(args: LxcDataPlanArgs, _ctx: &ToolCtx) -> Result<Vec<GuestPlan>> {
    let mut plans = local_plans();
    if let Some(ct) = args.ctid {
        plans.retain(|p| p.vmid == ct);
    }
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zigbee2mqtt CT whose live config dir is a bind mount.
    const Z2M: &str = "\
arch: amd64
hostname: zigbee2mqtt
memory: 1024
mp0: /srv/z2m-config,mp=/etc/zigbee2mqtt
mp1: /mnt/pve/media,mp=/media,ro=1
rootfs: local-lvm:vm-120-disk-0,size=4G

[snap1]
mp0: /srv/old,mp=/etc/zigbee2mqtt
";

    #[test]
    fn app_matching_prefers_the_specific_name() {
        assert_eq!(app_for("zigbee2mqtt").unwrap().app, "zigbee2mqtt");
        assert_eq!(app_for("MQTT-broker").unwrap().app, "mosquitto");
        assert_eq!(app_for("zwave-js-ui").unwrap().app, "zwave-js-ui");
        assert!(app_for("debian-base").is_none());
    }

    #[test]
    fn z2m_live_dir_in_a_bind_is_host_captured_not_vzdump() {
        let p = plan_guest("hyp1", 120, Z2M);
        assert_eq!(p.app.as_deref(), Some("zigbee2mqtt"));
        assert_eq!(
            p.data_paths,
            vec![DataPathPlan {
                path: "/etc/zigbee2mqtt".into(),
                location: Location::Bind {
                    key: "mp0".into(),
                    host_path: "/srv/z2m-config".into(),
                },
                method: Method::HostCapture,
            }],
            "the live section wins over the snapshot"
        );
        assert_eq!(p.mounts[0].method, Method::HostCapture);
        assert_eq!(
            p.mounts[1].method,
            Method::Uncovered,
            "bulk read-only share"
        );
        assert_eq!(
            p.host_captures(),
            vec![("mp0", "/etc/zigbee2mqtt", "/srv/z2m-config")]
        );
    }

    #[test]
    fn plex_paths_resolve_below_a_bind_of_the_library() {
        let conf = "hostname: plex\nmp0: /tank/plex,mp=/var/lib/plexmediaserver\nrootfs: local-lvm:vm-1-disk-0,size=8G\n";
        let p = plan_guest("hyp1", 101, conf);
        let hosts: Vec<&str> = p.host_captures().iter().map(|c| c.2).collect();
        assert_eq!(
            hosts,
            vec![
                "/tank/plex/Library/Application Support/Plex Media Server/Plug-in Support/Databases",
                "/tank/plex/Library/Application Support/Plex Media Server/Preferences.xml",
            ]
        );
    }

    #[test]
    fn deepest_mount_wins_and_components_are_whole() {
        let mounts = parse_mountpoints(
            "mp0: /a,mp=/var/lib\nmp1: /b,mp=/var/lib/gitea\nmp2: /c,mp=/var/lib/gitea-old\n",
        );
        assert_eq!(
            locate("/var/lib/gitea", &mounts),
            Location::Bind {
                key: "mp1".into(),
                host_path: "/b".into()
            }
        );
        assert_eq!(
            locate("/var/lib/giteax/y", &mounts),
            Location::Bind {
                key: "mp0".into(),
                host_path: "/a/giteax/y".into()
            }
        );
        assert_eq!(locate("/etc/gitea", &mounts), Location::Rootfs);
    }

    /// The PBS rule: no bind-resident path is ever planned as vzdump.
    #[test]
    fn bind_data_is_never_planned_for_vzdump() {
        for p in APP_PROFILES {
            let conf = format!(
                "hostname: {}\n{}",
                p.matches[0],
                p.data_paths
                    .iter()
                    .enumerate()
                    .map(|(i, d)| format!("mp{i}: /host{i},mp={d}\n"))
                    .collect::<String>()
            );
            let plan = plan_guest("n", 1, &conf);
            for d in &plan.data_paths {
                assert!(matches!(d.location, Location::Bind { .. }), "{d:?}");
                assert_eq!(d.method, Method::HostCapture, "{}: {d:?}", p.app);
            }
        }
        assert_eq!(method_for(&Location::Rootfs), Method::Vzdump);
    }

    #[test]
    fn volume_without_backup_flag_is_uncovered() {
        let conf = "hostname: gitea\nmp0: local-lvm:vm-117-disk-1,mp=/var/lib/gitea,size=50G\n";
        let p = plan_guest("n", 117, conf);
        assert_eq!(p.data_paths[0].method, Method::Uncovered);
        assert_eq!(
            p.data_paths[1].method,
            Method::Vzdump,
            "/etc/gitea is rootfs"
        );
        let f = findings_for(&p, &|_| true);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Warn);
        assert!(f[0].detail.contains("backup=1"), "{}", f[0].detail);

        let conf = "hostname: gitea\nmp0: local-lvm:vm-117-disk-1,mp=/var/lib/gitea,backup=1\n";
        assert!(findings_for(&plan_guest("n", 117, conf), &|_| true).is_empty());
    }

    #[test]
    fn unreadable_app_state_is_a_warning_naming_the_seam() {
        let p = plan_guest("hyp1", 120, Z2M);
        let f = findings_for(&p, &|_| false);
        let warn = f
            .iter()
            .find(|f| f.id == "bind-uncovered::hyp1::120::mp0")
            .unwrap();
        assert_eq!(warn.severity, Severity::Warn);
        assert!(warn.detail.contains("orca#762"), "{}", warn.detail);
        let info = f
            .iter()
            .find(|f| f.id == "bind-uncovered::hyp1::120::mp1")
            .unwrap();
        assert_eq!(info.severity, Severity::Info);

        let readable = findings_for(&p, &|_| true);
        assert!(
            readable
                .iter()
                .all(|f| f.id != "bind-uncovered::hyp1::120::mp0"),
            "a capturable bind is covered by lxc-bind"
        );
    }

    #[test]
    fn instances_are_only_guests_with_host_captures() {
        let plans = vec![
            plan_guest("hyp1", 120, Z2M),
            plan_guest("hyp1", 130, "hostname: debian\nmp0: /x,mp=/x\n"),
        ];
        assert_eq!(kind_instances(&plans), vec!["hyp1/120".to_string()]);
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "proxmox-bind-{name}-{}-{}",
            std::process::id(),
            plugin_toolkit::time::now().unix_seconds()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn capture_and_restore_round_trip_through_the_payload() {
        let root = scratch("rt");
        let host = root.join("srv-z2m");
        std::fs::create_dir_all(host.join("sub")).unwrap();
        std::fs::write(host.join("configuration.yaml"), "a: 1\n").unwrap();
        std::fs::write(host.join("sub/db.json"), "{}").unwrap();
        let conf = format!(
            "hostname: zigbee2mqtt\nmp0: {},mp=/etc/zigbee2mqtt\n",
            host.display()
        );
        let plan = plan_guest("hyp1", 120, &conf);

        let payload = root.join("payload");
        std::fs::create_dir_all(&payload).unwrap();
        assert_eq!(capture(&UnprivilegedTree, &plan, &payload).unwrap(), 2);
        assert!(payload.join("plan.json").exists());
        assert_eq!(
            std::fs::read_to_string(payload.join("mp0/etc/zigbee2mqtt/configuration.yaml"))
                .unwrap(),
            "a: 1\n"
        );

        std::fs::write(host.join("configuration.yaml"), "a: 2\n").unwrap();
        assert_eq!(restore(&UnprivilegedTree, &plan, &payload).unwrap(), 2);
        assert_eq!(
            std::fs::read_to_string(host.join("configuration.yaml")).unwrap(),
            "a: 1\n"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn permission_denied_names_the_privileged_seam() {
        let e = io_err(
            "copy",
            Path::new("/srv/x"),
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(e.to_string().contains("orca#762"), "{e}");
    }

    #[test]
    fn capture_with_nothing_to_capture_is_an_error() {
        let plan = plan_guest("n", 1, "hostname: debian\n");
        let dir = scratch("empty");
        assert!(capture(&UnprivilegedTree, &plan, &dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
