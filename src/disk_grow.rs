//! `proxmox.guest.disk.grow` — grow one guest disk through the PVE resize API,
//! refused first by [`thin_pool::check_grow`] when the disk sits on an LVM-thin
//! pool the grow would over-commit.
//!
//! PVE grows an LXC volume's filesystem itself; for a VM only the block device
//! grows, so the in-guest partition and filesystem still need growing.

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::backup::{enc, put_form, raw_get_data};
use crate::responses::{ConfigField, GuestConfigData};
use crate::thin_discard::{parse_thin_storages, volume_of};
use crate::thin_pool::{
    MetadataUsage, PoolCommit, check_data_usage, check_grow, check_metadata_usage, metadata_usage,
    provisioned_bytes,
};
use crate::tools::resolve_config;
use crate::{Config, GuestKind, fetch_guest_config};

const GIB: u64 = 1 << 30;
const MAX_GROW_GIB: u64 = 64 * 1024;

type PoolKey = (String, String);

static GROW_LOCKS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<PoolKey, std::sync::Arc<tokio::sync::Mutex<()>>>>,
> = std::sync::LazyLock::new(Default::default);

fn pool_lock(node: &str, storage: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    GROW_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry((node.to_string(), storage.to_string()))
        .or_default()
        .clone()
}

fn grow_bytes(grow_gib: u64) -> Result<u64> {
    if grow_gib == 0 || grow_gib > MAX_GROW_GIB {
        bail!("`grow_gib` must be between 1 and {MAX_GROW_GIB}");
    }
    grow_gib
        .checked_mul(GIB)
        .ok_or_else(|| anyhow!("`grow_gib` {grow_gib} overflows"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DiskGrowOutcome {
    pub endpoint: String,
    pub node: String,
    pub vmid: u64,
    pub kind: String,
    pub disk: String,
    pub volume: String,
    pub storage: String,
    pub grow_gib: u64,
    /// The thin pool before the grow; absent when the storage is not LVM-thin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolCommit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MetadataUsage>,
    /// Whether `force` overrode an overcommit refusal.
    pub forced: bool,
    /// Set when the pool re-read after the resize is past a limit or failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// What is left for the operator after the block device grew.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_up: Option<String>,
}

/// `(volid, storage)` of `disk` in a guest config, refusing keys that are not a
/// storage-backed disk.
pub fn disk_volume(
    kind: GuestKind,
    config: &GuestConfigData,
    disk: &str,
) -> Result<(String, String)> {
    let value = config
        .get_str(disk)
        .ok_or_else(|| anyhow!("{} has no disk '{disk}'", kind.as_str()))?;
    volume_of(kind, value).ok_or_else(|| {
        anyhow!("'{disk}' is not a storage-backed disk (bind mount, CD-ROM or empty drive)")
    })
}

/// `(size, used)` of a storage from `/nodes/{node}/storage/{storage}/status`.
fn storage_size(status: &Value) -> Option<(u64, u64)> {
    let total = status
        .get("total")
        .and_then(Value::as_u64)
        .filter(|t| *t > 0)?;
    Some((
        total,
        status.get("used").and_then(Value::as_u64).unwrap_or(0),
    ))
}

fn follow_up(kind: GuestKind) -> Option<String> {
    match kind {
        GuestKind::Lxc => None,
        GuestKind::Qemu => Some(
            "only the block device grew: grow the partition (growpart) if the filesystem sits \
             on one, then the filesystem (resize2fs / xfs_growfs) inside the guest"
                .into(),
        ),
    }
}

fn guard_grow(
    pool: &PoolCommit,
    meta: MetadataUsage,
    grow_bytes: u64,
    force: bool,
) -> Result<bool> {
    check_data_usage(pool, grow_bytes)
        .and_then(|()| check_metadata_usage(pool, meta, grow_bytes))
        .map_err(|e| {
            anyhow!(
                "refused: {e}; `force` cannot override this: a full thin pool stalls every guest on it"
            )
        })?;
    match check_grow(pool, grow_bytes) {
        Ok(()) => Ok(false),
        Err(e) if force => {
            tracing::warn!(node = %pool.node, storage = %pool.storage, "forced past thin pool guard: {e}");
            Ok(true)
        }
        Err(e) => bail!("refused: {e}; pass `force` to grow anyway"),
    }
}

async fn read_pool(
    http: &plugin_toolkit::reqwest::Client,
    base_url: &str,
    node: &str,
    storage: &str,
) -> Result<(PoolCommit, MetadataUsage)> {
    let base = format!("nodes/{}/storage/{}", enc(node), enc(storage));
    let status = raw_get_data(http, base_url, &format!("{base}/status")).await?;
    let (size_bytes, used_bytes) = storage_size(&status)
        .ok_or_else(|| anyhow!("thin pool '{storage}' on '{node}' reported no size"))?;
    let content = raw_get_data(http, base_url, &format!("{base}/content")).await?;
    let pool = PoolCommit {
        node: node.to_string(),
        storage: storage.to_string(),
        size_bytes,
        used_bytes,
        provisioned_bytes: provisioned_bytes(&content),
    };
    let storage_cfg = raw_get_data(http, base_url, &format!("storage/{}", enc(storage))).await?;
    let field = |k: &str| {
        storage_cfg
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("thin pool storage '{storage}' config has no `{k}`"))
    };
    let (vg, thinpool) = (field("vgname")?, field("thinpool")?);
    let lvmthin = raw_get_data(
        http,
        base_url,
        &format!("nodes/{}/disks/lvmthin", enc(node)),
    )
    .await?;
    let meta = metadata_usage(&lvmthin, vg, thinpool)
        .ok_or_else(|| anyhow!("no metadata usage for thin pool {vg}/{thinpool} on '{node}'"))?;
    Ok((pool, meta))
}

fn post_grow_warning(pool: &PoolCommit, meta: MetadataUsage) -> Option<String> {
    check_data_usage(pool, 0)
        .and_then(|()| check_metadata_usage(pool, meta, 0))
        .err()
        .map(|e| format!("thin pool past its limit after the grow: {e}"))
}

pub async fn grow_disk(
    cfg: &Config,
    args: &GuestDiskGrowArgs,
    kind: GuestKind,
    vmid: u64,
) -> Result<DiskGrowOutcome> {
    let GuestDiskGrowArgs {
        endpoint,
        node,
        disk,
        grow_gib,
        force,
        ..
    } = args;
    let (grow_gib, force) = (*grow_gib, *force);
    let grow = grow_bytes(grow_gib)?;
    let http = cfg.build_reqwest_client()?;
    let config = fetch_guest_config(&http, &cfg.base_url, node, kind, vmid).await?;
    let (volume, storage) = disk_volume(kind, &config.data, disk)?;

    let storages = raw_get_data(
        &http,
        &cfg.base_url,
        &format!("nodes/{}/storage", enc(node)),
    )
    .await?;
    let lock = pool_lock(node, &storage);
    let _held = lock.lock().await;
    let (pool, metadata, forced) = if parse_thin_storages(&storages).contains(&storage) {
        let (pool, meta) = read_pool(&http, &cfg.base_url, node, &storage).await?;
        let forced = guard_grow(&pool, meta, grow, force)?;
        (Some(pool), Some(meta), forced)
    } else {
        (None, None, false)
    };

    // The digest makes PVE reject the resize if the config changed since the
    // read the guard was computed from.
    let Some(ConfigField::Str(digest)) = config.data.fields.get("digest") else {
        bail!(
            "{} {vmid} config read returned no digest; refusing an unguarded resize",
            kind.as_str()
        );
    };
    let url = format!(
        "{}/nodes/{}/{}/{}/resize",
        cfg.base_url.trim_end_matches('/'),
        enc(node),
        kind.as_str(),
        vmid
    );
    let pairs = vec![
        ("disk".to_string(), disk.to_string()),
        ("size".to_string(), format!("+{grow_gib}G")),
        ("digest".to_string(), digest.clone()),
    ];
    put_form(&http, &url, &pairs).await?;

    let warning = match &pool {
        None => None,
        Some(_) => match read_pool(&http, &cfg.base_url, node, &storage).await {
            Ok((after, meta)) => post_grow_warning(&after, meta),
            Err(e) => Some(format!(
                "could not re-read the thin pool after the grow: {e}"
            )),
        },
    };
    if let Some(w) = &warning {
        tracing::warn!(node = %node, storage = %storage, "{w}");
    }

    Ok(DiskGrowOutcome {
        endpoint: endpoint.clone(),
        node: node.clone(),
        vmid,
        kind: kind.as_str().to_string(),
        disk: disk.clone(),
        volume,
        storage,
        grow_gib,
        pool,
        metadata,
        forced,
        warning,
        follow_up: follow_up(kind),
    })
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct GuestDiskGrowArgs {
    #[arg(long)]
    pub endpoint: String,
    #[arg(long)]
    pub node: String,
    /// QEMU VM id.
    #[arg(long)]
    pub vmid: Option<u64>,
    /// LXC container id.
    #[arg(long)]
    pub ctid: Option<u64>,
    /// Config key of the disk (`rootfs`, `mp0`, `scsi0`, …).
    #[arg(long)]
    pub disk: String,
    /// GiB to add to the disk.
    #[arg(long)]
    pub grow_gib: u64,
    /// Grow past the thin pool overcommit refusal; never past the data usage limit.
    #[arg(long)]
    #[serde(default)]
    pub force: bool,
}

/// [MUTATES STATE] Grow a guest disk by `grow_gib` GiB. On an LVM-thin pool
/// the grow is refused when the pool's data could pass the usage threshold,
/// and, unless `force` is set, when its provisioned total would pass its size
/// less the safety margin. A VM's in-guest partition/filesystem is not grown.
/// Grows are serialized per pool within this plugin process only, so the guard
/// is best-effort against concurrent grows from elsewhere; the pool is re-read
/// after the resize and `warning` is set if it ended up past a limit.
#[orca_tool(domain = "proxmox", verb = "guest.disk.grow", role = "admin")]
async fn proxmox_guest_disk_grow(
    args: GuestDiskGrowArgs,
    ctx: &ToolCtx,
) -> Result<DiskGrowOutcome> {
    crate::execute::require_admin("proxmox.guest.disk.grow", ctx.caller().as_ref())?;
    let (vmid, kind) = match (args.vmid, args.ctid) {
        (Some(v), None) => (v, GuestKind::Qemu),
        (None, Some(c)) => (c, GuestKind::Lxc),
        (Some(_), Some(_)) => bail!("set either `vmid` or `ctid`, not both"),
        (None, None) => bail!("`vmid` or `ctid` required"),
    };
    let cfg = resolve_config(&args.endpoint).await?;
    grow_disk(&cfg, &args, kind, vmid).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::json;

    fn config(v: Value) -> GuestConfigData {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn resolves_the_volume_of_a_disk_key() {
        let c = config(
            json!({"scsi0": "local-lvm:vm-102-disk-0,size=380G", "ide2": "none,media=cdrom"}),
        );
        assert_eq!(
            disk_volume(GuestKind::Qemu, &c, "scsi0").unwrap(),
            ("local-lvm:vm-102-disk-0".into(), "local-lvm".into())
        );
        assert!(disk_volume(GuestKind::Qemu, &c, "ide2").is_err());
        assert!(disk_volume(GuestKind::Qemu, &c, "scsi1").is_err());
    }

    #[test]
    fn lxc_bind_mount_is_not_growable() {
        let c = config(json!({"mp0": "/mnt/media,mp=/media"}));
        let e = disk_volume(GuestKind::Lxc, &c, "mp0")
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a storage-backed disk"), "{e}");
    }

    #[test]
    fn storage_status_needs_a_size() {
        assert_eq!(
            storage_size(&json!({"total": 100, "used": 40})),
            Some((100, 40))
        );
        assert_eq!(storage_size(&json!({"total": 0})), None);
        assert_eq!(storage_size(&json!({})), None);
    }

    fn pool(size_gib: u64, used_gib: u64, provisioned_gib: u64) -> PoolCommit {
        PoolCommit {
            node: "frigg".into(),
            storage: "local-lvm".into(),
            size_bytes: size_gib * GIB,
            used_bytes: used_gib * GIB,
            provisioned_bytes: provisioned_gib * GIB,
        }
    }

    const META: MetadataUsage = MetadataUsage {
        size_bytes: GIB,
        used_bytes: GIB / 10,
    };

    #[test]
    fn force_overrides_only_the_overcommit_refusal_and_reports_it() {
        let over = pool(100, 20, 94);
        let e = guard_grow(&over, META, 2 * GIB, false)
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("refused:") && e.contains("pass `force`"),
            "{e}"
        );
        assert!(guard_grow(&over, META, 2 * GIB, true).unwrap());
        assert!(!guard_grow(&pool(100, 20, 50), META, 2 * GIB, true).unwrap());
    }

    #[test]
    fn force_never_overrides_data_or_metadata_exhaustion() {
        let full = pool(100, 89, 50);
        for force in [false, true] {
            let e = guard_grow(&full, META, 2 * GIB, force)
                .unwrap_err()
                .to_string();
            assert!(e.contains("`force` cannot override"), "{e}");
            let meta_full = MetadataUsage {
                size_bytes: GIB,
                used_bytes: GIB * 9 / 10,
            };
            let e = guard_grow(&pool(100, 20, 50), meta_full, GIB, force)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("metadata") && e.contains("cannot override"),
                "{e}"
            );
        }
    }

    #[test]
    fn data_boundary_holds_through_guard_grow() {
        let p = pool(100, 85, 10);
        assert!(guard_grow(&p, META, 5 * GIB, false).is_ok());
        assert!(guard_grow(&p, META, 5 * GIB + 1, true).is_err());
    }

    #[test]
    fn zero_size_pool_is_refused_even_forced() {
        let p = pool(0, 0, 0);
        assert!(guard_grow(&p, META, GIB, true).is_err());
    }

    #[test]
    fn grow_size_is_bounded_and_never_overflows() {
        assert_eq!(grow_bytes(1).unwrap(), GIB);
        assert_eq!(grow_bytes(MAX_GROW_GIB).unwrap(), MAX_GROW_GIB * GIB);
        assert!(grow_bytes(0).is_err());
        assert!(grow_bytes(MAX_GROW_GIB + 1).is_err());
        assert!(grow_bytes(u64::MAX).is_err());
        assert!(grow_bytes(u64::MAX / GIB + 1).is_err());
    }

    #[test]
    fn post_grow_warning_flags_a_pool_past_its_limits() {
        assert!(post_grow_warning(&pool(100, 80, 50), META).is_none());
        let w = post_grow_warning(&pool(100, 95, 50), META).unwrap();
        assert!(w.contains("past its limit") && w.contains("of data"), "{w}");
        let meta_full = MetadataUsage {
            size_bytes: GIB,
            used_bytes: GIB * 95 / 100,
        };
        assert!(
            post_grow_warning(&pool(100, 80, 50), meta_full)
                .unwrap()
                .contains("metadata")
        );
    }

    #[test]
    fn only_vm_grows_leave_in_guest_work() {
        assert!(follow_up(GuestKind::Lxc).is_none());
        assert!(follow_up(GuestKind::Qemu).unwrap().contains("resize2fs"));
    }

    #[test]
    fn grows_on_one_pool_share_a_lock() {
        let a = pool_lock("frigg", "local-lvm");
        assert!(std::sync::Arc::ptr_eq(&a, &pool_lock("frigg", "local-lvm")));
        assert!(!std::sync::Arc::ptr_eq(&a, &pool_lock("thor", "local-lvm")));
    }
}
