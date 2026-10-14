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
use crate::thin_pool::{PoolCommit, check_grow, provisioned_bytes};
use crate::tools::resolve_config;
use crate::{Config, GuestKind, fetch_guest_config};

const GIB: u64 = 1 << 30;

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

pub async fn grow_disk(
    cfg: &Config,
    endpoint: &str,
    node: &str,
    kind: GuestKind,
    vmid: u64,
    disk: &str,
    grow_gib: u64,
) -> Result<DiskGrowOutcome> {
    if grow_gib == 0 {
        bail!("`grow_gib` must be at least 1");
    }
    let http = cfg.build_reqwest_client()?;
    let config = fetch_guest_config(&http, &cfg.base_url, node, kind, vmid).await?;
    let (volume, storage) = disk_volume(kind, &config.data, disk)?;

    let storages = raw_get_data(
        &http,
        &cfg.base_url,
        &format!("nodes/{}/storage", enc(node)),
    )
    .await?;
    let pool = if parse_thin_storages(&storages).contains(&storage) {
        let base = format!("nodes/{}/storage/{}", enc(node), enc(&storage));
        let status = raw_get_data(&http, &cfg.base_url, &format!("{base}/status")).await?;
        let (size_bytes, used_bytes) = storage_size(&status)
            .ok_or_else(|| anyhow!("thin pool '{storage}' on '{node}' reported no size"))?;
        let content = raw_get_data(&http, &cfg.base_url, &format!("{base}/content")).await?;
        let pool = PoolCommit {
            node: node.to_string(),
            storage: storage.clone(),
            size_bytes,
            used_bytes,
            provisioned_bytes: provisioned_bytes(&content),
        };
        check_grow(&pool, grow_gib * GIB).map_err(|e| anyhow!("refused: {e}"))?;
        Some(pool)
    } else {
        None
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

    Ok(DiskGrowOutcome {
        endpoint: endpoint.to_string(),
        node: node.to_string(),
        vmid,
        kind: kind.as_str().to_string(),
        disk: disk.to_string(),
        volume,
        storage,
        grow_gib,
        pool,
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
}

/// [MUTATES STATE] Grow a guest disk by `grow_gib` GiB. On an LVM-thin pool
/// the grow is refused when the pool's provisioned total would pass its size
/// less the safety margin. A VM's in-guest partition/filesystem is not grown.
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
    grow_disk(
        &cfg,
        &args.endpoint,
        &args.node,
        kind,
        vmid,
        &args.disk,
        args.grow_gib,
    )
    .await
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

    #[test]
    fn only_vm_grows_leave_in_guest_work() {
        assert!(follow_up(GuestKind::Lxc).is_none());
        assert!(follow_up(GuestKind::Qemu).unwrap().contains("resize2fs"));
    }
}
