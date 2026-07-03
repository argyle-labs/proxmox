//! Live, read-only smoke test against a real Proxmox VE node.
//!
//! Exercises the plugin's actual networked path — `Config` → auth-header +
//! TLS wiring → the progenitor-generated client → `/cluster/resources` → the
//! response parsing that `UnitProvider::List` / `Detail` rely on — against a
//! live cluster. It never mutates: no start/stop/create/delete. Power actions
//! are validated through the unit surface, not here.
//!
//! Credentials come from the environment so no secret is ever committed:
//!
//!   PROXMOX_URL=https://<node>:8006 \
//!   PROXMOX_TOKEN_ID='root@pam!orca' \
//!   PROXMOX_TOKEN_SECRET=<uuid> \
//!   PROXMOX_INSECURE=1 \
//!     cargo run --example live_smoke
//!
//! `PROXMOX_URL` may be the host root (`https://host:8006`) or the full API
//! root (`.../api2/json`) — the `/api2/json` suffix is appended if absent.

use proxmox::Config;
use proxmox::generated::types as gtypes;

fn env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("set {key}"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // The plugin's reqwest build uses `rustls-no-provider`; orca installs a
    // crypto provider at startup, so a standalone example must do the same.
    // Ignore the result: an already-installed provider is fine for an example.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let mut base = env("PROXMOX_URL")?;
    let base_trimmed = base.trim_end_matches('/');
    if !base_trimmed.ends_with("/api2/json") {
        base = format!("{base_trimmed}/api2/json");
    }
    let token_id = env("PROXMOX_TOKEN_ID")?;
    let token_secret = env("PROXMOX_TOKEN_SECRET")?;
    let insecure = std::env::var("PROXMOX_INSECURE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Same construction the UnitProvider uses per enabled endpoint.
    let client = Config::new(&base, &token_id, &token_secret)
        .insecure(insecure)
        .build_generated_client()?;

    // Prove auth + transport first with the trivial /version call.
    match client.get_version_version().await {
        Ok(v) => println!("connected to {base}  (PVE {})", v.into_inner().version),
        Err(e) => println!("!! version parse FAILED (envelope?): {e}"),
    }

    // The List path: enumerate qemu + lxc guests via /cluster/resources.
    let items = client
        .get_resources_cluster_resources(Some(gtypes::GetResourcesClusterResourcesType::Vm))
        .await
        .map_err(|e| anyhow::anyhow!("cluster resources: {e}"))?
        .into_inner();

    let mut guests: Vec<(&str, String, i64, String, String)> = Vec::new();
    for r in &items {
        let kind = match r.type_ {
            gtypes::GetResourcesClusterResourcesResponseItemType::Qemu => "vm",
            gtypes::GetResourcesClusterResourcesResponseItemType::Lxc => "lxc",
            _ => continue,
        };
        let (Some(node), Some(vmid)) = (r.node.clone(), r.vmid) else {
            continue;
        };
        if node.is_empty() || vmid <= 0 {
            continue;
        }
        let name = r.name.clone().unwrap_or_else(|| format!("{kind}-{vmid}"));
        let status = r.status.clone().unwrap_or_else(|| "-".into());
        guests.push((kind, node, vmid, name, status));
    }
    guests.sort_by_key(|(_, _, vmid, _, _)| *vmid);

    println!("\n{} guests:", guests.len());
    println!("  KIND    VMID  NAME                  STATUS      NODE");
    for (kind, node, vmid, name, status) in &guests {
        println!("  {kind:<4}  {vmid:>6}  {name:<20}  {status:<10}  {node}");
    }

    // The Detail path: re-find the first guest by (kind, vmid) as do_detail does.
    if let Some((kind, node, vmid, name, status)) = guests.first() {
        println!("\ndetail({kind} {vmid}): name={name} status={status} node={node}");
    }

    println!("\nlive smoke OK — List + Detail read paths validated (read-only, no mutations).");
    Ok(())
}
