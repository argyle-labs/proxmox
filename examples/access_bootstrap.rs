//! Live validation of the secure-first access bootstrap against a real node.
//!
//! MUTATES the cluster's access config: creates the `OrcaOps` role, the
//! `orca@pve` user, an ACL grant, and a privilege-separated token. Idempotent
//! and reversible (delete the token/user/role). Run with an *elevated* (root or
//! admin) credential — that is the whole point: bootstrap with root, mint a
//! scoped runtime identity, then repoint the endpoint at it and rotate root.
//!
//!   PROXMOX_URL=https://<node>:8006 \
//!   PROXMOX_TOKEN_ID='root@pam!orca' \
//!   PROXMOX_TOKEN_SECRET=<uuid> \
//!   PROXMOX_INSECURE=1 \
//!     cargo run --example access_bootstrap
//!
//! Prints the minted `token_id` and, once, the secret — which in the runtime
//! flow is handed straight to the secrets domain, never printed or stored plain.

use proxmox::Config;
use proxmox::access;

fn env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("set {key}"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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

    let client = Config::new(&base, &token_id, &token_secret)
        .insecure(insecure)
        .build_generated_client()?;

    println!("bootstrapping least-privilege runtime identity on {base} ...");
    let id = access::bootstrap_orca_identity(&client).await?;

    println!("\nprovisioned:");
    println!("  role      {}", id.role);
    println!("  token_id  {}", id.token_id);
    println!("  privsep   {}", id.privsep);
    println!(
        "  secret    {}",
        id.secret.as_deref().unwrap_or("(none returned)")
    );
    println!("\nNext (runtime flow): store `secret` in the secrets domain, repoint the");
    println!(
        "endpoint's token_id at `{}`, then rotate the root token away.",
        id.token_id
    );
    Ok(())
}
