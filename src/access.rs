//! Proxmox access management — users, roles, ACLs, API tokens.
//!
//! Secure-first ([[runtime-least-privilege-not-root]]): an admin bootstraps a
//! cluster with root, but orca must not *operate* as root. This module drives
//! PVE's `/access/*` API to mint a dedicated least-privilege identity
//! (`orca@pve` + an `OrcaOps` role + a privilege-separated token), so the
//! runtime credential's blast radius is bounded to exactly the guest-lifecycle
//! operations the plugin performs.
//!
//! Privilege tiers ([[proxmox-access-management-capability]]):
//!   * **Runtime** (`OrcaOps`, minted here) — full guest lifecycle: audit,
//!     power, console, config, allocate/clone/backup, datastore space. It does
//!     **not** carry `User.Modify` / `Permissions.Modify` / `Realm.*`, so a
//!     leaked runtime token cannot create users or escalate.
//!   * **Elevated** (root or a future dedicated admin token) — access
//!     management itself (this module's writes). Keeping access-management
//!     privilege *out* of the runtime tier is the pathway to the tiered
//!     two-token model (roadmap): an on-demand elevated token minted and
//!     revoked per privileged action.
//!
//! Network-first ([[network-first-then-on-system]]): every operation here goes
//! through the generated REST client, so the whole capability is exercised from
//! a laptop against a live node before any on-system pveum path is considered.

use plugin_toolkit::prelude::*;

use crate::tools::{ProxmoxEndpoint, endpoint_db, token_secret_name};
use plugin_toolkit::api;
use plugin_toolkit::serde_json::Value;

/// Least-privilege role granted to the runtime identity. Full guest lifecycle
/// (create/delete included, per the chosen scope) but no access-management or
/// realm privileges — see the module tier note. `Sys.Audit`/`Sys.Console` cover
/// node status + host-log reads; `Datastore.*` cover disk allocation + backup.
pub const ORCA_OPS_PRIVS: &str = "VM.Audit VM.PowerMgmt VM.Console \
VM.Config.Disk VM.Config.CPU VM.Config.Memory VM.Config.Network \
VM.Config.Options VM.Config.Cloudinit VM.Allocate VM.Clone VM.Backup \
Datastore.Audit Datastore.AllocateSpace Datastore.AllocateTemplate \
Sys.Audit Sys.Console Pool.Audit SDN.Audit Mapping.Audit";

/// Default identity names. Kept as constants so the bootstrap and any later
/// rotation/teardown agree on exactly what to look for.
pub const ORCA_ROLE: &str = "OrcaOps";
pub const ORCA_USER: &str = "orca@pve";
pub const ORCA_TOKEN: &str = "orca";

/// The freshly-minted runtime credential. `secret` is shown by PVE exactly once
/// (on token creation) and must be persisted immediately by the caller into the
/// abstract secrets domain — never a plaintext endpoint column
/// ([[plugins-use-abstract-secrets-domain]]).
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProvisionedIdentity {
    /// Full token id, e.g. `orca@pve!orca` — the `token_id` an endpoint uses.
    pub token_id: String,
    /// The token secret (UUID). Sensitive; hand straight to the secrets domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// The role granted to the token.
    pub role: String,
    /// True if privilege separation is on (token privileges are the
    /// intersection of its own ACL and the user's).
    pub privsep: bool,
}

#[derive(Deserialize)]
struct RoleRow {
    roleid: String,
}

#[derive(Deserialize)]
struct UserRow {
    userid: String,
}

#[derive(Deserialize)]
struct GeneratedToken {
    #[serde(rename = "full-tokenid")]
    full_tokenid: String,
    value: String,
}

// ── Primitives (each wraps one /access endpoint) ────────────────────────────

/// Create the `OrcaOps` role if absent, or update its privilege set if it
/// already exists (idempotent — safe to re-run during rotation).
pub fn ensure_role(endpoint: &str, roleid: &str, privs: &str) -> Result<()> {
    let roles: Vec<RoleRow> = api::call("proxmox.get_index_access_roles", endpoint, json!({}))
        .context("proxmox access: list roles")?;
    if roles.iter().any(|r| r.roleid == roleid) {
        api::call::<Value>(
            "proxmox.put_update_role_access_roles_roleid",
            endpoint,
            json!({ "roleid": roleid, "body": { "append": false, "privs": privs } }),
        )
        .with_context(|| format!("proxmox access: update role {roleid}"))?;
    } else {
        api::call::<Value>(
            "proxmox.post_create_role_access_roles",
            endpoint,
            json!({ "body": { "roleid": roleid, "privs": privs } }),
        )
        .with_context(|| format!("proxmox access: create role {roleid}"))?;
    }
    Ok(())
}

/// Create a user if absent (idempotent). Enables the account.
pub fn ensure_user(endpoint: &str, userid: &str) -> Result<()> {
    let users: Vec<UserRow> = api::call("proxmox.get_index_access_users", endpoint, json!({}))
        .context("proxmox access: list users")?;
    if users.iter().any(|u| u.userid == userid) {
        return Ok(());
    }
    api::call::<Value>(
        "proxmox.post_create_user_access_users",
        endpoint,
        json!({ "body": { "userid": userid, "enable": true } }),
    )
    .with_context(|| format!("proxmox access: create user {userid}"))?;
    Ok(())
}

/// Grant `roleid` at `path` to a user and/or a token id, propagating to
/// children. PVE merges ACL entries, so this is additive and idempotent.
pub fn grant_acl(
    endpoint: &str,
    path: &str,
    roleid: &str,
    users: Option<&str>,
    tokens: Option<&str>,
) -> Result<()> {
    api::call::<Value>(
        "proxmox.put_update_acl_access_acl",
        endpoint,
        crate::args(json!({
            "body": {
                "path": path,
                "roles": roleid,
                "propagate": true,
                "users": users,
                "tokens": tokens,
            }
        })),
    )
    .with_context(|| format!("proxmox access: grant {roleid} at {path}"))?;
    Ok(())
}

/// Generate (or regenerate) an API token for `userid`. Returns the full token
/// id and the one-time secret. `privsep` on means the token's effective
/// privileges are the intersection of its own ACL and the user's.
pub fn generate_token(
    endpoint: &str,
    userid: &str,
    tokenid: &str,
    privsep: bool,
    comment: Option<&str>,
) -> Result<(String, String)> {
    let resp: GeneratedToken = api::call(
        "proxmox.post_generate_token_access_users_userid_token_tokenid",
        endpoint,
        crate::args(json!({
            "userid": userid,
            "tokenid": tokenid,
            "body": { "privsep": privsep, "comment": comment },
        })),
    )
    .with_context(|| format!("proxmox access: generate token {userid}!{tokenid}"))?;
    Ok((resp.full_tokenid, resp.value))
}

/// Delete a token (used to revoke/rotate). Idempotent from the caller's view:
/// a missing token surfaces as an error the caller may ignore during teardown.
pub fn delete_token(endpoint: &str, userid: &str, tokenid: &str) -> Result<()> {
    api::call::<Value>(
        "proxmox.delete_remove_token_access_users_userid_token_tokenid",
        endpoint,
        json!({ "userid": userid, "tokenid": tokenid }),
    )
    .with_context(|| format!("proxmox access: delete token {userid}!{tokenid}"))?;
    Ok(())
}

// ── Bootstrap orchestrator ──────────────────────────────────────────────────

pub fn bootstrap_orca_identity(endpoint: &str) -> Result<ProvisionedIdentity> {
    ensure_role(endpoint, ORCA_ROLE, ORCA_OPS_PRIVS)?;
    ensure_user(endpoint, ORCA_USER)?;
    grant_acl(endpoint, "/", ORCA_ROLE, Some(ORCA_USER), None)?;

    if let Err(e) = delete_token(endpoint, ORCA_USER, ORCA_TOKEN) {
        if e.downcast_ref::<api::Planned>().is_some() {
            return Err(e);
        }
        tracing::debug!(error = %e, "no existing orca token to drop before regeneration");
    }
    let (token_id, secret) =
        generate_token(endpoint, ORCA_USER, ORCA_TOKEN, true, Some("orca runtime"))?;

    // Privsep tokens start with no privileges of their own — grant the role to
    // the token id too, or its effective privilege set is empty.
    grant_acl(endpoint, "/", ORCA_ROLE, None, Some(&token_id))?;

    Ok(ProvisionedIdentity {
        token_id,
        secret: Some(secret),
        role: ORCA_ROLE.to_string(),
        privsep: true,
    })
}

// ── Tool: proxmox.access_bootstrap ──────────────────────────────────────────

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct AccessBootstrapArgs {
    /// Registered endpoint whose (currently elevated/root) credential is used to
    /// mint the scoped runtime identity.
    #[arg(long)]
    pub endpoint: String,
    /// Also repoint the endpoint at the new `orca@pve!orca` token and clear the
    /// plaintext secret column (the secret moves to the secrets domain). Default
    /// true; set false to mint + store without switching the live credential yet.
    #[arg(long, default_value_t = true)]
    #[serde(default = "default_true")]
    pub repoint: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct AccessBootstrapReport {
    pub endpoint: String,
    pub role: String,
    pub token_id: String,
    /// Name under which the secret was stored in the abstract secrets domain.
    pub secret_ref: String,
    /// True if the endpoint now uses the scoped token (root can be rotated away).
    pub repointed: bool,
}

/// [MUTATES STATE] Mint (or rotate) the least-privilege `orca@pve` runtime
/// identity on a registered endpoint, store its token secret in the abstract
/// secrets domain, and repoint the endpoint at it. Run once with root/admin
/// credentials, then rotate the bootstrap credential away.
#[orca_tool(
    domain = "proxmox",
    verb = "access_bootstrap",
    role = "admin",
    reaches = [
        "proxmox.put_update_role_access_roles_roleid",
        "proxmox.post_create_role_access_roles",
        "proxmox.post_create_user_access_users",
        "proxmox.put_update_acl_access_acl",
        "proxmox.post_generate_token_access_users_userid_token_tokenid",
        "proxmox.delete_remove_token_access_users_userid_token_tokenid"
    ]
)]
async fn proxmox_access_bootstrap(
    args: AccessBootstrapArgs,
    ctx: &ToolCtx,
) -> Result<AccessBootstrapReport> {
    crate::execute::require_admin("proxmox.access_bootstrap", ctx.caller().as_ref())?;
    let id = bootstrap_orca_identity(&args.endpoint)?;
    let secret = id
        .secret
        .clone()
        .ok_or_else(|| anyhow::anyhow!("bootstrap did not return a token secret"))?;

    // The one-time secret goes straight to the secrets domain — never a
    // plaintext endpoint column.
    let secret_ref = token_secret_name(&args.endpoint)?;
    plugin_toolkit::secrets::set(
        &secret_ref,
        &secret,
        Some(&format!(
            "proxmox runtime token for endpoint '{}'",
            args.endpoint
        )),
    )?;

    let mut repointed = false;
    if args.repoint {
        let row = endpoint_db::get(&args.endpoint)?
            .with_context(|| format!("proxmox endpoint '{}' not registered", args.endpoint))?;
        let updated = ProxmoxEndpoint {
            token_id: id.token_id.clone(),
            token_secret: String::new(),
            ..row
        };
        endpoint_db::update(&updated)?;
        repointed = true;
    }

    Ok(AccessBootstrapReport {
        endpoint: args.endpoint,
        role: id.role,
        token_id: id.token_id,
        secret_ref,
        repointed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_acl_omits_absent_principals_from_the_body() {
        let (r, calls) = crate::test_support::record_api_calls(
            |_, _| "null".to_string(),
            || grant_acl("pve", "/", ORCA_ROLE, Some(ORCA_USER), None),
        );
        r.unwrap();
        assert_eq!(
            calls,
            vec![(
                "PUT".to_string(),
                "/access/acl".to_string(),
                json!({ "body": {
                    "path": "/",
                    "roles": ORCA_ROLE,
                    "propagate": true,
                    "users": ORCA_USER,
                } })
            )]
        );
    }

    #[test]
    fn generate_token_sends_privsep_in_the_body() {
        let (r, calls) = crate::test_support::record_api_calls(
            |_, _| r#"{"full-tokenid":"orca@pve!orca","value":"s"}"#.to_string(),
            || generate_token("pve", ORCA_USER, ORCA_TOKEN, true, None),
        );
        assert_eq!(r.unwrap(), ("orca@pve!orca".to_string(), "s".to_string()));
        assert_eq!(
            calls,
            vec![(
                "POST".to_string(),
                "/access/users/orca@pve/token/orca".to_string(),
                json!({ "body": { "privsep": true } })
            )]
        );
    }
}
