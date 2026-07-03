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

use crate::generated::{self, types as gtypes};
use crate::tools::{ProxmoxEndpoint, endpoint_db, make_client, token_secret_name};

/// Least-privilege role granted to the runtime identity. Full guest lifecycle
/// (create/delete included, per the chosen scope) but no access-management or
/// realm privileges — see the module tier note. `Sys.Audit`/`Sys.Console` cover
/// node status + host-log reads; `Datastore.*` cover disk allocation + backup.
pub const ORCA_OPS_PRIVS: &str = "VM.Audit VM.PowerMgmt VM.Console \
VM.Config.Disk VM.Config.CPU VM.Config.Memory VM.Config.Network \
VM.Config.Options VM.Config.Cloudinit VM.Allocate VM.Clone VM.Backup \
Datastore.Audit Datastore.AllocateSpace Datastore.AllocateTemplate \
Sys.Audit Sys.Console Pool.Audit";

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

// ── Primitives (each wraps one /access endpoint) ────────────────────────────

/// Create the `OrcaOps` role if absent, or update its privilege set if it
/// already exists (idempotent — safe to re-run during rotation).
pub async fn ensure_role(client: &generated::Client, roleid: &str, privs: &str) -> Result<()> {
    let exists = client
        .get_index_access_roles()
        .await
        .map_err(|e| anyhow::anyhow!("proxmox access: list roles: {e}"))?
        .into_inner()
        .iter()
        .any(|r| r.roleid == roleid);

    if exists {
        let body = gtypes::PutUpdateRoleAccessRolesRoleidBody {
            append: Some(false),
            privs: Some(privs.to_string()),
        };
        client
            .put_update_role_access_roles_roleid(roleid, &body)
            .await
            .map_err(|e| anyhow::anyhow!("proxmox access: update role {roleid}: {e}"))?;
    } else {
        let body = gtypes::PostCreateRoleAccessRolesBody {
            roleid: roleid.to_string(),
            privs: Some(privs.to_string()),
        };
        client
            .post_create_role_access_roles(&body)
            .await
            .map_err(|e| anyhow::anyhow!("proxmox access: create role {roleid}: {e}"))?;
    }
    Ok(())
}

/// Create a user if absent (idempotent). Enables the account.
pub async fn ensure_user(client: &generated::Client, userid: &str) -> Result<()> {
    let exists = client
        .get_index_access_users(None, None)
        .await
        .map_err(|e| anyhow::anyhow!("proxmox access: list users: {e}"))?
        .into_inner()
        .iter()
        .any(|u| u.userid == userid);
    if exists {
        return Ok(());
    }
    let body = gtypes::PostCreateUserAccessUsersBody {
        userid: userid.to_string(),
        enable: Some(true),
        comment: None,
        email: None,
        expire: None,
        firstname: None,
        lastname: None,
        groups: None,
        keys: None,
        password: None,
    };
    client
        .post_create_user_access_users(&body)
        .await
        .map_err(|e| anyhow::anyhow!("proxmox access: create user {userid}: {e}"))?;
    Ok(())
}

/// Grant `roleid` at `path` to a user and/or a token id, propagating to
/// children. PVE merges ACL entries, so this is additive and idempotent.
pub async fn grant_acl(
    client: &generated::Client,
    path: &str,
    roleid: &str,
    users: Option<&str>,
    tokens: Option<&str>,
) -> Result<()> {
    let body = gtypes::PutUpdateAclAccessAclBody {
        path: path.to_string(),
        roles: roleid.to_string(),
        propagate: Some(true),
        users: users.map(str::to_string),
        tokens: tokens.map(str::to_string),
        groups: None,
        delete: None,
    };
    client
        .put_update_acl_access_acl(&body)
        .await
        .map_err(|e| anyhow::anyhow!("proxmox access: grant {roleid} at {path}: {e}"))?;
    Ok(())
}

/// Generate (or regenerate) an API token for `userid`. Returns the full token
/// id and the one-time secret. `privsep` on means the token's effective
/// privileges are the intersection of its own ACL and the user's.
pub async fn generate_token(
    client: &generated::Client,
    userid: &str,
    tokenid: &str,
    privsep: bool,
    comment: Option<&str>,
) -> Result<(String, String)> {
    let tid: gtypes::PostGenerateTokenAccessUsersUseridTokenTokenidTokenid = tokenid
        .parse()
        .map_err(|e| anyhow::anyhow!("proxmox access: invalid token id '{tokenid}': {e}"))?;
    let body = gtypes::PostGenerateTokenAccessUsersUseridTokenTokenidBody {
        privsep: Some(privsep),
        comment: comment.map(str::to_string),
        expire: None,
    };
    let resp = client
        .post_generate_token_access_users_userid_token_tokenid(userid, &tid, &body)
        .await
        .map_err(|e| anyhow::anyhow!("proxmox access: generate token {userid}!{tokenid}: {e}"))?
        .into_inner();
    Ok((resp.full_tokenid, resp.value))
}

/// Delete a token (used to revoke/rotate). Idempotent from the caller's view:
/// a missing token surfaces as an error the caller may ignore during teardown.
pub async fn delete_token(client: &generated::Client, userid: &str, tokenid: &str) -> Result<()> {
    let tid: gtypes::DeleteRemoveTokenAccessUsersUseridTokenTokenidTokenid = tokenid
        .parse()
        .map_err(|e| anyhow::anyhow!("proxmox access: invalid token id '{tokenid}': {e}"))?;
    client
        .delete_remove_token_access_users_userid_token_tokenid(userid, &tid)
        .await
        .map_err(|e| anyhow::anyhow!("proxmox access: delete token {userid}!{tokenid}: {e}"))?;
    Ok(())
}

// ── Bootstrap orchestrator ──────────────────────────────────────────────────

/// Mint the least-privilege runtime identity on a cluster reachable via
/// `client` (which must currently carry an elevated/admin credential).
///
/// Sequence: ensure `OrcaOps` role → ensure `orca@pve` user → grant the role to
/// the user → generate a privsep token → grant the role to the token id. The
/// returned [`ProvisionedIdentity`] carries the one-time secret; the caller
/// persists it to the secrets domain and repoints the endpoint at the new
/// `token_id`, after which the bootstrap (root) credential can be rotated away.
///
/// Re-running rotates the token (a fresh secret) while leaving role/user/ACL in
/// place — the basis for scheduled rotation.
pub async fn bootstrap_orca_identity(client: &generated::Client) -> Result<ProvisionedIdentity> {
    ensure_role(client, ORCA_ROLE, ORCA_OPS_PRIVS).await?;
    ensure_user(client, ORCA_USER).await?;
    grant_acl(client, "/", ORCA_ROLE, Some(ORCA_USER), None).await?;

    // Regenerate cleanly: drop any stale token so the secret is fresh.
    let _ = delete_token(client, ORCA_USER, ORCA_TOKEN).await;
    let (token_id, secret) =
        generate_token(client, ORCA_USER, ORCA_TOKEN, true, Some("orca runtime")).await?;

    // Privsep tokens start with no privileges of their own — grant the role to
    // the token id too, or its effective privilege set is empty.
    grant_acl(client, "/", ORCA_ROLE, None, Some(&token_id)).await?;

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
#[orca_tool(domain = "proxmox", verb = "access_bootstrap")]
async fn proxmox_access_bootstrap(
    args: AccessBootstrapArgs,
    _ctx: &ToolCtx,
) -> Result<AccessBootstrapReport> {
    let client = make_client(&args.endpoint)?;
    let id = bootstrap_orca_identity(&client).await?;
    let secret = id
        .secret
        .clone()
        .ok_or_else(|| anyhow::anyhow!("bootstrap did not return a token secret"))?;

    // The one-time secret goes straight to the secrets domain — never a
    // plaintext endpoint column.
    let secret_ref = token_secret_name(&args.endpoint);
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
        let conn = runtime::open_db()?;
        let row = endpoint_db::get(&conn, &args.endpoint)?
            .with_context(|| format!("proxmox endpoint '{}' not registered", args.endpoint))?;
        let updated = ProxmoxEndpoint {
            token_id: id.token_id.clone(),
            token_secret: String::new(), // secret now lives in the secrets domain
            ..row
        };
        endpoint_db::update(&conn, &updated)?;
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
