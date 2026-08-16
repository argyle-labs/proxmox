//! Generic `deploy_target` adapter for Proxmox VM/LXC guests.
//!
//! This is the north-star deploy front door ([[generics-are-generic-deployment-verbs]]):
//! orca hands any target a runtime-agnostic [`WorkloadSpec`] and asks it to
//! `launch`/`stop`/`restart`. proxmox's adapter binds that generic spec to a PVE
//! guest by DELEGATING into the existing `unit` provision path
//! ([`crate::unit_provider::ProxmoxUnitProvider::provision_guest`]) — no second
//! create implementation, no rip-out of the `unit` surface.
//!
//! ## What maps, what doesn't
//!
//! A [`WorkloadSpec`] is container-shaped: it says *what* to deploy (name, image)
//! but carries no placement or sizing. Those live on the **target**, not the
//! spec ([[topology-deploy-program-plan]] operator decision): each configured
//! deploy target persists a [`DeployTargetRow`] (node / storage / cores /
//! memory) in the plugin-owned `proxmox_deploy_target` table, surfaced as a
//! typed [`ProxmoxProvisioning`] on the registered target. At launch the adapter
//! fuses spec (`name`, `image`→`ostemplate`/`iso`) with the target's provisioning
//! (`node`/`endpoint`/`storage`/`cores`/`memory`) into a [`ProvisionPayload`].
//!
//! Fields a PVE guest has no generic home for — `env`, `mounts`, `ports` — are
//! rejected loudly rather than silently dropped: a container's env/bind-mounts
//! are not an LXC/VM concept here, so a spec that sets them is a mismatch to
//! surface, not swallow.

use plugin_toolkit::abi::{BackendDef, ColumnDef, DbOp, DbRow, DbValue, TableDef};
use plugin_toolkit::backend_def::{deploy_backend_def, schemas_json as build_schemas_json};
use plugin_toolkit::deploy_target::{
    DeployCapability, DeployError, DeployOutcome, DeployTarget, ProvisioningConfig,
    ProxmoxProvisioning, Runtime, TargetKind, WorkloadSpec, dispatch_op,
};
use plugin_toolkit::prelude::*;
use plugin_toolkit::runtime::{ToDbValue, db_op, field_from_row};

use crate::GuestKind;
use crate::unit_provider::{ProvisionPayload, ProxmoxUnitProvider};

/// Plugin data namespace for proxmox-owned tables — the isolation key core
/// derives `plug__proxmox__<table>` from.
const NAMESPACE: &str = "proxmox";
const TABLE: &str = "deploy_target";

/// Invoke-prefix root the loader routes a registered deploy target's
/// `launch`/`stop`/`restart` ops through. The concrete per-target prefix appends
/// the `{endpoint}/{kind}` row key so [`dispatch`] can recover which target a
/// call addresses.
const DEPLOY_PREFIX: &str = "proxmox.__deploy";

// ── Config row (plugin-owned table) ─────────────────────────────────────────

/// One configured Proxmox deploy target: the placement + sizing a guest is
/// provisioned with. Keyed by `(endpoint, kind)` — the same endpoint offers a
/// distinct target for `lxc` vs `vm`. Persisted in `proxmox_deploy_target`; the
/// synthetic `id` column is `"{endpoint}/{kind}"`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeployTargetRow {
    /// Registered proxmox endpoint the guest is provisioned on.
    pub endpoint: String,
    /// `lxc` or `vm`.
    pub kind: String,
    /// Proxmox node the guest lands on.
    pub node: String,
    /// Storage pool for the guest's root volume.
    pub storage: String,
    /// CPU cores to allocate.
    pub cores: u32,
    /// Memory to allocate, in megabytes.
    pub memory_mb: u64,
}

impl DeployTargetRow {
    /// Synthetic single-column primary key: `"{endpoint}/{kind}"`.
    fn id(&self) -> String {
        format!("{}/{}", self.endpoint, self.kind)
    }
}

/// The declared shape of `proxmox_deploy_target`, materialized by core at plugin
/// load ([[db-changes-must-migrate-to-clean-schema]] — real typed columns, no
/// KV blob). `not_null` columns carry defaults so an additive migration onto an
/// existing table is safe.
fn table_def() -> TableDef {
    let text_nn = |name: &str, default: &str| ColumnDef {
        name: name.to_string(),
        sql_type: "TEXT".to_string(),
        not_null: true,
        primary_key: false,
        default: Some(format!("'{default}'")),
    };
    let int_nn = |name: &str, default: &str| ColumnDef {
        name: name.to_string(),
        sql_type: "INTEGER".to_string(),
        not_null: true,
        primary_key: false,
        default: Some(default.to_string()),
    };
    TableDef {
        table: TABLE.to_string(),
        columns: vec![
            ColumnDef {
                name: "id".to_string(),
                sql_type: "TEXT".to_string(),
                not_null: true,
                primary_key: true,
                default: None,
            },
            text_nn("endpoint", ""),
            text_nn("kind", "lxc"),
            text_nn("node", ""),
            text_nn("storage", ""),
            int_nn("cores", "1"),
            int_nn("memory_mb", "512"),
        ],
        indexes: vec![],
    }
}

/// The `schema_json` this plugin hands `serve_tool_plugin! { schemas: … }` so
/// core materializes `proxmox_deploy_target` at load.
pub fn schemas_json() -> String {
    build_schemas_json(NAMESPACE, vec![table_def()])
}

// ── Table access (mirrors the generated `endpoint_db` over `db_op`) ─────────

mod deploy_db {
    use super::*;

    fn to_dbrow(r: &DeployTargetRow) -> DbRow {
        let mut m = DbRow::new();
        m.insert("id".to_string(), DbValue::Text(r.id()));
        m.insert("endpoint".to_string(), DbValue::Text(r.endpoint.clone()));
        m.insert("kind".to_string(), DbValue::Text(r.kind.clone()));
        m.insert("node".to_string(), DbValue::Text(r.node.clone()));
        m.insert("storage".to_string(), DbValue::Text(r.storage.clone()));
        m.insert("cores".to_string(), ToDbValue::to_dbvalue(&r.cores));
        m.insert("memory_mb".to_string(), ToDbValue::to_dbvalue(&r.memory_mb));
        m
    }

    fn from_dbrow(m: &DbRow) -> Result<DeployTargetRow> {
        Ok(DeployTargetRow {
            endpoint: field_from_row(m, "endpoint")?,
            kind: field_from_row(m, "kind")?,
            node: field_from_row(m, "node")?,
            storage: field_from_row(m, "storage")?,
            cores: field_from_row(m, "cores")?,
            memory_mb: field_from_row(m, "memory_mb")?,
        })
    }

    pub fn list() -> Result<Vec<DeployTargetRow>> {
        let reply = db_op(&DbOp::List {
            namespace: NAMESPACE.to_string(),
            table: TABLE.to_string(),
        })?;
        reply.rows.iter().map(from_dbrow).collect()
    }

    pub fn get(id: &str) -> Result<Option<DeployTargetRow>> {
        let reply = db_op(&DbOp::Get {
            namespace: NAMESPACE.to_string(),
            table: TABLE.to_string(),
            key_col: "id".to_string(),
            key: id.to_string(),
        })?;
        match reply.rows.first() {
            Some(r) => Ok(Some(from_dbrow(r)?)),
            None => Ok(None),
        }
    }

    pub fn upsert(r: &DeployTargetRow) -> Result<()> {
        db_op(&DbOp::Upsert {
            namespace: NAMESPACE.to_string(),
            table: TABLE.to_string(),
            row: to_dbrow(r),
        })?;
        Ok(())
    }

    pub fn remove(id: &str) -> Result<bool> {
        let reply = db_op(&DbOp::Delete {
            namespace: NAMESPACE.to_string(),
            table: TABLE.to_string(),
            key_col: "id".to_string(),
            key: id.to_string(),
        })?;
        Ok(reply.affected > 0)
    }
}

/// Normalize + validate a deploy-target kind string to `lxc` | `vm`.
fn normalize_kind(kind: &str) -> Result<&'static str> {
    match kind {
        "lxc" | "container" => Ok("lxc"),
        "vm" | "qemu" => Ok("vm"),
        other => bail!("unknown proxmox deploy kind '{other}' (expected lxc | vm)"),
    }
}

// ── Config tools: proxmox.deploy_target_{upsert,list,delete} ────────────────

#[derive(clap::Args, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeployTargetUpsertArgs {
    /// Registered proxmox endpoint the guest is provisioned on.
    pub endpoint: String,
    /// `lxc` or `vm`.
    pub kind: String,
    /// Proxmox node the guest lands on.
    pub node: String,
    /// Storage pool for the guest's root volume.
    pub storage: String,
    /// CPU cores to allocate.
    pub cores: u32,
    /// Memory to allocate, in megabytes.
    pub memory_mb: u64,
}

/// Register (or update) a Proxmox deploy target — the placement + sizing a
/// generic `deploy`/`service` launch provisions a guest with on `(endpoint,
/// kind)`. Takes effect for new targets on the next plugin load (registration
/// reads this table); an existing target's sizing updates in place.
#[orca_tool(domain = "proxmox", verb = "deploy_target_upsert", role = "admin")]
async fn deploy_target_upsert(
    args: DeployTargetUpsertArgs,
    _ctx: &ToolCtx,
) -> Result<DeployTargetRow> {
    let kind = normalize_kind(&args.kind)?;
    if args.endpoint.is_empty() || args.endpoint.contains('/') {
        bail!("endpoint must be a non-empty registered endpoint name without '/'");
    }
    // Fail loud if the endpoint isn't registered — a target that can't resolve a
    // client is misconfigured.
    crate::tools::endpoint_db::require(&args.endpoint)?;
    let row = DeployTargetRow {
        endpoint: args.endpoint,
        kind: kind.to_string(),
        node: args.node,
        storage: args.storage,
        cores: args.cores,
        memory_mb: args.memory_mb,
    };
    deploy_db::upsert(&row)?;
    Ok(row)
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeployTargetList {
    pub targets: Vec<DeployTargetRow>,
}

/// List every configured Proxmox deploy target.
#[orca_tool(domain = "proxmox", verb = "deploy_target_list")]
async fn deploy_target_list(
    _args: DeployTargetListArgs,
    _ctx: &ToolCtx,
) -> Result<DeployTargetList> {
    Ok(DeployTargetList {
        targets: deploy_db::list()?,
    })
}

#[derive(clap::Args, Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct DeployTargetListArgs {}

#[derive(clap::Args, Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeployTargetDeleteArgs {
    pub endpoint: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DeployTargetDeleteResult {
    pub removed: bool,
}

/// Remove a configured Proxmox deploy target. Deregistration of the live target
/// follows on the next plugin load.
#[orca_tool(domain = "proxmox", verb = "deploy_target_delete", role = "admin")]
async fn deploy_target_delete(
    args: DeployTargetDeleteArgs,
    _ctx: &ToolCtx,
) -> Result<DeployTargetDeleteResult> {
    let kind = normalize_kind(&args.kind)?;
    let id = format!("{}/{}", args.endpoint, kind);
    Ok(DeployTargetDeleteResult {
        removed: deploy_db::remove(&id)?,
    })
}

// ── The DeployTarget adapter ────────────────────────────────────────────────

/// A single `(node, Lxc|Vm, Proxmox)` deploy target backed by a configured
/// [`DeployTargetRow`]. Delegates every operation into the existing `unit`
/// provision/lifecycle path.
pub struct ProxmoxDeployTarget {
    row: DeployTargetRow,
    runtime: Runtime,
}

impl ProxmoxDeployTarget {
    fn from_row(row: DeployTargetRow) -> Result<Self> {
        let runtime = match normalize_kind(&row.kind)? {
            "lxc" => Runtime::Lxc,
            "vm" => Runtime::Vm,
            _ => unreachable!("normalize_kind yields lxc|vm"),
        };
        Ok(Self { row, runtime })
    }

    fn guest_kind(&self) -> GuestKind {
        match self.runtime {
            Runtime::Vm => GuestKind::Qemu,
            _ => GuestKind::Lxc,
        }
    }
}

#[async_trait]
impl DeployTarget for ProxmoxDeployTarget {
    fn host(&self) -> &str {
        &self.row.node
    }
    fn runtime(&self) -> Runtime {
        self.runtime
    }
    fn kind(&self) -> TargetKind {
        TargetKind::Proxmox
    }
    fn capabilities(&self) -> Vec<DeployCapability> {
        vec![
            DeployCapability::Launch,
            DeployCapability::Stop,
            DeployCapability::Restart,
        ]
    }
    fn endpoint(&self) -> String {
        format!(
            "proxmox:{}/{}/{}",
            self.row.endpoint, self.row.node, self.row.kind
        )
    }
    fn provisioning(&self) -> Option<ProvisioningConfig> {
        Some(ProvisioningConfig::Proxmox(ProxmoxProvisioning {
            node: self.row.node.clone(),
            endpoint: self.row.endpoint.clone(),
            storage: self.row.storage.clone(),
            cores: self.row.cores,
            memory_mb: self.row.memory_mb,
        }))
    }

    async fn launch(&self, spec: &WorkloadSpec) -> std::result::Result<DeployOutcome, DeployError> {
        // Fields a PVE guest has no generic mapping for — reject, never drop.
        if !spec.env.is_empty() {
            return Err(DeployError::Other(
                "proxmox deploy target does not map WorkloadSpec.env (configure the guest \
                 template / cloud-init instead)"
                    .into(),
            ));
        }
        if !spec.mounts.is_empty() {
            return Err(DeployError::Other(
                "proxmox deploy target does not map WorkloadSpec.mounts (attach guest volumes \
                 out of band)"
                    .into(),
            ));
        }
        if !spec.ports.is_empty() {
            return Err(DeployError::Other(
                "proxmox deploy target does not map WorkloadSpec.ports (a guest is not \
                 port-published)"
                    .into(),
            ));
        }
        let image = spec
            .image
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                DeployError::Other(
                    match self.runtime {
                        Runtime::Vm => {
                            "proxmox vm launch requires spec.image (install ISO volume id)"
                        }
                        _ => "proxmox lxc launch requires spec.image (LXC template volume id)",
                    }
                    .into(),
                )
            })?;

        let mut payload = ProvisionPayload {
            endpoint: self.row.endpoint.clone(),
            node: self.row.node.clone(),
            kind: self.row.kind.clone(),
            vmid: None,
            name: Some(spec.name.clone()),
            cores: Some(self.row.cores as u64),
            memory: Some(self.row.memory_mb as i64),
            storage: Some(self.row.storage.clone()),
            ostemplate: None,
            password: None,
            iso: None,
        };
        match self.runtime {
            Runtime::Vm => payload.iso = Some(image.to_string()),
            _ => payload.ostemplate = Some(image.to_string()),
        }

        let resp = ProxmoxUnitProvider::new()
            .provision_guest(payload)
            .await
            .map_err(|e| DeployError::Other(e.to_string()))?;
        Ok(DeployOutcome {
            workload: spec.name.clone(),
            id: Some(resp.vmid.to_string()),
            state: Some("provisioned".to_string()),
            detail: resp.upid,
        })
    }

    async fn stop(&self, workload: &str) -> std::result::Result<DeployOutcome, DeployError> {
        let (vmid, node) = ProxmoxUnitProvider::new()
            .lifecycle_by_name(&self.row.endpoint, self.guest_kind(), workload, "stop")
            .await
            .map_err(|e| DeployError::Other(e.to_string()))?;
        Ok(DeployOutcome {
            workload: workload.to_string(),
            id: Some(vmid.to_string()),
            state: Some("stopped".to_string()),
            detail: Some(format!("on {node}")),
        })
    }

    async fn restart(&self, workload: &str) -> std::result::Result<DeployOutcome, DeployError> {
        // PVE's in-guest restart is `reboot` (a running guest); it is the
        // generic `restart` for a provisioned VM/LXC.
        let (vmid, node) = ProxmoxUnitProvider::new()
            .lifecycle_by_name(&self.row.endpoint, self.guest_kind(), workload, "reboot")
            .await
            .map_err(|e| DeployError::Other(e.to_string()))?;
        Ok(DeployOutcome {
            workload: workload.to_string(),
            id: Some(vmid.to_string()),
            state: Some("running".to_string()),
            detail: Some(format!("on {node}")),
        })
    }
}

// ── Registration + dispatch (called from crate::registration) ───────────────

/// Per-target invoke prefix: `proxmox.__deploy.{endpoint}/{kind}`. The loader
/// routes `"{prefix}.{op}"`; [`dispatch`] strips it back to the row key.
fn invoke_prefix(row: &DeployTargetRow) -> String {
    format!("{DEPLOY_PREFIX}.{}", row.id())
}

/// One `deploy_target` [`BackendDef`] per configured target, for the plugin's
/// `backends()` payload. A config-read failure logs and yields none rather than
/// blanking the plugin's other backends.
pub fn backend_defs() -> Vec<BackendDef> {
    let rows = match deploy_db::list() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "proxmox deploy: target list failed; none advertised");
            return Vec::new();
        }
    };
    rows.into_iter()
        .filter_map(|row| match ProxmoxDeployTarget::from_row(row.clone()) {
            Ok(target) => Some(deploy_backend_def(&target, &invoke_prefix(&row))),
            Err(e) => {
                tracing::warn!(target = %row.id(), error = %e, "proxmox deploy: skipping malformed target");
                None
            }
        })
        .collect()
}

/// Route a `proxmox.__deploy.{endpoint}/{kind}.{op}` backend call to the matching
/// target's [`dispatch_op`]. Returns `None` for names outside this prefix so the
/// caller falls through to other backends.
pub fn dispatch(name: &str, args_json: &str) -> Option<Result<String, String>> {
    let rest = name
        .strip_prefix(DEPLOY_PREFIX)
        .and_then(|s| s.strip_prefix('.'))?;
    // `rest` = "{endpoint}/{kind}.{op}"; op has no '.', so split at the last one.
    let (row_key, op) = match rest.rsplit_once('.') {
        Some(parts) => parts,
        None => return Some(Err(format!("malformed deploy op name '{name}'"))),
    };
    let row = match deploy_db::get(row_key) {
        Ok(Some(r)) => r,
        Ok(None) => return Some(Err(format!("no proxmox deploy target '{row_key}'"))),
        Err(e) => return Some(Err(format!("deploy target lookup '{row_key}': {e}"))),
    };
    let target = match ProxmoxDeployTarget::from_row(row) {
        Ok(t) => t,
        Err(e) => return Some(Err(e.to_string())),
    };
    Some(plugin_toolkit::reactor::block_on(dispatch_op(
        &target, op, args_json,
    )))
}
