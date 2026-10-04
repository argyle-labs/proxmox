//! Execute opt-in for verbs that plan their own changes.
//!
//! These verbs set `execute_gated = false` and take their own `execute` flag,
//! because orca's central gate can only echo the inputs while the verb can say
//! exactly which config keys and files it would change. Opting out of the
//! central gate also opts out of the role check orca runs inside it, so
//! [`authorize_execute`] replaces it: execute is refused unless the call
//! carries an admin caller identity.

use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::prelude::*;

/// A dry-run plan, or the verb's record of what it applied.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Change<T> {
    Plan(ExecutionPlan),
    Applied(T),
}

/// Fail closed: applying changes needs an identified admin caller. A call with
/// no caller identity is refused, never assumed trusted.
pub fn authorize_execute(tool: &str, caller: Option<&CallerIdentity>) -> Result<()> {
    match caller {
        Some(c) if c.role == "admin" => Ok(()),
        Some(c) => bail!(
            "{tool}: execute requires role 'admin'; caller '{}' has '{}'",
            c.username,
            c.role
        ),
        None => bail!(
            "{tool}: execute refused: the call carries no caller identity, so admin cannot be verified"
        ),
    }
}

/// Checked before any read, so an unauthorized execute never touches anything.
pub fn guard(tool: &str, execute: bool, ctx: &ToolCtx) -> Result<()> {
    if execute {
        authorize_execute(tool, ctx.caller().as_ref())?;
    }
    Ok(())
}

/// The detailed dry-run plan for `args`. An empty `changes` list is stated in
/// the summary so it never reads as "plan detail not implemented".
pub fn plan<A: Serialize>(
    tool: &str,
    args: &A,
    summary: String,
    changes: Vec<PlannedChange>,
) -> Result<ExecutionPlan> {
    let inputs = plugin_toolkit::serde_json::to_value(args)?;
    let summary = if changes.is_empty() {
        format!("{summary}; nothing to change")
    } else {
        summary
    };
    Ok(ExecutionPlan::generic(tool, inputs.into()).detailed(summary, changes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin() -> CallerIdentity {
        CallerIdentity {
            user_id: "u1".into(),
            username: "op".into(),
            role: "admin".into(),
            can_mutate: true,
        }
    }

    #[test]
    fn execute_needs_an_admin_caller() {
        assert!(authorize_execute("t", Some(&admin())).is_ok());
        let none = authorize_execute("t", None).unwrap_err().to_string();
        assert!(none.contains("no caller identity"), "{none}");
        let mut reader = admin();
        reader.role = "read".into();
        let err = authorize_execute("t", Some(&reader))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires role 'admin'"), "{err}");
    }

    #[test]
    fn empty_plan_says_nothing_to_change() {
        let p = plan("proxmox.x", &serde_json::json!({}), "do x".into(), vec![]).unwrap();
        assert!(p.dry_run && p.detailed);
        assert!(p.summary.ends_with("nothing to change"), "{}", p.summary);
    }
}
