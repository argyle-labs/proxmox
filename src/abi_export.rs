// The tool surface crosses this FFI boundary as opaque JSON — the designated
// JSON dispatch seam, identical to orca's `plugin-loader` and
// `dispatch::ErasedTool::run_json`. The payload type is aliased (`sj`) at this
// one seam, exactly as the loader aliases it, and the workspace
// disallowed-types lint is suppressed for this file only.
#![allow(clippy::disallowed_types)]

//! ABI-stable cdylib export.
//!
//! Builds and exports the single [`PluginModRef`] root module orca's
//! `plugin-loader` `dlopen`s. The accessor fns carry the version header the
//! loader reads before invoking anything; `manifest`/`invoke` wrap this crate's
//! own statically-linked tool inventory through the toolkit's re-exported
//! dispatch surface.
//!
//! Beyond tools, `backends()` advertises two domain backends — a
//! `cluster_roster` provider and a `topology` collector — that the loader
//! registers into orca's `contract` registries. Each routes back through
//! `invoke` under the `proxmox` prefix (`proxmox.list_clusters` /
//! `proxmox.collect_claims`), so a loaded proxmox plugin restores fleet cluster
//! grouping + parent-host nesting with no static link into orca.

use std::sync::Arc;
use std::sync::OnceLock;

use abi_stable::export_root_module;
use abi_stable::prefix_type::PrefixTypeTrait;
use abi_stable::std_types::{RErr, ROk, RResult, RStr, RString};
use plugin_toolkit::abi::{BackendDef, PluginMod, PluginModRef, ToolDef};
use plugin_toolkit::contract::config::{Config, Model, Ports};
use plugin_toolkit::contract::ToolCtx;
use plugin_toolkit::dispatch::{dispatch, tool_manifest_json};
// The JSON dispatch payload type, named once here at the designated opaque seam.
use plugin_toolkit::serde_json as sj;
use plugin_toolkit::tokio::runtime::{Builder, Runtime};

extern "C" fn plugin_semver() -> RString {
    RString::from(env!("CARGO_PKG_VERSION"))
}

extern "C" fn target_software() -> RString {
    RString::from("proxmox")
}

extern "C" fn target_compat() -> RString {
    RString::from(">=7.0")
}

extern "C" fn orca_compat() -> RString {
    RString::from(">=0.0.8, <0.1.0")
}

/// Tool-name prefix this plugin owns. The cdylib statically links the toolkit's
/// domain crates, each carrying its own `#[orca_tool]` inventory entries, so the
/// raw `tool_manifest_json()` walk returns those host-owned tools alongside the
/// plugin's. The plugin exposes only its own `proxmox.*` namespace across the
/// ABI; the host already owns the domain tools and would otherwise reject the
/// manifest as colliding built-ins.
const TOOL_PREFIX: &str = "proxmox.";

/// The plugin's own tool surface: `tool_manifest_json()` filtered to the
/// `proxmox.*` namespace. Shared by `manifest()` (serialized back out) and
/// `invoke()` (admission check) so both agree on exactly which tools cross.
fn own_tools() -> Vec<ToolDef> {
    let all: Vec<ToolDef> = sj::from_str(&tool_manifest_json()).unwrap_or_default();
    all.into_iter()
        .filter(|d| d.name.starts_with(TOOL_PREFIX))
        .collect()
}

extern "C" fn manifest() -> RString {
    let defs = own_tools();
    RString::from(sj::to_string(&defs).unwrap_or_else(|_| "[]".to_string()))
}

/// Shared multi-thread runtime driving the async tool bodies behind the
/// synchronous FFI `invoke`. Built once on first call and kept for the process
/// lifetime so repeated invocations don't spin a fresh runtime each time.
fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build plugin tokio runtime")
    })
}

/// A minimal `ToolCtx` for in-cdylib dispatch. The proxmox tool surface reads
/// endpoint rows from its own db + drives the PVE API; it needs no host-injected
/// services, so an empty service registry over a placeholder config suffices.
fn minimal_ctx() -> ToolCtx {
    let config = Config {
        anthropic_api_key: None,
        lmstudio_url: String::new(),
        ollama_url: String::new(),
        default_model: Model::LMStudio {
            id: String::new(),
            url: String::new(),
        },
        app_dir: std::env::temp_dir(),
        memory_root: std::env::temp_dir(),
        db_path: std::env::temp_dir().join("orca-plugin.db"),
        ports: Ports::default(),
    };
    ToolCtx::new(Arc::new(config))
}

extern "C" fn invoke(name: RStr<'_>, args_json: RStr<'_>) -> RResult<RString, RString> {
    if !name.as_str().starts_with(TOOL_PREFIX) {
        return RErr(RString::from(format!(
            "tool '{}' is not in this plugin's '{TOOL_PREFIX}' namespace",
            name.as_str()
        )));
    }
    let args: sj::Value = match sj::from_str(args_json.as_str()) {
        Ok(v) => v,
        Err(e) => return RErr(RString::from(format!("invalid args JSON: {e}"))),
    };
    let ctx = minimal_ctx();
    let result = runtime().block_on(dispatch(name.as_str(), args, &ctx));
    match result {
        Ok(value) => match sj::to_string(&value) {
            Ok(s) => ROk(RString::from(s)),
            Err(e) => RErr(RString::from(format!("failed to encode result: {e}"))),
        },
        Err(e) => RErr(RString::from(format!("{e:#}"))),
    }
}

/// Domain backends this plugin contributes. Two single-provider backends, both
/// reached back through `invoke` under the `proxmox` prefix:
///
/// - `cluster_roster` → `proxmox.list_clusters` (`contract::cluster_roster`)
/// - `topology` → `proxmox.collect_claims` (`contract::topology`)
///
/// `kind`/`capabilities` are unused by these two domains (their proxies call a
/// single fixed op), so they stay empty.
extern "C" fn backends() -> RString {
    let defs = vec![
        BackendDef {
            domain: "cluster_roster".to_string(),
            name: "proxmox".to_string(),
            kind: String::new(),
            endpoint: String::new(),
            capabilities: Vec::new(),
            invoke_prefix: "proxmox".to_string(),
        },
        BackendDef {
            domain: "topology".to_string(),
            name: "proxmox".to_string(),
            kind: String::new(),
            endpoint: String::new(),
            capabilities: Vec::new(),
            invoke_prefix: "proxmox".to_string(),
        },
    ];
    RString::from(sj::to_string(&defs).unwrap_or_else(|_| "[]".to_string()))
}

#[export_root_module]
fn export() -> PluginModRef {
    PluginMod {
        plugin_semver,
        target_software,
        target_compat,
        orca_compat,
        manifest,
        invoke,
        backends,
    }
    .leak_into_prefix()
}
