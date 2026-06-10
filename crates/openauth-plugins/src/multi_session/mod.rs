//! Multi-session plugin.

mod cookies;
mod endpoints;
mod errors;
mod hooks;
mod options;

pub use errors::{INVALID_SESSION_TOKEN, MULTI_SESSION_ERROR_CODES};
pub use options::MultiSessionConfig;

use openauth_core::plugin::{AuthPlugin, PluginErrorCode};

pub const UPSTREAM_PLUGIN_ID: &str = "multi-session";

#[must_use]
pub fn multi_session() -> AuthPlugin {
    multi_session_with(MultiSessionConfig::default())
}

#[must_use]
pub fn multi_session_with(config: MultiSessionConfig) -> AuthPlugin {
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(serde_json::json!({
            "maximumSessions": config.maximum_sessions,
        }))
        .with_error_code(PluginErrorCode::new(
            INVALID_SESSION_TOKEN,
            "Invalid session token",
        ))
        .with_endpoint(endpoints::list_device_sessions_endpoint())
        .with_endpoint(endpoints::set_active_session_endpoint())
        .with_endpoint(endpoints::revoke_device_session_endpoint())
        .with_async_after_hook("*", hooks::store_multi_session_cookie(config))
        .with_async_after_hook("/sign-out", hooks::revoke_multi_session_cookies())
}
