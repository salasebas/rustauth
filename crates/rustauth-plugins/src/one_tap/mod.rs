//! Google One Tap server plugin.

mod endpoint;
mod options;
mod response;

pub use options::OneTapOptions;
pub use options::OneTapOptionsBuilder;

use rustauth_core::plugin::AuthPlugin;

pub const UPSTREAM_PLUGIN_ID: &str = "one-tap";

#[must_use]
pub fn one_tap(options: OneTapOptions) -> AuthPlugin {
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(serde_json::to_value(&options).unwrap_or(serde_json::Value::Null))
        .with_endpoint(endpoint::one_tap_callback_endpoint(options))
}
