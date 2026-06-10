//! Bearer token plugin.

mod request;
mod response;

use openauth_core::plugin::AuthPlugin;
use serde_json::json;

pub const UPSTREAM_PLUGIN_ID: &str = "bearer";

/// Options for bearer token authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BearerOptions {
    /// Require bearer tokens to already be signed session-cookie values.
    pub require_signature: bool,
}

/// Create the bearer plugin with default options.
#[must_use]
pub fn bearer() -> AuthPlugin {
    bearer_with(BearerOptions::default())
}

/// Create the bearer plugin with explicit options.
#[must_use]
pub fn bearer_with(options: BearerOptions) -> AuthPlugin {
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(json!({
            "requireSignature": options.require_signature,
        }))
        .with_on_request(move |context, request| request::handle(context, request, options))
        .with_on_response(response::handle)
}
