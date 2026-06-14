//! Bearer token plugin.

mod request;
mod response;

use rustauth_core::plugin::AuthPlugin;
use serde_json::json;

pub const UPSTREAM_PLUGIN_ID: &str = "bearer";

/// Options for bearer token authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BearerOptions {
    /// Require bearer tokens to already be signed session-cookie values.
    pub require_signature: bool,
}

impl BearerOptions {
    #[must_use]
    pub fn builder() -> BearerOptionsBuilder {
        BearerOptionsBuilder::default()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BearerOptionsBuilder {
    require_signature: Option<bool>,
}

impl BearerOptionsBuilder {
    #[must_use]
    pub fn require_signature(mut self, require_signature: bool) -> Self {
        self.require_signature = Some(require_signature);
        self
    }

    #[must_use]
    pub fn build(self) -> BearerOptions {
        let defaults = BearerOptions::default();
        BearerOptions {
            require_signature: self.require_signature.unwrap_or(defaults.require_signature),
        }
    }
}

/// Create the bearer plugin.
#[must_use]
pub fn bearer(options: BearerOptions) -> AuthPlugin {
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(json!({
            "requireSignature": options.require_signature,
        }))
        .with_on_request(move |context, request| request::handle(context, request, options))
        .with_on_response(response::handle)
}
