//! Magic link authentication plugin.

mod endpoints;
mod options;
mod payload;
mod response;
mod session_response;
mod token;
mod user_response;

pub use options::{
    MagicLinkEmail, MagicLinkFuture, MagicLinkOptions, MagicLinkRateLimit, MagicLinkSendContext,
};
pub use token::{default_key_hasher, TokenStorage};

use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};

use crate::VERSION;

pub const UPSTREAM_PLUGIN_ID: &str = "magic-link";

pub fn magic_link_with(options: MagicLinkOptions) -> AuthPlugin {
    let rate_limit = options.rate_limit_rule();
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(VERSION)
        .with_endpoint(endpoints::sign_in_magic_link_endpoint(options.clone()))
        .with_endpoint(endpoints::verify_magic_link_endpoint(options))
        .with_rate_limit(PluginRateLimitRule::new(
            "/sign-in/magic-link",
            rate_limit.clone(),
        ))
        .with_rate_limit(PluginRateLimitRule::new("/magic-link/verify", rate_limit))
}
