//! Magic link authentication plugin.

mod endpoints;
mod options;
mod payload;
mod response;
mod session_response;
mod token;
mod user_response;

pub use options::{
    MagicLinkEmail, MagicLinkFuture, MagicLinkOptions, MagicLinkOptionsBuilder, MagicLinkRateLimit,
    MagicLinkSendContext,
};
pub use token::{default_key_hasher, TokenStorage};

use rustauth_core::plugin::{AuthPlugin, PluginRateLimitRule};

use crate::VERSION;

pub const UPSTREAM_PLUGIN_ID: &str = "magic-link";

/// Development only — do not use in production.
///
/// Logs magic-link emails to stderr instead of sending mail.
#[must_use]
pub fn magic_link_dev_log() -> AuthPlugin {
    magic_link(MagicLinkOptions::new(|email| {
        Box::pin(async move {
            eprintln!(
                "[rustauth-dev] magic link for {}: {}",
                email.email, email.url
            );
            Ok(())
        })
    }))
}

pub fn magic_link(options: MagicLinkOptions) -> AuthPlugin {
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
