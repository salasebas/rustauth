//! OAuth proxy plugin.

mod endpoint;
mod hooks;
mod options;
mod payload;
mod utils;

use openauth_core::plugin::AuthPlugin;

pub use options::OAuthProxyOptions;

pub const UPSTREAM_PLUGIN_ID: &str = "oauth-proxy";

#[must_use]
pub fn oauth_proxy() -> AuthPlugin {
    oauth_proxy_with(OAuthProxyOptions::default())
}

#[must_use]
pub fn oauth_proxy_with(options: OAuthProxyOptions) -> AuthPlugin {
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(crate::VERSION)
        .with_options(options.to_value())
        .with_endpoint(endpoint::oauth_proxy_callback_endpoint(options.clone()))
        .with_async_before_hook("/sign-in/social", hooks::before_sign_in(options.clone()))
        .with_async_after_hook("/sign-in/social", hooks::after_sign_in(options.clone()))
        .with_async_before_hook("/sign-in/oauth2", hooks::before_sign_in(options.clone()))
        .with_async_after_hook("/sign-in/oauth2", hooks::after_sign_in(options.clone()))
        .with_async_before_hook("/callback/:id", hooks::before_callback(options.clone()))
        .with_after_hook("/callback/:id", hooks::after_callback(options))
}
