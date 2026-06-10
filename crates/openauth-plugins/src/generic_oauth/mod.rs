//! Generic OAuth plugin support.

mod account;
mod config;
mod discovery;
mod errors;
mod provider;
pub mod providers;
mod route_http;
mod route_support;
mod routes;
mod user_info;

use openauth_core::plugin::{AuthPlugin, PluginInitOutput};
use openauth_oauth::oauth2::SocialOAuthProvider;
use std::collections::BTreeSet;
use std::sync::Arc;

pub const UPSTREAM_PLUGIN_ID: &str = "generic-oauth";

pub use config::{
    GenericOAuthConfig, GenericOAuthFlow, GenericOAuthGetToken, GenericOAuthGetUserInfo,
    GenericOAuthMapProfileToUser, GenericOAuthOptions, GenericOAuthParams,
    GenericOAuthParamsCallback, GenericOAuthParamsContext, GenericOAuthParamsFuture,
    GenericOAuthRefreshAccessToken, GenericOAuthRevokeToken, GenericOAuthTokenRequest,
    GenericOAuthVerifyIdToken,
};
pub use errors::{
    INVALID_OAUTH_CONFIG, INVALID_OAUTH_CONFIGURATION, ISSUER_MISMATCH, ISSUER_MISSING,
    PROVIDER_CONFIG_NOT_FOUND, PROVIDER_ID_REQUIRED, SESSION_REQUIRED, TOKEN_URL_NOT_FOUND,
};
pub use provider::GenericOAuthProvider;
pub use providers::{
    auth0, gumroad, hubspot, keycloak, line, microsoft_entra_id, okta, patreon, slack,
    Auth0Options, BaseOAuthProviderOptions, GumroadOptions, HubSpotOptions, KeycloakOptions,
    LineOptions, MicrosoftEntraIdOptions, OktaOptions, PatreonOptions, SlackOptions,
};

/// Build the Better Auth-compatible generic OAuth plugin.
pub fn generic_oauth_with(options: GenericOAuthOptions) -> AuthPlugin {
    let init_options = options.clone();
    let discovery_cache = discovery::DiscoveryCache::default();
    let init_discovery_cache = discovery_cache.clone();
    AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_options(options.to_json())
        .with_error_code(errors::error_code(
            INVALID_OAUTH_CONFIGURATION,
            "Invalid OAuth configuration",
        ))
        .with_error_code(errors::error_code(
            TOKEN_URL_NOT_FOUND,
            "Invalid OAuth configuration. Token URL not found.",
        ))
        .with_error_code(errors::error_code(
            PROVIDER_CONFIG_NOT_FOUND,
            "No config found for provider",
        ))
        .with_error_code(errors::error_code(
            PROVIDER_ID_REQUIRED,
            "Provider ID is required",
        ))
        .with_error_code(errors::error_code(
            INVALID_OAUTH_CONFIG,
            "Invalid OAuth configuration.",
        ))
        .with_error_code(errors::error_code(SESSION_REQUIRED, "Session is required"))
        .with_error_code(errors::error_code(
            ISSUER_MISMATCH,
            "OAuth issuer mismatch. The authorization server issuer does not match the expected value (RFC 9207).",
        ))
        .with_error_code(errors::error_code(
            ISSUER_MISSING,
            "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207).",
        ))
        .with_endpoint(routes::sign_in_oauth2_endpoint(
            options.clone(),
            discovery_cache.clone(),
        ))
        .with_endpoint(routes::oauth2_callback_endpoint(
            options.clone(),
            discovery_cache.clone(),
        ))
        .with_endpoint(routes::oauth2_link_endpoint(options, discovery_cache))
        .with_init(move |_context| {
            let mut output = PluginInitOutput::new();
            let mut seen = BTreeSet::new();
            for config in &init_options.config {
                if !seen.insert(config.provider_id.clone()) {
                    continue;
                }
                let provider: Arc<dyn SocialOAuthProvider> =
                    Arc::new(GenericOAuthProvider::with_discovery_cache(
                        config.clone(),
                        init_discovery_cache.clone(),
                    ));
                output = output.social_provider(provider);
            }
            Ok(output)
        })
}
