//! Server-side enterprise single sign-on support for OpenAuth.
//!
//! The crate exposes an OpenAuth plugin that adds Better Auth-compatible SSO
//! provider management, OIDC sign-in, SAML ACS, SAML metadata, domain
//! verification, and SAML single logout endpoints.
//!
//! # SAML support
//!
//! SAML 2.0 SP flows (sign-in, ACS, metadata, SLO) are implemented via the
//! [`openauth_saml`] crate and the pinned [`opensaml`] dependency. Enable the
//! `saml` feature on this crate; use `saml-signed` on [`openauth_saml`] for
//! XMLDSig and XML-Enc. Without `saml-signed`, signed or encrypted IdP messages
//! are rejected fail-closed.
//!
//! # Example
//!
//! ```no_run
//! use openauth_sso::{sso, SsoOptions};
//!
//! let plugin = sso(SsoOptions::default());
//! assert_eq!(plugin.id, "sso");
//! ```

mod audit;
mod errors;
mod hooks;
#[path = "linking.rs"]
mod linking_impl;
mod openapi;
mod options;
mod org;
mod routes;
mod schema;
mod secrets;
mod state;
mod store;
mod utils;

#[cfg(feature = "oidc")]
pub(crate) use openauth_oidc as oidc_impl;
#[cfg(feature = "saml")]
pub(crate) use openauth_saml as saml_impl;

/// Stable SSO account-linking helpers.
pub mod linking {
    pub use crate::linking_impl::{
        assign_organization_by_domain, assign_organization_from_provider,
        provider_matches_email_domain, validate_provider_domains, NormalizedSsoProfile,
    };
}

#[cfg(feature = "oidc")]
pub use openauth_oidc as oidc;
pub use openauth_oidc::{OidcProfileMapping, OidcProviderConfig};
#[cfg(feature = "saml")]
pub use openauth_saml as saml;

pub use errors::{sso_error_category, sso_error_descriptors, SsoErrorCategory, SsoErrorDescriptor};
pub use linking::NormalizedSsoProfile;
#[cfg(not(feature = "saml"))]
pub use options::DeprecatedAlgorithmBehavior;
pub use options::{
    DnsTxtResolver, DomainVerificationOptions, OidcConfig, OidcMapping, OidcOptions,
    OrganizationProvisioningOptions, OrganizationRoleInput, OrganizationRoleResolver,
    ProvidersLimitResolver, ProvisionUserInput, ProvisionUserResolver, SamlAlgorithmOptions,
    SamlConfig, SamlIdpMetadata, SamlMapping, SamlOptions, SamlService, SamlSpMetadata,
    SsoAuditEvent, SsoAuditEventKind, SsoAuditEventResolver, SsoAuditSeverity, SsoOptions,
    SsoProvider, SsoRateLimitOptions, TokenEndpointAuthentication, DEFAULT_MAX_SAML_METADATA_SIZE,
    DEFAULT_MAX_SAML_RESPONSE_SIZE,
};
#[cfg(feature = "saml")]
pub use saml::DeprecatedAlgorithmBehavior;
pub use secrets::SecretString;
pub use store::{
    CreateSsoProviderInput, SanitizedSsoProvider, SsoProviderRecord, SsoProviderStore,
};

use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};
use std::sync::Arc;

/// Better Auth upstream plugin identifier used for endpoint and schema parity.
pub const UPSTREAM_PLUGIN_ID: &str = "sso";

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the server-side SSO plugin.
///
/// The returned [`AuthPlugin`] contributes
/// the `sso_providers` schema, SSO endpoints, rate limit rules, OpenAPI
/// metadata, and hooks for organization assignment and SAML logout cleanup.
#[must_use]
pub fn sso(options: SsoOptions) -> AuthPlugin {
    let options = Arc::new(options);
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID).with_version(VERSION);

    for contribution in schema::contributions(&options) {
        plugin = plugin.with_schema(contribution);
    }
    for code in errors::plugin_error_codes() {
        plugin = plugin.with_error_code(code);
    }
    for endpoint in routes::endpoints(Arc::clone(&options)) {
        plugin = plugin.with_endpoint(endpoint);
    }
    for rule in rate_limit_rules(&options.rate_limit) {
        plugin = plugin.with_rate_limit(rule);
    }

    #[cfg(feature = "saml")]
    {
        plugin = plugin
            .with_async_before_hook("/sign-out", |context, request| {
                Box::pin(hooks::capture_sign_out_session(context, request))
            })
            .with_async_after_hook("/sign-out", |context, request, response| {
                Box::pin(hooks::cleanup_sign_out_session(context, request, response))
            });
    }

    for path in [
        "/sign-up/email",
        "/sign-in/email",
        "/sign-in/social",
        "/sign-in/oauth2",
        "/callback/:id",
    ] {
        let hook_options = Arc::clone(&options);
        plugin = plugin.with_async_after_hook(path, move |context, request, response| {
            Box::pin(hooks::assign_domain_organization_after_auth(
                context,
                request,
                response,
                Arc::clone(&hook_options),
            ))
        });
    }

    plugin
}

fn rate_limit_rules(options: &SsoRateLimitOptions) -> Vec<PluginRateLimitRule> {
    if !options.enabled {
        return Vec::new();
    }
    let mut rules = vec![
        PluginRateLimitRule::new("/sso/register", options.registration.clone()),
        PluginRateLimitRule::new(
            "/sso/request-domain-verification",
            options.domain_verification.clone(),
        ),
        PluginRateLimitRule::new("/sso/verify-domain", options.domain_verification.clone()),
    ];
    #[cfg(feature = "oidc")]
    {
        rules.push(PluginRateLimitRule::new(
            "/sso/callback",
            options.oidc_callback.clone(),
        ));
        rules.push(PluginRateLimitRule::new(
            "/sso/callback/:providerId",
            options.oidc_callback.clone(),
        ));
    }
    #[cfg(feature = "saml")]
    {
        rules.push(PluginRateLimitRule::new(
            "/sso/saml2/callback/:providerId",
            options.saml.clone(),
        ));
        rules.push(PluginRateLimitRule::new(
            "/sso/saml2/sp/acs/:providerId",
            options.saml.clone(),
        ));
        rules.push(PluginRateLimitRule::new(
            "/sso/saml2/sp/slo/:providerId",
            options.saml.clone(),
        ));
        rules.push(PluginRateLimitRule::new(
            "/sso/saml2/logout/:providerId",
            options.saml.clone(),
        ));
    }
    rules
}
