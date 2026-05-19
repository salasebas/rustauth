//! Server-side enterprise single sign-on support for OpenAuth.
//!
//! The crate exposes an OpenAuth plugin that adds Better Auth-compatible SSO
//! provider management, OIDC sign-in, SAML ACS, SAML metadata, domain
//! verification, and SAML single logout endpoints.
//!
//! # SAML support
//!
//! SAML is currently limited to compatibility scaffolding. Signed and encrypted
//! SAML messages fail closed until OpenAuth has a dedicated, auditable XML
//! signature backend. Prefer OIDC for new IdP integrations.
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
#[path = "oidc/mod.rs"]
mod oidc_impl;
mod openapi;
mod options;
mod org;
mod routes;
#[path = "saml/mod.rs"]
mod saml_impl;
mod schema;
mod secrets;
mod state;
mod store;
mod utils;

/// Stable SSO account-linking helpers.
pub mod linking {
    pub use crate::linking_impl::{
        assign_organization_by_domain, assign_organization_from_provider,
        provider_matches_email_domain, validate_provider_domains, NormalizedSsoProfile,
    };
}

/// Stable OIDC helpers used by the SSO plugin.
pub mod oidc {
    /// OIDC discovery URL helpers.
    pub mod discovery {
        pub use crate::oidc_impl::discovery::{compute_discovery_url, normalize_url};
    }

    /// OIDC redirect URI helpers.
    pub mod flow {
        pub use crate::oidc_impl::flow::oidc_redirect_uri;
    }
}

/// Stable SAML validation helpers used by the SSO plugin.
pub mod saml {
    /// SAML assertion parsing and structural validation helpers.
    pub mod assertions {
        pub use crate::saml_impl::assertions::{
            count_assertions, parse_saml_response, parse_saml_response_with_decryption,
            validate_single_assertion, AssertionCounts, ParsedSamlAssertion, ParsedSamlResponse,
            ParsedSubjectConfirmation, SamlResponseParseError,
        };
    }

    /// SAML XML well-formedness and parser boundary helpers.
    pub mod xml {
        pub use crate::saml_impl::xml::validate_saml_xml;
    }

    pub use crate::saml_impl::{
        collect_saml_runtime_algorithms, validate_saml_config_algorithms,
        validate_saml_config_algorithms_with_policy, validate_saml_runtime_algorithms,
        validate_saml_timestamp, DataEncryptionAlgorithm, DeprecatedAlgorithmBehavior,
        DigestAlgorithm, KeyEncryptionAlgorithm, SamlConditions, SamlRuntimeAlgorithmPolicy,
        SamlRuntimeAlgorithms, SamlSecurityError, SignatureAlgorithm, TimestampValidationOptions,
    };
}

pub use errors::{sso_error_category, sso_error_descriptors, SsoErrorCategory, SsoErrorDescriptor};
pub use linking::NormalizedSsoProfile;
pub use options::{
    DnsTxtResolver, DomainVerificationOptions, OidcConfig, OidcMapping,
    OrganizationProvisioningOptions, OrganizationRoleInput, OrganizationRoleResolver,
    ProvidersLimitResolver, ProvisionUserInput, ProvisionUserResolver, SamlAlgorithmOptions,
    SamlConfig, SamlIdpMetadata, SamlMapping, SamlOptions, SamlService, SamlSpMetadata,
    SsoAuditEvent, SsoAuditEventKind, SsoAuditEventResolver, SsoAuditSeverity, SsoOptions,
    SsoProvider, SsoRateLimitOptions, TokenEndpointAuthentication,
};
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

    plugin = plugin
        .with_async_before_hook("/sign-out", |context, request| {
            Box::pin(hooks::capture_sign_out_session(context, request))
        })
        .with_async_after_hook("/sign-out", |context, request, response| {
            Box::pin(hooks::cleanup_sign_out_session(context, request, response))
        });

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
    vec![
        PluginRateLimitRule::new("/sso/register", options.registration.clone()),
        PluginRateLimitRule::new(
            "/sso/request-domain-verification",
            options.domain_verification.clone(),
        ),
        PluginRateLimitRule::new("/sso/verify-domain", options.domain_verification.clone()),
        PluginRateLimitRule::new("/sso/callback", options.oidc_callback.clone()),
        PluginRateLimitRule::new("/sso/callback/:providerId", options.oidc_callback.clone()),
        PluginRateLimitRule::new("/sso/saml2/callback/:providerId", options.saml.clone()),
        PluginRateLimitRule::new("/sso/saml2/sp/acs/:providerId", options.saml.clone()),
        PluginRateLimitRule::new("/sso/saml2/sp/slo/:providerId", options.saml.clone()),
        PluginRateLimitRule::new("/sso/saml2/logout/:providerId", options.saml.clone()),
    ]
}
