//! Enterprise OIDC relying-party support for OpenAuth.
//!
//! This crate is for OpenAuth acting as a client of external OIDC identity
//! providers. OpenAuth's own OAuth/OIDC provider implementation lives in
//! `openauth-oauth-provider`.

pub mod discovery;
pub mod flow;
pub mod options;

pub use discovery::{
    compute_discovery_url, discover_oidc_config, discover_oidc_config_with_origin_validator,
    ensure_runtime_oidc_config_with_origin_validator, fetch_discovery_document,
    is_configured_oidc_endpoint, needs_runtime_discovery, normalize_absolute_http_url,
    normalize_discovery_urls, normalize_endpoint_url, normalize_url,
    select_token_endpoint_authentication, validate_configured_oidc_endpoint_origins,
    validate_discovery_document, validate_discovery_url, validate_issuer_url,
    HydratedOidcDiscovery, OidcDiscoveryDocument, OidcDiscoveryError, OidcEndpointConfig,
    OidcRuntimeRequirement, PartialOidcDiscoveryConfig, REQUIRED_DISCOVERY_FIELDS,
};
pub use flow::{oidc_redirect_uri, OidcFlowOptions};
pub use options::{
    OidcConfig, OidcMapping, OidcProfileMapping, OidcProviderConfig, SecretString,
    TokenEndpointAuthentication,
};

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
