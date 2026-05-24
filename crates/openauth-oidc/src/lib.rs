//! Enterprise OIDC relying-party support for OpenAuth.
//!
//! This crate is for OpenAuth acting as a client of external OIDC identity
//! providers. OpenAuth's own OAuth/OIDC provider implementation lives in
//! `openauth-oauth-provider`.

pub mod discovery;
pub mod flow;
pub mod options;

mod utils;

pub use discovery::{
    compute_discovery_url, discover_oidc_config, discover_oidc_config_with_origin_validator,
    ensure_runtime_oidc_config_with_origin_validator, needs_runtime_discovery,
    normalize_absolute_http_url, normalize_endpoint_url, normalize_url,
    validate_configured_oidc_endpoint_origins, validate_issuer_url, HydratedOidcDiscovery,
    OidcDiscoveryDocument, OidcDiscoveryError, OidcEndpointConfig, OidcRuntimeRequirement,
    PartialOidcDiscoveryConfig,
};
pub use flow::{oidc_redirect_uri, OidcFlowOptions};
pub use options::{
    OidcConfig, OidcMapping, OidcProfileMapping, OidcProviderConfig, SecretString,
    TokenEndpointAuthentication,
};

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
