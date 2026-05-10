//! OAuth 2.0 structure for OpenAuth.
//!
//! This module is intentionally structure-only in the initial core port.

pub mod authorization_url;
pub mod client_credentials_token;
pub mod provider;
pub mod refresh_access_token;
pub mod tokens;
pub mod validate_authorization_code;
pub mod verify;

pub use provider::OAuthProviderMetadata;
