use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Secret string wrapper that redacts its value in `Debug` output.
///
/// Serialization intentionally exposes the wrapped value so provider configs
/// can be persisted and later used for token exchange. Do not serialize this
/// type into logs, API responses, or other user-visible surfaces.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the raw secret value.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the raw secret value.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString(REDACTED)")
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.expose_secret()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// OIDC configuration for an enterprise SSO provider.
pub struct OidcProviderConfig {
    /// OIDC issuer URL.
    pub issuer: String,
    /// Whether authorization requests should use PKCE.
    pub pkce: bool,
    /// OAuth/OIDC client id.
    pub client_id: String,
    /// OAuth/OIDC client secret. Debug output is redacted.
    pub client_secret: SecretString,
    /// OIDC discovery document URL.
    pub discovery_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit authorization endpoint override.
    pub authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit token endpoint override.
    pub token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit UserInfo endpoint override.
    pub user_info_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Explicit JWKS endpoint override.
    pub jwks_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional OAuth token revocation endpoint discovered from the IdP.
    pub revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional OIDC end-session endpoint discovered from the IdP.
    pub end_session_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional OAuth token introspection endpoint discovered from the IdP.
    pub introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Token endpoint authentication method.
    pub token_endpoint_authentication: Option<TokenEndpointAuthentication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Authorization request scopes.
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Provider claim mapping.
    pub mapping: Option<OidcProfileMapping>,
    /// Override existing OpenAuth user fields with mapped OIDC values on login.
    pub override_user_info: bool,
}

/// Backward-compatible OIDC provider config alias.
pub type OidcConfig = OidcProviderConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Supported OAuth token endpoint authentication methods.
pub enum TokenEndpointAuthentication {
    /// Send client credentials through HTTP Basic authentication.
    ClientSecretBasic,
    /// Send client credentials in the token request body.
    ClientSecretPost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Mapping from OIDC claims to OpenAuth profile fields.
pub struct OidcProfileMapping {
    /// Claim used as the external account id.
    pub id: Option<String>,
    /// Claim used as email.
    pub email: Option<String>,
    /// Claim used as email verification status.
    pub email_verified: Option<String>,
    /// Claim used as display name.
    pub name: Option<String>,
    /// Claim used as avatar URL.
    pub image: Option<String>,
    /// Additional claim mappings exposed to hooks as raw attributes.
    pub extra_fields: Option<BTreeMap<String, String>>,
}

/// Backward-compatible OIDC mapping alias.
pub type OidcMapping = OidcProfileMapping;
