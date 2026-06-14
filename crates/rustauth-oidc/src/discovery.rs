use serde::{Deserialize, Serialize};
use url::Url;

use crate::options::{OidcConfig, TokenEndpointAuthentication};

/// Required fields that must be present in a valid OIDC discovery document.
///
/// Matches Better Auth `REQUIRED_DISCOVERY_FIELDS` in `@better-auth/sso`.
pub const REQUIRED_DISCOVERY_FIELDS: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_uri",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: String,
    #[serde(default)]
    pub token_endpoint: String,
    #[serde(default)]
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub subject_types_supported: Option<Vec<String>>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    pub claims_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Returns true when an optional endpoint URL is present and non-empty.
///
/// Better Auth treats empty strings as missing for runtime discovery
/// (`!config.tokenEndpoint` is true for `""`).
pub fn is_configured_oidc_endpoint(endpoint: Option<&str>) -> bool {
    endpoint.is_some_and(|value| !value.is_empty())
}

fn merge_required_endpoint(existing: Option<&str>, discovered: String) -> String {
    existing
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or(discovered)
}

fn merge_optional_endpoint(existing: Option<&str>, discovered: Option<String>) -> Option<String> {
    if let Some(value) = existing.filter(|value| !value.is_empty()) {
        return Some(value.to_owned());
    }
    discovered
}

fn non_empty_endpoint(endpoint: Option<&str>) -> Option<&str> {
    endpoint.filter(|value| !value.is_empty())
}

pub fn compute_discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

pub fn normalize_url(value: &str) -> Result<String, url::ParseError> {
    Url::parse(value).map(|url| url.to_string())
}

/// Normalize and validate an absolute HTTP(S) URL.
///
/// This is stricter than [`normalize_url`], which is retained for backward
/// compatibility and only parses the URL.
pub fn normalize_absolute_http_url(
    field: &'static str,
    value: &str,
) -> Result<String, OidcDiscoveryError> {
    validate_trusted_url(field, value, &|_| true)?;
    Url::parse(value)
        .map(|url| url.to_string())
        .map_err(|source| OidcDiscoveryError::InvalidUrl {
            field,
            reason: source.to_string(),
        })
}

/// Normalize an OIDC endpoint URL, resolving relative endpoints against the
/// issuer origin and path.
pub fn normalize_endpoint_url(
    field: &'static str,
    endpoint: &str,
    issuer: &str,
) -> Result<String, OidcDiscoveryError> {
    normalize_endpoint(field, endpoint, issuer)
}

pub fn validate_issuer_url(value: &str) -> Result<String, openidconnect::url::ParseError> {
    openidconnect::IssuerUrl::new(value.to_owned()).map(|issuer| issuer.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydratedOidcDiscovery {
    pub issuer: String,
    pub discovery_endpoint: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_endpoint: String,
    pub user_info_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub end_session_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub token_endpoint_authentication: TokenEndpointAuthentication,
    pub scopes_supported: Option<Vec<String>>,
}

pub async fn discover_oidc_config(
    issuer: &str,
    discovery_endpoint: Option<&str>,
    existing: PartialOidcDiscoveryConfig<'_>,
    client: &reqwest::Client,
) -> Result<HydratedOidcDiscovery, OidcDiscoveryError> {
    discover_oidc_config_with_origin_validator(
        issuer,
        discovery_endpoint,
        existing,
        |_| true,
        client,
    )
    .await
}

pub async fn discover_oidc_config_with_origin_validator<F>(
    issuer: &str,
    discovery_endpoint: Option<&str>,
    existing: PartialOidcDiscoveryConfig<'_>,
    is_trusted_origin: F,
    client: &reqwest::Client,
) -> Result<HydratedOidcDiscovery, OidcDiscoveryError>
where
    F: Fn(&str) -> bool,
{
    let discovery_endpoint = discovery_endpoint
        .map(str::to_owned)
        .or_else(|| existing.discovery_endpoint.map(str::to_owned))
        .unwrap_or_else(|| compute_discovery_url(issuer));
    validate_trusted_url(
        "discovery_endpoint",
        &discovery_endpoint,
        &is_trusted_origin,
    )?;
    let document = fetch_discovery_document(&discovery_endpoint, client).await?;
    validate_discovery_document(&document, issuer)?;
    let normalized = normalize_discovery_document(document, issuer)?;
    let token_endpoint_authentication =
        select_token_endpoint_authentication(&normalized, existing.token_endpoint_authentication);

    let hydrated = HydratedOidcDiscovery {
        issuer: existing
            .issuer
            .map(str::to_owned)
            .unwrap_or(normalized.issuer),
        discovery_endpoint,
        authorization_endpoint: merge_required_endpoint(
            existing.authorization_endpoint,
            normalized.authorization_endpoint,
        ),
        token_endpoint: merge_required_endpoint(existing.token_endpoint, normalized.token_endpoint),
        jwks_endpoint: merge_required_endpoint(existing.jwks_endpoint, normalized.jwks_uri),
        user_info_endpoint: merge_optional_endpoint(
            existing.user_info_endpoint,
            normalized.userinfo_endpoint,
        ),
        revocation_endpoint: merge_optional_endpoint(
            existing.revocation_endpoint,
            normalized.revocation_endpoint,
        ),
        end_session_endpoint: merge_optional_endpoint(
            existing.end_session_endpoint,
            normalized.end_session_endpoint,
        ),
        introspection_endpoint: merge_optional_endpoint(
            existing.introspection_endpoint,
            normalized.introspection_endpoint,
        ),
        token_endpoint_authentication,
        scopes_supported: normalized.scopes_supported,
    };
    validate_trusted_url(
        "authorization_endpoint",
        &hydrated.authorization_endpoint,
        &is_trusted_origin,
    )?;
    validate_trusted_url(
        "token_endpoint",
        &hydrated.token_endpoint,
        &is_trusted_origin,
    )?;
    validate_trusted_url("jwks_uri", &hydrated.jwks_endpoint, &is_trusted_origin)?;
    if let Some(user_info_endpoint) = &hydrated.user_info_endpoint {
        validate_trusted_url("userinfo_endpoint", user_info_endpoint, &is_trusted_origin)?;
    }
    if let Some(revocation_endpoint) = &hydrated.revocation_endpoint {
        validate_trusted_url(
            "revocation_endpoint",
            revocation_endpoint,
            &is_trusted_origin,
        )?;
    }
    if let Some(end_session_endpoint) = &hydrated.end_session_endpoint {
        validate_trusted_url(
            "end_session_endpoint",
            end_session_endpoint,
            &is_trusted_origin,
        )?;
    }
    if let Some(introspection_endpoint) = &hydrated.introspection_endpoint {
        validate_trusted_url(
            "introspection_endpoint",
            introspection_endpoint,
            &is_trusted_origin,
        )?;
    }
    Ok(hydrated)
}

pub trait OidcEndpointConfig {
    fn discovery_endpoint(&self) -> &str;
    fn authorization_endpoint(&self) -> Option<&str>;
    fn token_endpoint(&self) -> Option<&str>;
    fn user_info_endpoint(&self) -> Option<&str>;
    fn jwks_endpoint(&self) -> Option<&str>;
    fn revocation_endpoint(&self) -> Option<&str>;
    fn end_session_endpoint(&self) -> Option<&str>;
    fn introspection_endpoint(&self) -> Option<&str>;
}

impl OidcEndpointConfig for OidcConfig {
    fn discovery_endpoint(&self) -> &str {
        &self.discovery_endpoint
    }

    fn authorization_endpoint(&self) -> Option<&str> {
        self.authorization_endpoint.as_deref()
    }

    fn token_endpoint(&self) -> Option<&str> {
        self.token_endpoint.as_deref()
    }

    fn user_info_endpoint(&self) -> Option<&str> {
        self.user_info_endpoint.as_deref()
    }

    fn jwks_endpoint(&self) -> Option<&str> {
        self.jwks_endpoint.as_deref()
    }

    fn revocation_endpoint(&self) -> Option<&str> {
        self.revocation_endpoint.as_deref()
    }

    fn end_session_endpoint(&self) -> Option<&str> {
        self.end_session_endpoint.as_deref()
    }

    fn introspection_endpoint(&self) -> Option<&str> {
        self.introspection_endpoint.as_deref()
    }
}

pub fn validate_configured_oidc_endpoint_origins<C, F>(
    config: &C,
    is_trusted_origin: F,
) -> Result<(), OidcDiscoveryError>
where
    C: OidcEndpointConfig + ?Sized,
    F: Fn(&str) -> bool,
{
    validate_trusted_url(
        "discovery_endpoint",
        config.discovery_endpoint(),
        &is_trusted_origin,
    )?;
    if let Some(endpoint) = config.authorization_endpoint() {
        validate_trusted_url("authorization_endpoint", endpoint, &is_trusted_origin)?;
    }
    if let Some(endpoint) = config.token_endpoint() {
        validate_trusted_url("token_endpoint", endpoint, &is_trusted_origin)?;
    }
    if let Some(endpoint) = config.user_info_endpoint() {
        validate_trusted_url("userinfo_endpoint", endpoint, &is_trusted_origin)?;
    }
    if let Some(endpoint) = config.jwks_endpoint() {
        validate_trusted_url("jwks_uri", endpoint, &is_trusted_origin)?;
    }
    if let Some(endpoint) = config.revocation_endpoint() {
        validate_trusted_url("revocation_endpoint", endpoint, &is_trusted_origin)?;
    }
    if let Some(endpoint) = config.end_session_endpoint() {
        validate_trusted_url("end_session_endpoint", endpoint, &is_trusted_origin)?;
    }
    if let Some(endpoint) = config.introspection_endpoint() {
        validate_trusted_url("introspection_endpoint", endpoint, &is_trusted_origin)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PartialOidcDiscoveryConfig<'a> {
    pub issuer: Option<&'a str>,
    pub discovery_endpoint: Option<&'a str>,
    pub authorization_endpoint: Option<&'a str>,
    pub token_endpoint: Option<&'a str>,
    pub user_info_endpoint: Option<&'a str>,
    pub jwks_endpoint: Option<&'a str>,
    pub revocation_endpoint: Option<&'a str>,
    pub end_session_endpoint: Option<&'a str>,
    pub introspection_endpoint: Option<&'a str>,
    pub token_endpoint_authentication: Option<TokenEndpointAuthentication>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcRuntimeRequirement {
    SignIn,
    Callback,
}

impl OidcRuntimeRequirement {
    pub fn is_satisfied(self, config: &OidcConfig) -> bool {
        // Better Auth performs runtime discovery unless the provider has the
        // complete OIDC endpoint set needed across sign-in and callback.
        // Preserve the enum for API clarity while keeping both modes aligned
        // with that upstream contract.
        let _ = self;
        is_configured_oidc_endpoint(config.authorization_endpoint.as_deref())
            && is_configured_oidc_endpoint(config.token_endpoint.as_deref())
            && is_configured_oidc_endpoint(config.jwks_endpoint.as_deref())
    }
}

pub fn needs_runtime_discovery(config: &OidcConfig, requirement: OidcRuntimeRequirement) -> bool {
    !requirement.is_satisfied(config)
}

pub async fn ensure_runtime_oidc_config_with_origin_validator<F>(
    issuer: &str,
    config: OidcConfig,
    requirement: OidcRuntimeRequirement,
    is_trusted_origin: F,
    validate_configured_origins: bool,
    client: &reqwest::Client,
) -> Result<OidcConfig, OidcDiscoveryError>
where
    F: Fn(&str) -> bool,
{
    if !needs_runtime_discovery(&config, requirement) {
        if validate_configured_origins {
            validate_configured_oidc_endpoint_origins(&config, &is_trusted_origin)?;
        }
        return Ok(config);
    }

    let hydrated = discover_oidc_config_with_origin_validator(
        issuer,
        (!config.discovery_endpoint.is_empty()).then_some(config.discovery_endpoint.as_str()),
        PartialOidcDiscoveryConfig {
            issuer: Some(config.issuer.as_str()),
            discovery_endpoint: (!config.discovery_endpoint.is_empty())
                .then_some(config.discovery_endpoint.as_str()),
            authorization_endpoint: non_empty_endpoint(config.authorization_endpoint.as_deref()),
            token_endpoint: non_empty_endpoint(config.token_endpoint.as_deref()),
            user_info_endpoint: non_empty_endpoint(config.user_info_endpoint.as_deref()),
            jwks_endpoint: non_empty_endpoint(config.jwks_endpoint.as_deref()),
            revocation_endpoint: non_empty_endpoint(config.revocation_endpoint.as_deref()),
            end_session_endpoint: non_empty_endpoint(config.end_session_endpoint.as_deref()),
            introspection_endpoint: non_empty_endpoint(config.introspection_endpoint.as_deref()),
            token_endpoint_authentication: config.token_endpoint_authentication,
        },
        &is_trusted_origin,
        client,
    )
    .await?;

    let hydrated_config = OidcConfig {
        issuer: hydrated.issuer,
        pkce: config.pkce,
        client_id: config.client_id,
        client_secret: config.client_secret,
        discovery_endpoint: hydrated.discovery_endpoint,
        authorization_endpoint: Some(hydrated.authorization_endpoint),
        token_endpoint: Some(hydrated.token_endpoint),
        user_info_endpoint: hydrated.user_info_endpoint,
        jwks_endpoint: Some(hydrated.jwks_endpoint),
        revocation_endpoint: hydrated.revocation_endpoint,
        end_session_endpoint: hydrated.end_session_endpoint,
        introspection_endpoint: hydrated.introspection_endpoint,
        token_endpoint_authentication: Some(hydrated.token_endpoint_authentication),
        scopes: config.scopes,
        mapping: config.mapping,
        override_user_info: config.override_user_info,
    };

    if validate_configured_origins {
        validate_configured_oidc_endpoint_origins(&hydrated_config, &is_trusted_origin)?;
    }
    Ok(hydrated_config)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OidcDiscoveryError {
    #[error("OIDC discovery request failed: {0}")]
    Request(String),
    #[error("OIDC discovery endpoint not found")]
    NotFound,
    #[error("OIDC discovery request timed out")]
    Timeout,
    #[error("OIDC discovery endpoint returned invalid JSON: {0}")]
    InvalidJson(String),
    #[error("OIDC discovery document contains untrusted URL for `{field}`: {url}")]
    UntrustedOrigin { field: &'static str, url: String },
    #[error("OIDC discovery document is missing required field `{0}`")]
    MissingField(&'static str),
    #[error("OIDC discovery document is missing required fields: {0:?}")]
    MissingFields(Vec<&'static str>),
    #[error("OIDC discovery issuer mismatch")]
    IssuerMismatch,
    #[error("OIDC discovery document contains invalid URL for `{field}`: {reason}")]
    InvalidUrl { field: &'static str, reason: String },
}

impl OidcDiscoveryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Timeout => "discovery_timeout",
            Self::NotFound => "discovery_not_found",
            Self::InvalidJson(_) => "discovery_invalid_json",
            Self::InvalidUrl { .. } => "discovery_invalid_url",
            Self::UntrustedOrigin { .. } => "discovery_untrusted_origin",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::MissingField(_) | Self::MissingFields(_) => "discovery_incomplete",
            Self::Request(_) => "discovery_unexpected_error",
        }
    }

    pub fn status(&self) -> http::StatusCode {
        match self {
            Self::Timeout | Self::Request(_) => http::StatusCode::BAD_GATEWAY,
            Self::NotFound
            | Self::InvalidJson(_)
            | Self::InvalidUrl { .. }
            | Self::UntrustedOrigin { .. }
            | Self::IssuerMismatch
            | Self::MissingField(_)
            | Self::MissingFields(_) => http::StatusCode::BAD_REQUEST,
        }
    }
}

/// Validate a discovery URL before fetching.
pub fn validate_discovery_url<F>(url: &str, is_trusted_origin: F) -> Result<(), OidcDiscoveryError>
where
    F: Fn(&str) -> bool,
{
    validate_trusted_url("discovery_endpoint", url, &is_trusted_origin)
}

/// Fetch the OIDC discovery document from the IdP.
pub async fn fetch_discovery_document(
    discovery_endpoint: &str,
    client: &reqwest::Client,
) -> Result<OidcDiscoveryDocument, OidcDiscoveryError> {
    let response = client
        .get(discovery_endpoint)
        .header("accept", "application/json")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(classify_reqwest_error)?;
    let status = response.status();
    if status == http::StatusCode::NOT_FOUND {
        return Err(OidcDiscoveryError::NotFound);
    }
    if status == http::StatusCode::REQUEST_TIMEOUT {
        return Err(OidcDiscoveryError::Timeout);
    }
    let response = response
        .error_for_status()
        .map_err(classify_reqwest_error)?;
    response
        .json::<OidcDiscoveryDocument>()
        .await
        .map_err(|error| OidcDiscoveryError::InvalidJson(error.to_string()))
}

fn classify_reqwest_error(error: reqwest::Error) -> OidcDiscoveryError {
    if error.is_timeout() {
        return OidcDiscoveryError::Timeout;
    }
    if error.status() == Some(http::StatusCode::NOT_FOUND) {
        return OidcDiscoveryError::NotFound;
    }
    OidcDiscoveryError::Request(error.to_string())
}

/// Validate a discovery document for required fields and issuer match.
pub fn validate_discovery_document(
    document: &OidcDiscoveryDocument,
    issuer: &str,
) -> Result<(), OidcDiscoveryError> {
    let mut missing = Vec::new();
    for field in REQUIRED_DISCOVERY_FIELDS {
        let is_empty = match *field {
            "issuer" => document.issuer.is_empty(),
            "authorization_endpoint" => document.authorization_endpoint.is_empty(),
            "token_endpoint" => document.token_endpoint.is_empty(),
            "jwks_uri" => document.jwks_uri.is_empty(),
            _ => false,
        };
        if is_empty {
            missing.push(*field);
        }
    }
    if !missing.is_empty() {
        return Err(if missing.len() == 1 {
            OidcDiscoveryError::MissingField(missing[0])
        } else {
            OidcDiscoveryError::MissingFields(missing)
        });
    }
    if trim_trailing_slash(&document.issuer) != trim_trailing_slash(issuer) {
        return Err(OidcDiscoveryError::IssuerMismatch);
    }
    Ok(())
}

/// Normalize discovery document URLs and validate each endpoint origin.
pub fn normalize_discovery_urls<F>(
    document: OidcDiscoveryDocument,
    issuer: &str,
    is_trusted_origin: F,
) -> Result<OidcDiscoveryDocument, OidcDiscoveryError>
where
    F: Fn(&str) -> bool,
{
    let normalized = normalize_discovery_document(document, issuer)?;
    validate_trusted_url(
        "authorization_endpoint",
        &normalized.authorization_endpoint,
        &is_trusted_origin,
    )?;
    validate_trusted_url(
        "token_endpoint",
        &normalized.token_endpoint,
        &is_trusted_origin,
    )?;
    validate_trusted_url("jwks_uri", &normalized.jwks_uri, &is_trusted_origin)?;
    if let Some(userinfo_endpoint) = &normalized.userinfo_endpoint {
        validate_trusted_url("userinfo_endpoint", userinfo_endpoint, &is_trusted_origin)?;
    }
    if let Some(revocation_endpoint) = &normalized.revocation_endpoint {
        validate_trusted_url(
            "revocation_endpoint",
            revocation_endpoint,
            &is_trusted_origin,
        )?;
    }
    if let Some(end_session_endpoint) = &normalized.end_session_endpoint {
        validate_trusted_url(
            "end_session_endpoint",
            end_session_endpoint,
            &is_trusted_origin,
        )?;
    }
    if let Some(introspection_endpoint) = &normalized.introspection_endpoint {
        validate_trusted_url(
            "introspection_endpoint",
            introspection_endpoint,
            &is_trusted_origin,
        )?;
    }
    Ok(normalized)
}

fn normalize_discovery_document(
    mut document: OidcDiscoveryDocument,
    issuer: &str,
) -> Result<OidcDiscoveryDocument, OidcDiscoveryError> {
    document.authorization_endpoint = normalize_endpoint(
        "authorization_endpoint",
        &document.authorization_endpoint,
        issuer,
    )?;
    document.token_endpoint =
        normalize_endpoint("token_endpoint", &document.token_endpoint, issuer)?;
    document.jwks_uri = normalize_endpoint("jwks_uri", &document.jwks_uri, issuer)?;
    document.userinfo_endpoint = document
        .userinfo_endpoint
        .as_deref()
        .map(|endpoint| normalize_endpoint("userinfo_endpoint", endpoint, issuer))
        .transpose()?;
    document.revocation_endpoint = document
        .revocation_endpoint
        .as_deref()
        .map(|endpoint| normalize_endpoint("revocation_endpoint", endpoint, issuer))
        .transpose()?;
    document.end_session_endpoint = document
        .end_session_endpoint
        .as_deref()
        .map(|endpoint| normalize_endpoint("end_session_endpoint", endpoint, issuer))
        .transpose()?;
    document.introspection_endpoint = document
        .introspection_endpoint
        .as_deref()
        .map(|endpoint| normalize_endpoint("introspection_endpoint", endpoint, issuer))
        .transpose()?;
    Ok(document)
}

fn normalize_endpoint(
    field: &'static str,
    endpoint: &str,
    issuer: &str,
) -> Result<String, OidcDiscoveryError> {
    if let Ok(url) = Url::parse(endpoint) {
        ensure_supported_url_scheme(field, &url)?;
        return Ok(url.to_string());
    }

    let issuer_url = Url::parse(issuer).map_err(|source| OidcDiscoveryError::InvalidUrl {
        field,
        reason: source.to_string(),
    })?;
    let origin = issuer_url.origin().ascii_serialization();
    let base_path = issuer_url.path().trim_end_matches('/');
    let endpoint_path = endpoint.trim_start_matches('/');
    let url = Url::parse(&format!("{origin}{base_path}/{endpoint_path}")).map_err(|source| {
        OidcDiscoveryError::InvalidUrl {
            field,
            reason: source.to_string(),
        }
    })?;
    ensure_supported_url_scheme(field, &url)?;
    Ok(url.to_string())
}

fn validate_trusted_url<F>(
    field: &'static str,
    value: &str,
    is_trusted_origin: &F,
) -> Result<(), OidcDiscoveryError>
where
    F: Fn(&str) -> bool,
{
    let url = Url::parse(value).map_err(|source| OidcDiscoveryError::InvalidUrl {
        field,
        reason: source.to_string(),
    })?;
    ensure_supported_url_scheme(field, &url)?;
    if !is_trusted_origin(value) {
        return Err(OidcDiscoveryError::UntrustedOrigin {
            field,
            url: value.to_owned(),
        });
    }
    Ok(())
}

fn ensure_supported_url_scheme(field: &'static str, url: &Url) -> Result<(), OidcDiscoveryError> {
    if matches!(url.scheme(), "http" | "https") {
        return Ok(());
    }
    Err(OidcDiscoveryError::InvalidUrl {
        field,
        reason: format!("unsupported URL scheme `{}`", url.scheme()),
    })
}

/// Select the token endpoint authentication method from discovery metadata.
pub fn select_token_endpoint_authentication(
    document: &OidcDiscoveryDocument,
    existing: Option<TokenEndpointAuthentication>,
) -> TokenEndpointAuthentication {
    if let Some(existing) = existing {
        return existing;
    }
    let Some(supported) = &document.token_endpoint_auth_methods_supported else {
        return TokenEndpointAuthentication::ClientSecretBasic;
    };
    if supported
        .iter()
        .any(|method| method == "client_secret_basic")
    {
        return TokenEndpointAuthentication::ClientSecretBasic;
    }
    if supported
        .iter()
        .any(|method| method == "client_secret_post")
    {
        return TokenEndpointAuthentication::ClientSecretPost;
    }
    TokenEndpointAuthentication::ClientSecretBasic
}

fn trim_trailing_slash(value: &str) -> &str {
    value.strip_suffix('/').unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery_document(issuer: &str) -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: issuer.to_owned(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            jwks_uri: format!("{issuer}/keys"),
            userinfo_endpoint: Some(format!("{issuer}/userinfo")),
            revocation_endpoint: None,
            end_session_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_auth_methods_supported: None,
            scopes_supported: None,
            response_types_supported: None,
            subject_types_supported: None,
            id_token_signing_alg_values_supported: None,
            claims_supported: None,
            code_challenge_methods_supported: None,
        }
    }

    #[test]
    fn normalizes_relative_discovery_endpoints_against_issuer_path(
    ) -> Result<(), OidcDiscoveryError> {
        assert_eq!(
            normalize_endpoint(
                "token_endpoint",
                "oauth/token",
                "https://idp.example.com/tenant"
            )?,
            "https://idp.example.com/tenant/oauth/token"
        );
        assert_eq!(
            normalize_endpoint("jwks_uri", "/keys", "https://idp.example.com/tenant")?,
            "https://idp.example.com/tenant/keys"
        );
        let document = normalize_discovery_document(
            OidcDiscoveryDocument {
                issuer: "https://idp.example.com/tenant".to_owned(),
                authorization_endpoint: "authorize".to_owned(),
                token_endpoint: "token".to_owned(),
                jwks_uri: "keys".to_owned(),
                userinfo_endpoint: Some("userinfo".to_owned()),
                revocation_endpoint: Some("revoke".to_owned()),
                end_session_endpoint: Some("endsession".to_owned()),
                introspection_endpoint: Some("introspect".to_owned()),
                token_endpoint_auth_methods_supported: None,
                scopes_supported: None,
                response_types_supported: None,
                subject_types_supported: None,
                id_token_signing_alg_values_supported: None,
                claims_supported: None,
                code_challenge_methods_supported: None,
            },
            "https://idp.example.com/tenant",
        )?;
        assert_eq!(
            document.revocation_endpoint.as_deref(),
            Some("https://idp.example.com/tenant/revoke")
        );
        assert_eq!(
            document.end_session_endpoint.as_deref(),
            Some("https://idp.example.com/tenant/endsession")
        );
        assert_eq!(
            document.introspection_endpoint.as_deref(),
            Some("https://idp.example.com/tenant/introspect")
        );
        Ok(())
    }

    #[test]
    fn discovery_url_preserves_issuer_path() {
        assert_eq!(
            compute_discovery_url("https://idp.example.com/tenant/v1/"),
            "https://idp.example.com/tenant/v1/.well-known/openid-configuration"
        );
    }

    #[test]
    fn absolute_http_url_api_rejects_relative_and_non_http_values() -> Result<(), OidcDiscoveryError>
    {
        assert!(normalize_absolute_http_url("discovery_endpoint", "/relative").is_err());
        assert!(
            normalize_absolute_http_url("discovery_endpoint", "ftp://idp.example.com").is_err()
        );
        assert_eq!(
            normalize_absolute_http_url("discovery_endpoint", "https://idp.example.com")?,
            "https://idp.example.com/"
        );
        Ok::<(), OidcDiscoveryError>(())
    }

    #[test]
    fn normalize_endpoint_resolves_relative_urls_with_duplicate_slashes(
    ) -> Result<(), OidcDiscoveryError> {
        assert_eq!(
            normalize_endpoint(
                "token_endpoint",
                "//oauth2/token",
                "https://idp.example.com/base//",
            )?,
            "https://idp.example.com/base/oauth2/token"
        );
        assert_eq!(
            normalize_endpoint(
                "token_endpoint",
                "oauth2/token",
                "https://idp.example.com/base/"
            )?,
            "https://idp.example.com/base/oauth2/token"
        );
        Ok(())
    }

    #[test]
    fn endpoint_url_api_resolves_relative_values_against_issuer_path(
    ) -> Result<(), OidcDiscoveryError> {
        assert_eq!(
            normalize_endpoint_url(
                "authorization_endpoint",
                "/oauth2/authorize",
                "https://idp.example.com/tenant/",
            )?,
            "https://idp.example.com/tenant/oauth2/authorize"
        );
        assert!(normalize_endpoint_url(
            "authorization_endpoint",
            "ftp://idp.example.com/authorize",
            "https://idp.example.com/tenant/",
        )
        .is_err());
        Ok::<(), OidcDiscoveryError>(())
    }

    #[test]
    fn is_configured_oidc_endpoint_treats_empty_string_as_missing() {
        assert!(!is_configured_oidc_endpoint(None));
        assert!(!is_configured_oidc_endpoint(Some("")));
        assert!(is_configured_oidc_endpoint(Some(
            "https://idp.example.com/oauth2/v1/authorize"
        )));
    }

    #[test]
    fn runtime_discovery_treats_empty_string_endpoints_as_missing() {
        let config = OidcConfig {
            issuer: "https://idp.example.com".to_owned(),
            pkce: true,
            client_id: "client".to_owned(),
            client_secret: "secret".into(),
            discovery_endpoint: compute_discovery_url("https://idp.example.com"),
            authorization_endpoint: Some(String::new()),
            token_endpoint: Some("https://idp.example.com/token".to_owned()),
            user_info_endpoint: None,
            jwks_endpoint: Some("https://idp.example.com/keys".to_owned()),
            revocation_endpoint: None,
            end_session_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_authentication: None,
            scopes: None,
            mapping: None,
            override_user_info: false,
        };

        assert!(needs_runtime_discovery(
            &config,
            OidcRuntimeRequirement::SignIn
        ));
        assert!(needs_runtime_discovery(
            &config,
            OidcRuntimeRequirement::Callback
        ));
        assert!(!is_configured_oidc_endpoint(
            config.authorization_endpoint.as_deref()
        ));
    }

    #[test]
    fn runtime_discovery_requirements_match_sign_in_and_callback_needs() {
        let mut config = OidcConfig {
            issuer: "https://idp.example.com".to_owned(),
            pkce: true,
            client_id: "client".to_owned(),
            client_secret: "secret".into(),
            discovery_endpoint: compute_discovery_url("https://idp.example.com"),
            authorization_endpoint: None,
            token_endpoint: Some("https://idp.example.com/token".to_owned()),
            user_info_endpoint: Some("https://idp.example.com/userinfo".to_owned()),
            jwks_endpoint: None,
            revocation_endpoint: None,
            end_session_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_authentication: None,
            scopes: None,
            mapping: None,
            override_user_info: false,
        };

        assert!(needs_runtime_discovery(
            &config,
            OidcRuntimeRequirement::SignIn
        ));
        assert!(needs_runtime_discovery(
            &config,
            OidcRuntimeRequirement::Callback
        ));

        config.authorization_endpoint = Some("https://idp.example.com/authorize".to_owned());
        assert!(needs_runtime_discovery(
            &config,
            OidcRuntimeRequirement::SignIn
        ));
        assert!(needs_runtime_discovery(
            &config,
            OidcRuntimeRequirement::Callback
        ));

        config.user_info_endpoint = None;
        config.jwks_endpoint = Some("https://idp.example.com/keys".to_owned());
        assert!(!needs_runtime_discovery(
            &config,
            OidcRuntimeRequirement::SignIn
        ));
        assert!(!needs_runtime_discovery(
            &config,
            OidcRuntimeRequirement::Callback
        ));
    }

    #[test]
    fn discovery_errors_expose_stable_codes_and_statuses() {
        assert_eq!(
            OidcDiscoveryError::MissingField("issuer").code(),
            "discovery_incomplete"
        );
        assert_eq!(
            OidcDiscoveryError::MissingFields(vec!["issuer", "jwks_uri"]).code(),
            "discovery_incomplete"
        );
        assert_eq!(OidcDiscoveryError::IssuerMismatch.code(), "issuer_mismatch");
        assert_eq!(
            OidcDiscoveryError::InvalidUrl {
                field: "authorization_endpoint",
                reason: "bad URL".to_owned(),
            }
            .code(),
            "discovery_invalid_url"
        );
        assert_eq!(
            OidcDiscoveryError::Timeout.status(),
            http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            OidcDiscoveryError::InvalidJson("bad".to_owned()).status(),
            http::StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn discovery_validation_reports_all_missing_required_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let document: OidcDiscoveryDocument = serde_json::from_str(
            r#"{
                "issuer":"https://idp.example.com"
            }"#,
        )?;

        let error = match validate_discovery_document(&document, "https://idp.example.com") {
            Ok(()) => return Err("expected incomplete discovery document".into()),
            Err(error) => error,
        };

        assert_eq!(error.code(), "discovery_incomplete");
        assert!(matches!(
            error,
            OidcDiscoveryError::MissingFields(fields)
                if fields == vec!["authorization_endpoint", "token_endpoint", "jwks_uri"]
        ));
        Ok(())
    }

    #[test]
    fn discovery_validation_reports_each_missing_required_field() {
        for (field, document) in [
            (
                "issuer",
                OidcDiscoveryDocument {
                    issuer: String::new(),
                    ..discovery_document("https://idp.example.com")
                },
            ),
            (
                "authorization_endpoint",
                OidcDiscoveryDocument {
                    authorization_endpoint: String::new(),
                    ..discovery_document("https://idp.example.com")
                },
            ),
            (
                "token_endpoint",
                OidcDiscoveryDocument {
                    token_endpoint: String::new(),
                    ..discovery_document("https://idp.example.com")
                },
            ),
            (
                "jwks_uri",
                OidcDiscoveryDocument {
                    jwks_uri: String::new(),
                    ..discovery_document("https://idp.example.com")
                },
            ),
        ] {
            assert!(matches!(
                validate_discovery_document(&document, "https://idp.example.com"),
                Err(OidcDiscoveryError::MissingField(missing)) if missing == field
            ));
        }
    }

    #[test]
    fn discovery_validation_normalizes_issuer_trailing_slash() {
        let document = discovery_document("https://idp.example.com/");
        assert!(validate_discovery_document(&document, "https://idp.example.com").is_ok());
        let document = discovery_document("https://idp.example.com");
        assert!(validate_discovery_document(&document, "https://idp.example.com/").is_ok());
    }

    #[test]
    fn discovery_validation_rejects_issuer_mismatch() {
        let document = discovery_document("https://evil.example.com");
        assert!(matches!(
            validate_discovery_document(&document, "https://idp.example.com"),
            Err(OidcDiscoveryError::IssuerMismatch)
        ));
    }

    #[test]
    fn required_discovery_fields_match_upstream_contract() {
        assert_eq!(
            REQUIRED_DISCOVERY_FIELDS,
            &[
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "jwks_uri",
            ]
        );
    }

    #[test]
    fn validate_discovery_url_rejects_invalid_and_untrusted_urls() {
        assert!(matches!(
            validate_discovery_url("not-a-url", |_| true),
            Err(OidcDiscoveryError::InvalidUrl { .. })
        ));
        assert!(matches!(
            validate_discovery_url("ftp://idp.example.com/config", |_| true),
            Err(OidcDiscoveryError::InvalidUrl { .. })
        ));
        assert!(matches!(
            validate_discovery_url(
                "https://untrusted.example.com/.well-known/openid-configuration",
                |_| false
            ),
            Err(OidcDiscoveryError::UntrustedOrigin { .. })
        ));
        assert!(validate_discovery_url(
            "https://idp.example.com/.well-known/openid-configuration",
            |_| true
        )
        .is_ok());
    }

    #[test]
    fn normalize_discovery_urls_rejects_untrusted_required_endpoints(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let document = OidcDiscoveryDocument {
            issuer: "https://idp.example.com".to_owned(),
            authorization_endpoint: "/oauth2/authorize".to_owned(),
            token_endpoint: "/oauth2/token".to_owned(),
            jwks_uri: "/.well-known/jwks.json".to_owned(),
            userinfo_endpoint: Some("/userinfo".to_owned()),
            revocation_endpoint: Some("/revoke".to_owned()),
            end_session_endpoint: Some("/endsession".to_owned()),
            introspection_endpoint: Some("/introspection".to_owned()),
            token_endpoint_auth_methods_supported: None,
            scopes_supported: None,
            response_types_supported: None,
            subject_types_supported: None,
            id_token_signing_alg_values_supported: None,
            claims_supported: None,
            code_challenge_methods_supported: None,
        };

        for (suffix, field_hint) in [
            ("/oauth2/token", "token_endpoint"),
            ("/oauth2/authorize", "authorization_endpoint"),
            ("/.well-known/jwks.json", "jwks_uri"),
            ("/userinfo", "userinfo_endpoint"),
            ("/revoke", "revocation_endpoint"),
            ("/endsession", "end_session_endpoint"),
            ("/introspection", "introspection_endpoint"),
        ] {
            let error =
                match normalize_discovery_urls(document.clone(), "https://idp.example.com", |url| {
                    !url.ends_with(suffix)
                }) {
                    Ok(_) => return Err(format!("expected untrusted {field_hint}").into()),
                    Err(error) => error,
                };
            assert_eq!(error.code(), "discovery_untrusted_origin");
            assert!(error.to_string().contains(field_hint));
        }
        Ok(())
    }

    #[test]
    fn token_endpoint_authentication_prefers_existing_config_value() {
        let document = discovery_document("https://idp.example.com");
        assert_eq!(
            select_token_endpoint_authentication(
                &document,
                Some(TokenEndpointAuthentication::ClientSecretPost)
            ),
            TokenEndpointAuthentication::ClientSecretPost
        );
    }

    #[test]
    fn token_endpoint_authentication_prefers_client_secret_basic_when_both_supported() {
        let mut document = discovery_document("https://idp.example.com");
        document.token_endpoint_auth_methods_supported = Some(vec![
            "client_secret_post".to_owned(),
            "client_secret_basic".to_owned(),
        ]);
        assert_eq!(
            select_token_endpoint_authentication(&document, None),
            TokenEndpointAuthentication::ClientSecretBasic
        );
    }

    #[test]
    fn token_endpoint_authentication_selects_client_secret_post_when_only_supported() {
        let mut document = discovery_document("https://idp.example.com");
        document.token_endpoint_auth_methods_supported =
            Some(vec!["client_secret_post".to_owned()]);
        assert_eq!(
            select_token_endpoint_authentication(&document, None),
            TokenEndpointAuthentication::ClientSecretPost
        );
    }

    #[test]
    fn normalize_absolute_http_url_accepts_http_and_https() -> Result<(), OidcDiscoveryError> {
        assert_eq!(
            normalize_absolute_http_url("discovery_endpoint", "http://idp.example.com/path")?,
            "http://idp.example.com/path"
        );
        assert_eq!(
            normalize_absolute_http_url("discovery_endpoint", "https://idp.example.com/path")?,
            "https://idp.example.com/path"
        );
        Ok(())
    }

    #[test]
    fn token_endpoint_authentication_defaults_for_empty_or_unsupported_methods() {
        let mut document = discovery_document("https://idp.example.com");
        document.token_endpoint_auth_methods_supported = Some(Vec::new());
        assert_eq!(
            select_token_endpoint_authentication(&document, None),
            TokenEndpointAuthentication::ClientSecretBasic
        );

        document.token_endpoint_auth_methods_supported = Some(vec![
            "private_key_jwt".to_owned(),
            "tls_client_auth".to_owned(),
        ]);
        assert_eq!(
            select_token_endpoint_authentication(&document, None),
            TokenEndpointAuthentication::ClientSecretBasic
        );
    }

    #[test]
    fn discovery_validation_accepts_document_without_optional_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let document: OidcDiscoveryDocument = serde_json::from_str(
            r#"{
                "issuer":"https://idp.example.com",
                "authorization_endpoint":"https://idp.example.com/authorize",
                "token_endpoint":"https://idp.example.com/token",
                "jwks_uri":"https://idp.example.com/keys"
            }"#,
        )?;

        validate_discovery_document(&document, "https://idp.example.com")?;
        assert_eq!(document.userinfo_endpoint, None);
        assert_eq!(document.response_types_supported, None);
        assert_eq!(document.subject_types_supported, None);
        assert_eq!(document.id_token_signing_alg_values_supported, None);
        assert_eq!(document.claims_supported, None);
        assert_eq!(document.code_challenge_methods_supported, None);
        Ok(())
    }

    #[tokio::test]
    async fn fetch_discovery_document_classifies_http_and_json_errors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let (status, body) = if request.starts_with("GET /missing ") {
                        ("404 Not Found", "not found")
                    } else if request.starts_with("GET /server-error ") {
                        ("500 Internal Server Error", "server error")
                    } else if request.starts_with("GET /timeout-status ") {
                        ("408 Request Timeout", "timeout")
                    } else if request.starts_with("GET /empty ") {
                        ("200 OK", "")
                    } else {
                        ("200 OK", "not-json")
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let client = reqwest::Client::new();
        let missing_error =
            match fetch_discovery_document(&format!("http://{address}/missing"), &client).await {
                Ok(_) => return Err("expected missing discovery document to fail".into()),
                Err(error) => error,
            };
        assert_eq!(missing_error.code(), "discovery_not_found");

        let server_error = match fetch_discovery_document(
            &format!("http://{address}/server-error"),
            &client,
        )
        .await
        {
            Ok(_) => return Err("expected server error discovery document to fail".into()),
            Err(error) => error,
        };
        assert_eq!(server_error.code(), "discovery_unexpected_error");

        let timeout_error =
            match fetch_discovery_document(&format!("http://{address}/timeout-status"), &client)
                .await
            {
                Ok(_) => return Err("expected timeout discovery document to fail".into()),
                Err(error) => error,
            };
        assert_eq!(timeout_error.code(), "discovery_timeout");

        let empty_response_error =
            match fetch_discovery_document(&format!("http://{address}/empty"), &client).await {
                Ok(_) => return Err("expected empty discovery document to fail".into()),
                Err(error) => error,
            };
        assert_eq!(empty_response_error.code(), "discovery_invalid_json");

        let invalid_json_error = match fetch_discovery_document(
            &format!("http://{address}/invalid-json"),
            &client,
        )
        .await
        {
            Ok(_) => return Err("expected invalid JSON discovery document to fail".into()),
            Err(error) => error,
        };
        assert_eq!(invalid_json_error.code(), "discovery_invalid_json");
        Ok(())
    }

    #[tokio::test]
    async fn discovery_rejects_untrusted_discovered_endpoint_origins(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let server_base_url = base_url.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let server_base_url = server_base_url.clone();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                        format!(
                            r#"{{
                                "issuer":"{server_base_url}",
                                "authorization_endpoint":"{server_base_url}/authorize",
                                "token_endpoint":"https://untrusted.example.com/token",
                                "jwks_uri":"{server_base_url}/keys",
                                "userinfo_endpoint":"{server_base_url}/userinfo"
                            }}"#
                        )
                    } else {
                        r#"{"error":"not_found"}"#.to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let error = match discover_oidc_config_with_origin_validator(
            &base_url,
            None,
            PartialOidcDiscoveryConfig::default(),
            |url| url.starts_with(&base_url),
            &reqwest::Client::new(),
        )
        .await
        {
            Ok(_) => return Err("expected untrusted discovered endpoint to fail".into()),
            Err(error) => error,
        };
        assert_eq!(error.code(), "discovery_untrusted_origin");
        Ok(())
    }

    #[tokio::test]
    async fn discovery_rejects_untrusted_optional_endpoint_origins(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let server_base_url = base_url.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let server_base_url = server_base_url.clone();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                        format!(
                            r#"{{
                                "issuer":"{server_base_url}",
                                "authorization_endpoint":"{server_base_url}/authorize",
                                "token_endpoint":"{server_base_url}/token",
                                "jwks_uri":"{server_base_url}/keys",
                                "revocation_endpoint":"https://untrusted.example.com/revoke"
                            }}"#
                        )
                    } else {
                        r#"{"error":"not_found"}"#.to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let error = match discover_oidc_config_with_origin_validator(
            &base_url,
            None,
            PartialOidcDiscoveryConfig::default(),
            |url| url.starts_with(&base_url),
            &reqwest::Client::new(),
        )
        .await
        {
            Ok(_) => return Err("expected untrusted optional endpoint to fail".into()),
            Err(error) => error,
        };
        assert_eq!(error.code(), "discovery_untrusted_origin");
        assert!(error.to_string().contains("revocation_endpoint"));
        Ok(())
    }

    #[tokio::test]
    async fn discover_ignores_empty_existing_endpoint_overrides(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let server_base_url = base_url.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let server_base_url = server_base_url.clone();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                        format!(
                            r#"{{
                                "issuer":"{server_base_url}",
                                "authorization_endpoint":"{server_base_url}/authorize",
                                "token_endpoint":"{server_base_url}/token",
                                "jwks_uri":"{server_base_url}/keys"
                            }}"#
                        )
                    } else {
                        r#"{"error":"not_found"}"#.to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let hydrated = discover_oidc_config_with_origin_validator(
            &base_url,
            None,
            PartialOidcDiscoveryConfig {
                authorization_endpoint: Some(""),
                ..PartialOidcDiscoveryConfig::default()
            },
            |url| url.starts_with(&base_url),
            &reqwest::Client::new(),
        )
        .await?;

        assert_eq!(
            hydrated.authorization_endpoint,
            format!("{base_url}/authorize")
        );
        Ok(())
    }

    #[tokio::test]
    async fn discovery_preserves_user_supplied_endpoints_over_discovered_values(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let server_base_url = base_url.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let server_base_url = server_base_url.clone();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                        format!(
                            r#"{{
                                "issuer":"{server_base_url}",
                                "authorization_endpoint":"{server_base_url}/discovered/authorize",
                                "token_endpoint":"{server_base_url}/discovered/token",
                                "jwks_uri":"{server_base_url}/discovered/keys",
                                "userinfo_endpoint":"{server_base_url}/discovered/userinfo",
                                "token_endpoint_auth_methods_supported":["client_secret_post"]
                            }}"#
                        )
                    } else {
                        r#"{"error":"not_found"}"#.to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let custom_authorization_endpoint = format!("{base_url}/custom/authorize");
        let custom_token_endpoint = format!("{base_url}/custom/token");
        let custom_user_info_endpoint = format!("{base_url}/custom/userinfo");
        let custom_jwks_endpoint = format!("{base_url}/custom/keys");
        let existing = PartialOidcDiscoveryConfig {
            authorization_endpoint: Some(&custom_authorization_endpoint),
            token_endpoint: Some(&custom_token_endpoint),
            user_info_endpoint: Some(&custom_user_info_endpoint),
            jwks_endpoint: Some(&custom_jwks_endpoint),
            token_endpoint_authentication: Some(TokenEndpointAuthentication::ClientSecretBasic),
            ..PartialOidcDiscoveryConfig::default()
        };

        let hydrated = discover_oidc_config_with_origin_validator(
            &base_url,
            None,
            existing,
            |url| url.starts_with(&base_url),
            &reqwest::Client::new(),
        )
        .await?;

        assert_eq!(
            hydrated.authorization_endpoint,
            custom_authorization_endpoint
        );
        assert_eq!(hydrated.token_endpoint, custom_token_endpoint);
        assert_eq!(hydrated.jwks_endpoint, custom_jwks_endpoint);
        assert_eq!(
            hydrated.user_info_endpoint.as_deref(),
            Some(custom_user_info_endpoint.as_str())
        );
        assert_eq!(
            hydrated.token_endpoint_authentication,
            TokenEndpointAuthentication::ClientSecretBasic
        );
        Ok(())
    }

    #[tokio::test]
    async fn discover_uses_custom_and_existing_discovery_endpoints(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let server_base_url = base_url.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let server_base_url = server_base_url.clone();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let body = if request.contains("GET /custom/.well-known/openid-configuration ")
                    {
                        format!(
                            r#"{{
                                "issuer":"{server_base_url}",
                                "authorization_endpoint":"{server_base_url}/authorize",
                                "token_endpoint":"{server_base_url}/token",
                                "jwks_uri":"{server_base_url}/keys"
                            }}"#
                        )
                    } else if request.contains("GET /tenant/.well-known/openid-configuration ") {
                        format!(
                            r#"{{
                                "issuer":"{server_base_url}",
                                "authorization_endpoint":"{server_base_url}/tenant/authorize",
                                "token_endpoint":"{server_base_url}/tenant/token",
                                "jwks_uri":"{server_base_url}/tenant/keys"
                            }}"#
                        )
                    } else {
                        r#"{"error":"not_found"}"#.to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let custom_endpoint = format!("{base_url}/custom/.well-known/openid-configuration");
        let custom = discover_oidc_config_with_origin_validator(
            &base_url,
            Some(&custom_endpoint),
            PartialOidcDiscoveryConfig::default(),
            |url| url.starts_with(&base_url),
            &reqwest::Client::new(),
        )
        .await?;
        assert_eq!(custom.discovery_endpoint, custom_endpoint);

        let existing_endpoint = format!("{base_url}/tenant/.well-known/openid-configuration");
        let existing = discover_oidc_config_with_origin_validator(
            &base_url,
            None,
            PartialOidcDiscoveryConfig {
                discovery_endpoint: Some(&existing_endpoint),
                ..PartialOidcDiscoveryConfig::default()
            },
            |url| url.starts_with(&base_url),
            &reqwest::Client::new(),
        )
        .await?;
        assert_eq!(existing.discovery_endpoint, existing_endpoint);
        assert_eq!(
            existing.authorization_endpoint,
            format!("{base_url}/tenant/authorize")
        );
        Ok(())
    }

    #[tokio::test]
    async fn discover_includes_scopes_supported_and_ignores_unknown_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let server_base_url = base_url.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let server_base_url = server_base_url.clone();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                        format!(
                            r#"{{
                                "issuer":"{server_base_url}",
                                "authorization_endpoint":"{server_base_url}/authorize",
                                "token_endpoint":"{server_base_url}/token",
                                "jwks_uri":"{server_base_url}/keys",
                                "scopes_supported":["openid","profile","email","custom"],
                                "x-vendor-feature":true,
                                "custom_logout_endpoint":"{server_base_url}/logout"
                            }}"#
                        )
                    } else {
                        r#"{"error":"not_found"}"#.to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let hydrated = discover_oidc_config_with_origin_validator(
            &base_url,
            None,
            PartialOidcDiscoveryConfig::default(),
            |url| url.starts_with(&base_url),
            &reqwest::Client::new(),
        )
        .await?;

        assert_eq!(
            hydrated.scopes_supported,
            Some(vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
                "custom".to_owned()
            ])
        );
        assert_eq!(hydrated.user_info_endpoint, None);
        Ok(())
    }

    #[tokio::test]
    async fn discover_rejects_untrusted_main_discovery_url(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let error = match discover_oidc_config_with_origin_validator(
            "https://idp.example.com",
            None,
            PartialOidcDiscoveryConfig::default(),
            |_| false,
            &reqwest::Client::new(),
        )
        .await
        {
            Ok(_) => return Err("expected untrusted discovery URL to fail".into()),
            Err(error) => error,
        };
        assert_eq!(error.code(), "discovery_untrusted_origin");
        assert!(error.to_string().contains("discovery_endpoint"));
        Ok(())
    }

    #[tokio::test]
    async fn ensure_runtime_returns_unchanged_config_when_discovery_not_needed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = OidcConfig {
            issuer: "https://idp.example.com".to_owned(),
            pkce: true,
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".into(),
            discovery_endpoint: compute_discovery_url("https://idp.example.com"),
            authorization_endpoint: Some("https://idp.example.com/authorize".to_owned()),
            token_endpoint: Some("https://idp.example.com/token".to_owned()),
            user_info_endpoint: Some("https://idp.example.com/userinfo".to_owned()),
            jwks_endpoint: Some("https://idp.example.com/keys".to_owned()),
            revocation_endpoint: None,
            end_session_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_authentication: None,
            scopes: Some(vec!["openid".to_owned()]),
            mapping: None,
            override_user_info: false,
        };

        let unchanged = ensure_runtime_oidc_config_with_origin_validator(
            "https://idp.example.com",
            config.clone(),
            OidcRuntimeRequirement::Callback,
            |_| true,
            false,
            &reqwest::Client::new(),
        )
        .await?;

        assert_eq!(unchanged.client_id, config.client_id);
        assert_eq!(
            unchanged.client_secret.expose_secret(),
            config.client_secret.expose_secret()
        );
        assert_eq!(unchanged.pkce, config.pkce);
        assert_eq!(unchanged.scopes, config.scopes);
        assert_eq!(
            unchanged.authorization_endpoint,
            config.authorization_endpoint
        );
        Ok(())
    }

    #[tokio::test]
    async fn ensure_runtime_throws_when_discovery_fails() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
                    let response =
                        "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let config = OidcConfig {
            issuer: base_url.clone(),
            pkce: true,
            client_id: "client-id".to_owned(),
            client_secret: "client-secret".into(),
            discovery_endpoint: compute_discovery_url(&base_url),
            authorization_endpoint: None,
            token_endpoint: None,
            user_info_endpoint: None,
            jwks_endpoint: None,
            revocation_endpoint: None,
            end_session_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_authentication: None,
            scopes: None,
            mapping: None,
            override_user_info: false,
        };

        let error = match ensure_runtime_oidc_config_with_origin_validator(
            &base_url,
            config,
            OidcRuntimeRequirement::SignIn,
            |_| true,
            false,
            &reqwest::Client::new(),
        )
        .await
        {
            Ok(_) => return Err("expected runtime discovery failure".into()),
            Err(error) => error,
        };
        assert_eq!(error.code(), "discovery_not_found");
        Ok(())
    }

    #[tokio::test]
    async fn runtime_discovery_preserves_only_explicit_request_scopes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let base_url = format!("http://{address}");
        let server_base_url = base_url.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let server_base_url = server_base_url.clone();
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 1024];
                    let Ok(read) = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await
                    else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                        format!(
                            r#"{{
                                "issuer":"{server_base_url}",
                                "authorization_endpoint":"{server_base_url}/authorize",
                                "token_endpoint":"{server_base_url}/token",
                                "jwks_uri":"{server_base_url}/keys",
                                "scopes_supported":["openid","profile"]
                            }}"#
                        )
                    } else {
                        r#"{"error":"not_found"}"#.to_owned()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
                });
            }
        });

        let config = OidcConfig {
            issuer: base_url.clone(),
            pkce: true,
            client_id: "client".to_owned(),
            client_secret: "secret".into(),
            discovery_endpoint: compute_discovery_url(&base_url),
            authorization_endpoint: None,
            token_endpoint: None,
            user_info_endpoint: None,
            jwks_endpoint: None,
            revocation_endpoint: None,
            end_session_endpoint: None,
            introspection_endpoint: None,
            token_endpoint_authentication: None,
            scopes: None,
            mapping: None,
            override_user_info: false,
        };

        let hydrated = ensure_runtime_oidc_config_with_origin_validator(
            &base_url,
            config,
            OidcRuntimeRequirement::SignIn,
            |url| url.starts_with(&base_url),
            false,
            &reqwest::Client::new(),
        )
        .await?;

        assert_eq!(hydrated.scopes, None);

        let explicit_config = OidcConfig {
            scopes: Some(vec!["openid".to_owned(), "email".to_owned()]),
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_endpoint: None,
            ..hydrated
        };
        let explicit_hydrated = ensure_runtime_oidc_config_with_origin_validator(
            &base_url,
            explicit_config,
            OidcRuntimeRequirement::SignIn,
            |url| url.starts_with(&base_url),
            false,
            &reqwest::Client::new(),
        )
        .await?;

        assert_eq!(
            explicit_hydrated.scopes,
            Some(vec!["openid".to_owned(), "email".to_owned()])
        );
        Ok(())
    }
}
