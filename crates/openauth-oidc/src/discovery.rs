use serde::{Deserialize, Serialize};
use url::Url;

use crate::options::{OidcConfig, TokenEndpointAuthentication};

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
) -> Result<HydratedOidcDiscovery, OidcDiscoveryError> {
    discover_oidc_config_with_origin_validator(issuer, discovery_endpoint, existing, |_| true).await
}

pub async fn discover_oidc_config_with_origin_validator<F>(
    issuer: &str,
    discovery_endpoint: Option<&str>,
    existing: PartialOidcDiscoveryConfig<'_>,
    is_trusted_origin: F,
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
    let document = fetch_discovery_document(&discovery_endpoint).await?;
    validate_discovery_document(&document, issuer)?;
    let normalized = normalize_discovery_document(document, issuer)?;
    let token_endpoint_authentication = existing
        .token_endpoint_authentication
        .unwrap_or_else(|| select_token_endpoint_authentication(&normalized));

    let hydrated = HydratedOidcDiscovery {
        issuer: existing
            .issuer
            .map(str::to_owned)
            .unwrap_or(normalized.issuer),
        discovery_endpoint,
        authorization_endpoint: existing
            .authorization_endpoint
            .map(str::to_owned)
            .unwrap_or(normalized.authorization_endpoint),
        token_endpoint: existing
            .token_endpoint
            .map(str::to_owned)
            .unwrap_or(normalized.token_endpoint),
        jwks_endpoint: existing
            .jwks_endpoint
            .map(str::to_owned)
            .unwrap_or(normalized.jwks_uri),
        user_info_endpoint: existing
            .user_info_endpoint
            .map(str::to_owned)
            .or(normalized.userinfo_endpoint),
        revocation_endpoint: existing
            .revocation_endpoint
            .map(str::to_owned)
            .or(normalized.revocation_endpoint),
        end_session_endpoint: existing
            .end_session_endpoint
            .map(str::to_owned)
            .or(normalized.end_session_endpoint),
        introspection_endpoint: existing
            .introspection_endpoint
            .map(str::to_owned)
            .or(normalized.introspection_endpoint),
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

async fn fetch_discovery_document(
    discovery_endpoint: &str,
) -> Result<OidcDiscoveryDocument, OidcDiscoveryError> {
    let response = crate::utils::http_client()
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

fn validate_discovery_document(
    document: &OidcDiscoveryDocument,
    issuer: &str,
) -> Result<(), OidcDiscoveryError> {
    let mut missing = Vec::new();
    if document.issuer.is_empty() {
        missing.push("issuer");
    }
    if document.authorization_endpoint.is_empty() {
        missing.push("authorization_endpoint");
    }
    if document.token_endpoint.is_empty() {
        missing.push("token_endpoint");
    }
    if document.jwks_uri.is_empty() {
        missing.push("jwks_uri");
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
        return Ok(url.to_string());
    }

    let issuer_url = Url::parse(issuer).map_err(|source| OidcDiscoveryError::InvalidUrl {
        field,
        reason: source.to_string(),
    })?;
    let origin = issuer_url.origin().ascii_serialization();
    let base_path = issuer_url.path().trim_end_matches('/');
    let endpoint_path = endpoint.trim_start_matches('/');
    Url::parse(&format!("{origin}{base_path}/{endpoint_path}"))
        .map(|url| url.to_string())
        .map_err(|source| OidcDiscoveryError::InvalidUrl {
            field,
            reason: source.to_string(),
        })
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
    if !matches!(url.scheme(), "http" | "https") {
        return Err(OidcDiscoveryError::InvalidUrl {
            field,
            reason: format!("unsupported URL scheme `{}`", url.scheme()),
        });
    }
    if !is_trusted_origin(value) {
        return Err(OidcDiscoveryError::UntrustedOrigin {
            field,
            url: value.to_owned(),
        });
    }
    Ok(())
}

fn select_token_endpoint_authentication(
    document: &OidcDiscoveryDocument,
) -> TokenEndpointAuthentication {
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

        let missing_error =
            match fetch_discovery_document(&format!("http://{address}/missing")).await {
                Ok(_) => return Err("expected missing discovery document to fail".into()),
                Err(error) => error,
            };
        assert_eq!(missing_error.code(), "discovery_not_found");

        let invalid_json_error =
            match fetch_discovery_document(&format!("http://{address}/invalid-json")).await {
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

        let hydrated =
            discover_oidc_config_with_origin_validator(&base_url, None, existing, |url| {
                url.starts_with(&base_url)
            })
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
}
