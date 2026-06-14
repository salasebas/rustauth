use http::{header, Response, StatusCode};
use rustauth_core::api::ApiResponse;
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use serde::Serialize;

use crate::options::{GrantType, ResolvedOAuthProviderOptions, TokenEndpointAuthMethod};

#[derive(Debug, Clone, Serialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    pub registration_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub response_types_supported: Vec<String>,
    pub response_modes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub introspection_endpoint_auth_methods_supported: Vec<String>,
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub authorization_response_iss_parameter_supported: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OidcServerMetadata {
    #[serde(flatten)]
    pub auth: AuthServerMetadata,
    pub claims_supported: Vec<String>,
    pub userinfo_endpoint: String,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub end_session_endpoint: String,
    pub acr_values_supported: Vec<String>,
    pub prompt_values_supported: Vec<String>,
}

pub fn auth_server_metadata(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
) -> AuthServerMetadata {
    let issuer = validate_issuer_url(&context.base_url);
    let scopes_supported = if options.advertised_scopes_supported.is_empty() {
        Some(options.scopes.clone())
    } else {
        Some(options.advertised_scopes_supported.clone())
    };
    AuthServerMetadata {
        issuer,
        authorization_endpoint: format!("{}/oauth2/authorize", context.base_url),
        token_endpoint: format!("{}/oauth2/token", context.base_url),
        jwks_uri: jwks_uri(context, options),
        registration_endpoint: format!("{}/oauth2/register", context.base_url),
        scopes_supported,
        introspection_endpoint: format!("{}/oauth2/introspect", context.base_url),
        revocation_endpoint: format!("{}/oauth2/revoke", context.base_url),
        response_types_supported: if options.grant_types.contains(&GrantType::AuthorizationCode) {
            vec!["code".to_owned()]
        } else {
            Vec::new()
        },
        response_modes_supported: vec!["query".to_owned()],
        grant_types_supported: options
            .grant_types
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect(),
        token_endpoint_auth_methods_supported: token_auth_methods(
            options.allow_unauthenticated_client_registration,
        ),
        introspection_endpoint_auth_methods_supported: token_auth_methods(false),
        revocation_endpoint_auth_methods_supported: token_auth_methods(false),
        code_challenge_methods_supported: vec!["S256".to_owned()],
        authorization_response_iss_parameter_supported: true,
    }
}

/// Cache-Control for well-known metadata responses (15s TTL + stale windows).
pub const WELL_KNOWN_METADATA_CACHE_CONTROL: &str =
    "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400";

/// Metadata for `/.well-known/oauth-authorization-server` (OIDC document when `openid` is enabled).
#[cfg_attr(not(feature = "test-util"), allow(dead_code))]
pub fn oauth_authorization_server_metadata(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
) -> Result<serde_json::Value, RustAuthError> {
    let metadata = if options.scopes.iter().any(|scope| scope == "openid") {
        serde_json::to_value(oidc_server_metadata(context, options))
    } else {
        serde_json::to_value(auth_server_metadata(context, options))
    };
    metadata.map_err(|error| RustAuthError::Api(error.to_string()))
}

pub fn well_known_metadata_response<T: Serialize>(body: &T) -> Result<ApiResponse, RustAuthError> {
    let body = serde_json::to_vec(body).map_err(|error| RustAuthError::Api(error.to_string()))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, WELL_KNOWN_METADATA_CACHE_CONTROL)
        .body(body)
        .map_err(|error| RustAuthError::Api(error.to_string()))
}

pub fn oidc_server_metadata(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
) -> OidcServerMetadata {
    OidcServerMetadata {
        auth: auth_server_metadata(context, options),
        claims_supported: if options.advertised_claims_supported.is_empty() {
            options.claims.clone()
        } else {
            options.advertised_claims_supported.clone()
        },
        userinfo_endpoint: format!("{}/oauth2/userinfo", context.base_url),
        subject_types_supported: if options.pairwise_secret.is_some() {
            vec!["public".to_owned(), "pairwise".to_owned()]
        } else {
            vec!["public".to_owned()]
        },
        id_token_signing_alg_values_supported: id_token_signing_algorithms(context, options),
        end_session_endpoint: format!("{}/oauth2/end-session", context.base_url),
        acr_values_supported: vec!["urn:mace:incommon:iap:bronze".to_owned()],
        prompt_values_supported: vec![
            "login".to_owned(),
            "consent".to_owned(),
            "create".to_owned(),
            "select_account".to_owned(),
            "none".to_owned(),
        ],
    }
}

pub fn validate_issuer_url(issuer: &str) -> String {
    match url::Url::parse(issuer) {
        Ok(mut url) => {
            if url.scheme() != "https" && !is_loopback_host(url.host_str()) {
                let _ = url.set_scheme("https");
            }
            url.set_query(None);
            url.set_fragment(None);
            url.to_string().trim_end_matches('/').to_owned()
        }
        Err(_) => issuer.to_owned(),
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

fn jwks_uri(context: &AuthContext, options: &ResolvedOAuthProviderOptions) -> Option<String> {
    if options.disable_jwt_plugin {
        return None;
    }
    if let Some(uri) = &options.advertised_jwks_uri {
        return Some(uri.clone());
    }
    if let Some(jwt) = rustauth_plugins::jwt::jwt_options_from_context(context) {
        if let Some(uri) = &jwt.jwks.remote_url {
            return Some(uri.clone());
        }
        let path = effective_jwks_path(options, jwt.as_ref());
        return Some(format!(
            "{}{}",
            context.base_url.trim_end_matches('/'),
            path
        ));
    }
    let path = if options.jwks_path.starts_with('/') {
        options.jwks_path.clone()
    } else {
        format!("/{}", options.jwks_path)
    };
    Some(format!(
        "{}{}",
        context.base_url.trim_end_matches('/'),
        path
    ))
}

fn effective_jwks_path(
    options: &ResolvedOAuthProviderOptions,
    jwt: &rustauth_plugins::jwt::JwtOptions,
) -> String {
    if options.jwks_path != "/jwks" {
        if options.jwks_path.starts_with('/') {
            return options.jwks_path.clone();
        }
        return format!("/{}", options.jwks_path);
    }
    if jwt.jwks.jwks_path.starts_with('/') {
        jwt.jwks.jwks_path.clone()
    } else {
        format!("/{}", jwt.jwks.jwks_path)
    }
}

fn id_token_signing_algorithms(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
) -> Vec<String> {
    if !options.advertised_id_token_signing_algorithms.is_empty() {
        return options.advertised_id_token_signing_algorithms.clone();
    }
    if options.disable_jwt_plugin {
        return vec!["HS256".to_owned()];
    }
    if let Some(jwt) = rustauth_plugins::jwt::jwt_options_from_context(context) {
        return vec![jwt
            .jwks
            .key_pair_algorithm
            .unwrap_or(rustauth_plugins::jwt::JwkAlgorithm::EdDsa)
            .as_str()
            .to_owned()];
    }
    vec!["EdDSA".to_owned()]
}

fn token_auth_methods(public_client_supported: bool) -> Vec<String> {
    let mut methods = Vec::new();
    if public_client_supported {
        methods.push(TokenEndpointAuthMethod::None.as_str().to_owned());
    }
    methods.push(
        TokenEndpointAuthMethod::ClientSecretBasic
            .as_str()
            .to_owned(),
    );
    methods.push(
        TokenEndpointAuthMethod::ClientSecretPost
            .as_str()
            .to_owned(),
    );
    methods
}
