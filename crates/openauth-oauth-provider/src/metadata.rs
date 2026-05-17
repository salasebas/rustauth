use openauth_core::context::AuthContext;
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
        jwks_uri: (!options.disable_jwt_plugin).then(|| format!("{}/jwks", context.base_url)),
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

pub fn oidc_server_metadata(
    context: &AuthContext,
    options: &ResolvedOAuthProviderOptions,
) -> OidcServerMetadata {
    OidcServerMetadata {
        auth: auth_server_metadata(context, options),
        claims_supported: options.claims.clone(),
        userinfo_endpoint: format!("{}/oauth2/userinfo", context.base_url),
        subject_types_supported: if options.pairwise_secret.is_some() {
            vec!["public".to_owned(), "pairwise".to_owned()]
        } else {
            vec!["public".to_owned()]
        },
        id_token_signing_alg_values_supported: if options.disable_jwt_plugin {
            vec!["HS256".to_owned()]
        } else {
            vec!["EdDSA".to_owned()]
        },
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
