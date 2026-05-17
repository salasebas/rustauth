//! OAuth 2.1 and OpenID Connect provider support for OpenAuth.
//!
//! This crate ports the server-side Better Auth `oauth-provider` behavior into
//! idiomatic Rust. It is intentionally separate from `openauth-oauth`, which
//! contains OAuth client and social-provider primitives.

mod authorize;
mod client;
mod consent;
mod endpoints;
mod error;
mod metadata;
mod models;
mod options;
mod schema;
mod token;
mod utils;

pub mod mcp;

pub use authorize::{decide_authorize, AuthorizeDecision};
pub use client::{
    check_oauth_client, oauth_to_schema, schema_to_oauth, CreateOAuthClientInput, OAuthClient,
};
pub use consent::{
    delete_consent, find_consent, has_granted_scopes, upsert_consent, ConsentGrantInput,
};
pub use error::OAuthProviderError;
pub use metadata::{auth_server_metadata, oidc_server_metadata};
pub use models::{OAuthAccessToken, OAuthConsent, OAuthRefreshToken, SchemaClient};
pub use options::{
    GrantType, OAuthProviderConfigError, OAuthProviderOptions, OAuthProviderPlugin,
    ResolvedOAuthProviderOptions, SecretStorage, TokenEndpointAuthMethod,
};
pub use schema::{
    oauth_provider_schema, OAUTH_ACCESS_TOKEN_MODEL, OAUTH_CLIENT_MODEL, OAUTH_CONSENT_MODEL,
    OAUTH_REFRESH_TOKEN_MODEL,
};
pub use token::{
    create_client_credentials_token, decode_refresh_token, store_client_secret, store_token,
    verify_client_secret, TokenResponse,
};

use std::collections::HashSet;
use std::sync::Arc;

use openauth_core::options::RateLimitRule;
use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the OAuth provider extension.
pub fn oauth_provider(
    options: OAuthProviderOptions,
) -> Result<OAuthProviderPlugin, OAuthProviderConfigError> {
    let resolved = resolve_options(options)?;
    let shared = Arc::new(resolved.clone());
    let mut auth_plugin = AuthPlugin::new("oauth-provider").with_version(VERSION);

    if !resolved.disable_jwt_plugin {
        let jwt_plugin = openauth_plugins::jwt::jwt()
            .map_err(|error| OAuthProviderConfigError::JwtPlugin(error.to_string()))?;
        auth_plugin.schema.extend(jwt_plugin.schema);
        auth_plugin.endpoints.extend(jwt_plugin.endpoints);
        auth_plugin.migrations.extend(jwt_plugin.migrations);
        auth_plugin.database_hooks.extend(jwt_plugin.database_hooks);
    }

    for contribution in oauth_provider_schema() {
        auth_plugin = auth_plugin.with_schema(contribution);
    }
    for endpoint in endpoints::oauth_provider_endpoints(Arc::clone(&shared)) {
        auth_plugin = auth_plugin.with_endpoint(endpoint);
    }
    for rule in rate_limit_rules() {
        auth_plugin = auth_plugin.with_rate_limit(rule);
    }

    Ok(OAuthProviderPlugin {
        id: "oauth-provider".to_owned(),
        version: VERSION.to_owned(),
        options: resolved,
        auth_plugin,
    })
}

fn resolve_options(
    options: OAuthProviderOptions,
) -> Result<ResolvedOAuthProviderOptions, OAuthProviderConfigError> {
    if options.login_page.is_empty() {
        return Err(OAuthProviderConfigError::MissingLoginPage);
    }
    if options.consent_page.is_empty() {
        return Err(OAuthProviderConfigError::MissingConsentPage);
    }

    let scopes = non_empty_or_default(
        options.scopes,
        ["openid", "profile", "email", "offline_access"],
    );
    let scope_set: HashSet<&str> = scopes.iter().map(String::as_str).collect();

    let client_registration_allowed_scopes = merge_allowed_scopes(
        options.client_registration_allowed_scopes,
        &options.client_registration_default_scopes,
    );
    for scope in &client_registration_allowed_scopes {
        if !scope_set.contains(scope.as_str()) {
            return Err(OAuthProviderConfigError::UnknownClientRegistrationScope(
                scope.clone(),
            ));
        }
    }
    for scope in &options.advertised_scopes_supported {
        if !scope_set.contains(scope.as_str()) {
            return Err(OAuthProviderConfigError::UnknownAdvertisedScope(
                scope.clone(),
            ));
        }
    }
    if options
        .pairwise_secret
        .as_ref()
        .is_some_and(|secret| secret.len() < 32)
    {
        return Err(OAuthProviderConfigError::PairwiseSecretTooShort);
    }

    let grant_types = if options.grant_types.is_empty() {
        vec![
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken,
        ]
    } else {
        options.grant_types
    };
    if grant_types.contains(&GrantType::RefreshToken)
        && !grant_types.contains(&GrantType::AuthorizationCode)
    {
        return Err(OAuthProviderConfigError::RefreshTokenRequiresAuthorizationCode);
    }

    let store_client_secret =
        resolve_client_secret_storage(options.store_client_secret, options.disable_jwt_plugin)?;
    Ok(ResolvedOAuthProviderOptions {
        claims: claims_for_scopes(&scope_set),
        scopes,
        client_registration_allowed_scopes,
        grant_types,
        login_page: options.login_page,
        consent_page: options.consent_page,
        code_expires_in: options.code_expires_in,
        access_token_expires_in: options.access_token_expires_in,
        m2m_access_token_expires_in: options.m2m_access_token_expires_in,
        id_token_expires_in: options.id_token_expires_in,
        refresh_token_expires_in: options.refresh_token_expires_in,
        allow_unauthenticated_client_registration: options
            .allow_unauthenticated_client_registration,
        allow_dynamic_client_registration: options.allow_dynamic_client_registration,
        disable_jwt_plugin: options.disable_jwt_plugin,
        store_client_secret,
        store_tokens: options.store_tokens,
        pairwise_secret: options.pairwise_secret,
        advertised_scopes_supported: options.advertised_scopes_supported,
        valid_audiences: options.valid_audiences,
    })
}

fn non_empty_or_default<const N: usize>(values: Vec<String>, default: [&str; N]) -> Vec<String> {
    let values: Vec<String> = values
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect();
    if values.is_empty() {
        default.into_iter().map(str::to_owned).collect()
    } else {
        values
    }
}

fn merge_allowed_scopes(mut allowed: Vec<String>, default_scopes: &[String]) -> Vec<String> {
    if default_scopes.is_empty() {
        return allowed;
    }
    for scope in default_scopes {
        if !allowed.contains(scope) {
            allowed.push(scope.clone());
        }
    }
    allowed
}

fn claims_for_scopes(scopes: &HashSet<&str>) -> Vec<String> {
    let mut claims = vec![
        "sub".to_owned(),
        "iss".to_owned(),
        "aud".to_owned(),
        "exp".to_owned(),
        "iat".to_owned(),
        "sid".to_owned(),
        "scope".to_owned(),
        "azp".to_owned(),
    ];
    if scopes.contains("email") {
        claims.push("email".to_owned());
        claims.push("email_verified".to_owned());
    }
    if scopes.contains("profile") {
        claims.push("name".to_owned());
        claims.push("picture".to_owned());
        claims.push("family_name".to_owned());
        claims.push("given_name".to_owned());
    }
    claims
}

fn resolve_client_secret_storage(
    storage: SecretStorage,
    disable_jwt_plugin: bool,
) -> Result<SecretStorage, OAuthProviderConfigError> {
    match (storage, disable_jwt_plugin) {
        (SecretStorage::Auto, true) => Ok(SecretStorage::Encrypted),
        (SecretStorage::Auto, false) => Ok(SecretStorage::Hashed),
        (SecretStorage::Hashed, true) => {
            Err(OAuthProviderConfigError::HashedClientSecretsRequireJwtPlugin)
        }
        (SecretStorage::Encrypted, false) => {
            Err(OAuthProviderConfigError::EncryptedClientSecretsWithJwtPlugin)
        }
        (storage, _) => Ok(storage),
    }
}

fn rate_limit_rules() -> Vec<PluginRateLimitRule> {
    [
        ("/oauth2/token", 60, 20),
        ("/oauth2/authorize", 60, 30),
        ("/oauth2/introspect", 60, 100),
        ("/oauth2/revoke", 60, 30),
        ("/oauth2/register", 60, 5),
        ("/oauth2/userinfo", 60, 60),
    ]
    .into_iter()
    .map(|(path, window, max)| PluginRateLimitRule::new(path, RateLimitRule { window, max }))
    .collect()
}
