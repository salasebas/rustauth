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

pub use error::OAuthProviderError;
pub use openauth_plugins::jwt::JwtOptions;
pub use options::{
    ClientPrivilegeAction, ClientPrivilegesInput, ClientPrivilegesResolver, ClientReferenceInput,
    ClientReferenceResolver, ClientSecretHashInput, ClientSecretHashResolver,
    ClientSecretVerifyInput, ClientSecretVerifyResolver, CustomAccessTokenClaimsInput,
    CustomAccessTokenClaimsResolver, CustomIdTokenClaimsInput, CustomIdTokenClaimsResolver,
    CustomTokenResponseFieldsInput, CustomTokenResponseFieldsResolver, CustomUserInfoClaimsInput,
    CustomUserInfoClaimsResolver, GrantType, McpMetadataOverrides, McpOptions,
    OAuthProviderConfigError, OAuthProviderOptions, OAuthProviderRateLimit,
    OAuthProviderRateLimits, OAuthTokenPrefixes, PromptRedirectInput, PromptRedirectResolver,
    PromptShouldRedirectResolver, RefreshTokenFormatDecodeOutput, RefreshTokenFormatEncodeInput,
    RefreshTokenFormatter, RequestUriResolver, RequestUriResolverInput, ResolvedMcpOptions,
    ResolvedOAuthProviderOptions, SecretStorage, StringGeneratorResolver, TokenEndpointAuthMethod,
    TokenHashInput, TokenHashResolver, TrustedClientCache,
};

#[cfg(feature = "test-util")]
pub use authorize::{decide_authorize, AuthorizeDecision};
#[cfg(feature = "test-util")]
pub use client::{
    check_oauth_client, oauth_to_schema, schema_to_oauth, CreateOAuthClientInput, OAuthClient,
};
#[cfg(feature = "test-util")]
pub use consent::{
    delete_consent, find_consent, has_granted_scopes, upsert_consent, ConsentGrantInput,
};
#[cfg(feature = "test-util")]
pub use metadata::{
    auth_server_metadata, oauth_authorization_server_metadata, oidc_server_metadata,
    well_known_metadata_response, WELL_KNOWN_METADATA_CACHE_CONTROL,
};
#[cfg(feature = "test-util")]
pub use models::{OAuthAccessToken, OAuthConsent, OAuthRefreshToken, SchemaClient};
#[cfg(feature = "test-util")]
pub use schema::{
    oauth_provider_schema, OAUTH_ACCESS_TOKEN_MODEL, OAUTH_CLIENT_MODEL, OAUTH_CONSENT_MODEL,
    OAUTH_REFRESH_TOKEN_MODEL,
};
#[cfg(feature = "test-util")]
pub use token::{
    create_client_credentials_token, decode_refresh_token, store_client_secret, store_token,
    verify_client_secret, TokenResponse,
};

#[cfg(feature = "mcp-client")]
pub use mcp::client::{McpAuthClient, McpAuthClientOptions, McpSession};

use std::collections::HashSet;
use std::sync::Arc;

use openauth_core::options::RateLimitRule;
use openauth_core::plugin::{AuthPlugin, PluginRateLimitRule};

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the OAuth provider plugin with default JWT plugin options.
pub fn oauth_provider(
    options: OAuthProviderOptions,
) -> Result<AuthPlugin, OAuthProviderConfigError> {
    build_oauth_provider(options, None)
}

/// Build the OAuth provider plugin and merge the given JWT plugin configuration.
///
/// When [`advertised_jwks_uri`](OAuthProviderOptions::advertised_jwks_uri) and
/// [`advertised_id_token_signing_algorithms`](OAuthProviderOptions::advertised_id_token_signing_algorithms)
/// are unset, they are derived from `jwt_options`.
pub fn oauth_provider_with_jwt(
    options: OAuthProviderOptions,
    jwt_options: JwtOptions,
) -> Result<AuthPlugin, OAuthProviderConfigError> {
    build_oauth_provider(options, Some(jwt_options))
}

fn build_oauth_provider(
    options: OAuthProviderOptions,
    jwt_plugin_options: Option<JwtOptions>,
) -> Result<AuthPlugin, OAuthProviderConfigError> {
    let mut resolved = resolve_options(options)?;
    let mut auth_plugin = AuthPlugin::new("oauth-provider").with_version(VERSION);

    if !resolved.disable_jwt_plugin {
        let jwt_options = jwt_plugin_options.unwrap_or_default();
        apply_jwt_metadata_defaults(&mut resolved, &jwt_options);
        let jwt_plugin = openauth_plugins::jwt::jwt_with_options(jwt_options)
            .map_err(|error| OAuthProviderConfigError::JwtPlugin(error.to_string()))?;
        auth_plugin.schema.extend(jwt_plugin.schema);
        auth_plugin.endpoints.extend(jwt_plugin.endpoints);
        auth_plugin.migrations.extend(jwt_plugin.migrations);
        auth_plugin.database_hooks.extend(jwt_plugin.database_hooks);
    }

    let shared = Arc::new(resolved);

    for contribution in schema::oauth_provider_schema() {
        auth_plugin = auth_plugin.with_schema(contribution);
    }
    for endpoint in endpoints::oauth_provider_endpoints(Arc::clone(&shared)) {
        auth_plugin = auth_plugin.with_endpoint(endpoint);
    }
    for rule in rate_limit_rules(&shared.rate_limits) {
        auth_plugin = auth_plugin.with_rate_limit(rule);
    }

    Ok(auth_plugin)
}

fn apply_jwt_metadata_defaults(resolved: &mut ResolvedOAuthProviderOptions, jwt: &JwtOptions) {
    if resolved.advertised_jwks_uri.is_none() {
        resolved.advertised_jwks_uri = jwt.jwks.remote_url.clone();
    }
    if resolved.advertised_id_token_signing_algorithms.is_empty() {
        resolved.advertised_id_token_signing_algorithms.push(
            jwt.jwks
                .key_pair_algorithm
                .unwrap_or(openauth_plugins::jwt::JwkAlgorithm::EdDsa)
                .as_str()
                .to_owned(),
        );
    }
    if resolved.jwks_path == "/jwks" && jwt.jwks.jwks_path != "/jwks" {
        resolved.jwks_path = jwt.jwks.jwks_path.clone();
    }
}

pub(crate) fn resolve_options(
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

    let client_registration_default_scopes = options.client_registration_default_scopes;
    let client_registration_allowed_scopes = merge_allowed_scopes(
        options.client_registration_allowed_scopes,
        &client_registration_default_scopes,
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
    for scope in &options.client_credential_grant_default_scopes {
        if !scope_set.contains(scope.as_str()) {
            return Err(OAuthProviderConfigError::UnknownClientCredentialGrantScope(
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

    let mcp = resolve_mcp_options(options.mcp)?;
    let store_client_secret =
        resolve_client_secret_storage(options.store_client_secret, options.disable_jwt_plugin)?;
    Ok(ResolvedOAuthProviderOptions {
        claims: claims_for_scopes(&scope_set),
        scopes,
        client_registration_allowed_scopes,
        grant_types,
        login_page: options.login_page,
        consent_page: options.consent_page,
        signup_page: options.signup_page,
        select_account_page: options.select_account_page,
        post_login_page: options.post_login_page,
        signup_redirect: options.signup_redirect,
        select_account_redirect: options.select_account_redirect,
        post_login_redirect: options.post_login_redirect,
        signup_should_redirect: options.signup_should_redirect,
        select_account_should_redirect: options.select_account_should_redirect,
        post_login_should_redirect: options.post_login_should_redirect,
        consent_reference_id: options.consent_reference_id,
        code_expires_in: options.code_expires_in,
        access_token_expires_in: options.access_token_expires_in,
        m2m_access_token_expires_in: options.m2m_access_token_expires_in,
        id_token_expires_in: options.id_token_expires_in,
        refresh_token_expires_in: options.refresh_token_expires_in,
        client_credential_grant_default_scopes: options.client_credential_grant_default_scopes,
        scope_expirations: options.scope_expirations,
        client_registration_default_scopes,
        client_registration_client_secret_expiration: options
            .client_registration_client_secret_expiration,
        allow_unauthenticated_client_registration: options
            .allow_unauthenticated_client_registration,
        allow_dynamic_client_registration: options.allow_dynamic_client_registration,
        allow_public_client_prelogin: options.allow_public_client_prelogin,
        cached_trusted_clients: options.cached_trusted_clients,
        trusted_client_cache: TrustedClientCache::default(),
        client_reference: options.client_reference,
        client_privileges: options.client_privileges,
        custom_access_token_claims: options.custom_access_token_claims,
        custom_id_token_claims: options.custom_id_token_claims,
        custom_token_response_fields: options.custom_token_response_fields,
        custom_userinfo_claims: options.custom_userinfo_claims,
        request_uri_resolver: options.request_uri_resolver,
        prefixes: options.prefixes,
        generate_client_id: options.generate_client_id,
        generate_client_secret: options.generate_client_secret,
        generate_opaque_access_token: options.generate_opaque_access_token,
        generate_refresh_token: options.generate_refresh_token,
        format_refresh_token: options.format_refresh_token,
        disable_jwt_plugin: options.disable_jwt_plugin,
        store_client_secret,
        store_tokens: options.store_tokens,
        hash_client_secret: options.hash_client_secret,
        verify_client_secret_hash: options.verify_client_secret_hash,
        hash_token: options.hash_token,
        pairwise_secret: options.pairwise_secret,
        advertised_scopes_supported: options.advertised_scopes_supported,
        advertised_claims_supported: options.advertised_claims_supported,
        advertised_jwks_uri: options.advertised_jwks_uri,
        advertised_id_token_signing_algorithms: options.advertised_id_token_signing_algorithms,
        jwks_path: options.jwks_path,
        valid_audiences: options.valid_audiences,
        rate_limits: options.rate_limits,
        mcp,
    })
}

/// Resolve and validate OAuth provider options without building the plugin.
pub fn resolve_oauth_provider_options(
    options: OAuthProviderOptions,
) -> Result<ResolvedOAuthProviderOptions, OAuthProviderConfigError> {
    resolve_options(options)
}

/// Resolve OAuth provider options and apply JWT-derived metadata defaults.
pub fn resolve_oauth_provider_options_with_jwt(
    options: OAuthProviderOptions,
    jwt_options: JwtOptions,
) -> Result<ResolvedOAuthProviderOptions, OAuthProviderConfigError> {
    let mut resolved = resolve_options(options)?;
    if !resolved.disable_jwt_plugin {
        apply_jwt_metadata_defaults(&mut resolved, &jwt_options);
    }
    Ok(resolved)
}

fn resolve_mcp_options(
    options: Option<McpOptions>,
) -> Result<Option<ResolvedMcpOptions>, OAuthProviderConfigError> {
    options
        .map(|options| {
            if let Some(resource) = &options.resource {
                let parsed = url::Url::parse(resource)
                    .map_err(|_| OAuthProviderConfigError::InvalidMcpResource)?;
                if !parsed.has_host() {
                    return Err(OAuthProviderConfigError::InvalidMcpResource);
                }
            }
            Ok(ResolvedMcpOptions {
                resource: options.resource,
                metadata: options.metadata,
            })
        })
        .transpose()
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

fn rate_limit_rules(options: &OAuthProviderRateLimits) -> Vec<PluginRateLimitRule> {
    [
        ("/oauth2/token", RateLimitRule::new(60, 20), &options.token),
        (
            "/oauth2/authorize",
            RateLimitRule::new(60, 30),
            &options.authorize,
        ),
        (
            "/oauth2/introspect",
            RateLimitRule::new(60, 100),
            &options.introspect,
        ),
        (
            "/oauth2/revoke",
            RateLimitRule::new(60, 30),
            &options.revoke,
        ),
        (
            "/oauth2/register",
            RateLimitRule::new(60, 5),
            &options.register,
        ),
        (
            "/oauth2/userinfo",
            RateLimitRule::new(60, 60),
            &options.userinfo,
        ),
    ]
    .into_iter()
    .filter_map(|(path, default, setting)| match setting {
        OAuthProviderRateLimit::Default => Some(PluginRateLimitRule::new(path, default)),
        OAuthProviderRateLimit::Disabled => None,
        OAuthProviderRateLimit::Custom(rule) => Some(PluginRateLimitRule::new(path, rule.clone())),
    })
    .collect()
}
