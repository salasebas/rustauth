//! OAuth 2.1 and OpenID Connect provider support for OpenAuth.
//!
//! This crate models the Better Auth `oauth-provider` package as a separate
//! OpenAuth extension. It is intentionally separate from `openauth-oauth`,
//! which is for OAuth client primitives and social sign-in provider support.

use std::collections::HashSet;

use openauth_core::plugin::AuthPlugin;
use thiserror::Error;

/// Supported token endpoint grant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
}

/// Storage strategy for OAuth provider secrets and tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretStorage {
    /// Choose the upstream default from the JWT plugin setting.
    Auto,
    /// Store only a hash of the value.
    Hashed,
    /// Store an encrypted value.
    Encrypted,
}

/// User-facing OAuth provider plugin options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProviderOptions {
    pub scopes: Vec<String>,
    pub client_registration_default_scopes: Vec<String>,
    pub client_registration_allowed_scopes: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub login_page: String,
    pub consent_page: String,
    pub code_expires_in: u64,
    pub access_token_expires_in: u64,
    pub m2m_access_token_expires_in: u64,
    pub id_token_expires_in: u64,
    pub refresh_token_expires_in: u64,
    pub allow_unauthenticated_client_registration: bool,
    pub allow_dynamic_client_registration: bool,
    pub disable_jwt_plugin: bool,
    pub store_client_secret: SecretStorage,
    pub store_tokens: SecretStorage,
    pub pairwise_secret: Option<String>,
    pub advertised_scopes_supported: Vec<String>,
}

impl Default for OAuthProviderOptions {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            client_registration_default_scopes: Vec::new(),
            client_registration_allowed_scopes: Vec::new(),
            grant_types: Vec::new(),
            login_page: String::new(),
            consent_page: String::new(),
            code_expires_in: 600,
            access_token_expires_in: 3600,
            m2m_access_token_expires_in: 3600,
            id_token_expires_in: 36000,
            refresh_token_expires_in: 2_592_000,
            allow_unauthenticated_client_registration: false,
            allow_dynamic_client_registration: false,
            disable_jwt_plugin: false,
            store_client_secret: SecretStorage::Auto,
            store_tokens: SecretStorage::Hashed,
            pairwise_secret: None,
            advertised_scopes_supported: Vec::new(),
        }
    }
}

/// Fully resolved OAuth provider options after upstream-compatible defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOAuthProviderOptions {
    pub scopes: Vec<String>,
    pub claims: Vec<String>,
    pub client_registration_allowed_scopes: Vec<String>,
    pub grant_types: Vec<GrantType>,
    pub login_page: String,
    pub consent_page: String,
    pub code_expires_in: u64,
    pub access_token_expires_in: u64,
    pub m2m_access_token_expires_in: u64,
    pub id_token_expires_in: u64,
    pub refresh_token_expires_in: u64,
    pub allow_unauthenticated_client_registration: bool,
    pub allow_dynamic_client_registration: bool,
    pub disable_jwt_plugin: bool,
    pub store_client_secret: SecretStorage,
    pub store_tokens: SecretStorage,
    pub pairwise_secret: Option<String>,
    pub advertised_scopes_supported: Vec<String>,
}

/// OAuth provider extension returned by [`oauth_provider`].
#[derive(Debug, Clone)]
pub struct OAuthProviderPlugin {
    pub id: String,
    pub version: String,
    pub options: ResolvedOAuthProviderOptions,
    auth_plugin: AuthPlugin,
}

impl OAuthProviderPlugin {
    /// Convert this typed extension into the generic OpenAuth plugin contract.
    pub fn into_auth_plugin(self) -> AuthPlugin {
        self.auth_plugin
    }

    /// Borrow the generic OpenAuth plugin contract.
    pub fn as_auth_plugin(&self) -> &AuthPlugin {
        &self.auth_plugin
    }
}

/// OAuth provider configuration errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OAuthProviderConfigError {
    #[error("login_page is required")]
    MissingLoginPage,
    #[error("consent_page is required")]
    MissingConsentPage,
    #[error("clientRegistrationAllowedScope {0} not found in scopes")]
    UnknownClientRegistrationScope(String),
    #[error("advertisedMetadata.scopes_supported {0} not found in scopes")]
    UnknownAdvertisedScope(String),
    #[error(
        "pairwiseSecret must be at least 32 characters long for adequate HMAC-SHA256 security"
    )]
    PairwiseSecretTooShort,
    #[error("refresh_token grant requires authorization_code grant")]
    RefreshTokenRequiresAuthorizationCode,
    #[error("unable to store hashed secrets because id tokens will be signed with secret")]
    HashedClientSecretsRequireJwtPlugin,
    #[error("encryption method not recommended, please use 'hashed' or the 'hash' function")]
    EncryptedClientSecretsWithJwtPlugin,
}

/// Build the OAuth provider extension.
pub fn oauth_provider(
    options: OAuthProviderOptions,
) -> Result<OAuthProviderPlugin, OAuthProviderConfigError> {
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
    let resolved = ResolvedOAuthProviderOptions {
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
    };

    Ok(OAuthProviderPlugin {
        id: "oauth-provider".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        options: resolved,
        auth_plugin: AuthPlugin::new("oauth-provider").with_version(env!("CARGO_PKG_VERSION")),
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

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
