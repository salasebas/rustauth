use openauth_core::plugin::AuthPlugin;
use thiserror::Error;

/// Supported token endpoint grant types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
}

impl GrantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// OAuth token endpoint client authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }
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
    pub valid_audiences: Vec<String>,
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
            valid_audiences: Vec::new(),
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
    pub valid_audiences: Vec<String>,
}

/// OAuth provider extension returned by [`crate::oauth_provider`].
#[derive(Debug, Clone)]
pub struct OAuthProviderPlugin {
    pub id: String,
    pub version: String,
    pub options: ResolvedOAuthProviderOptions,
    pub(crate) auth_plugin: AuthPlugin,
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
    #[error("unable to initialize jwt plugin: {0}")]
    JwtPlugin(String),
}
