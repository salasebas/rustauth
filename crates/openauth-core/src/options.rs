//! Configuration types for OpenAuth core.

use crate::crypto::SecretEntry;
use crate::db::{DbFieldType, User};
use crate::error::OpenAuthError;
use crate::plugin::AuthPlugin;
use crate::utils::ip::Ipv6Subnet;
use http::Request;
use openauth_oauth::oauth2::SocialOAuthProvider;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Telemetry collection settings (parity with Better Auth `telemetry` init option).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TelemetryOptions {
    /// When `None`, option-side telemetry is off unless overridden by environment.
    pub enabled: Option<bool>,
    pub debug: bool,
}

/// Experimental feature flags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExperimentalOptions {
    pub joins: bool,
}

/// Top-level OpenAuth configuration.
#[derive(Clone, Default)]
pub struct OpenAuthOptions {
    pub base_url: Option<String>,
    pub base_path: Option<String>,
    pub secret: Option<String>,
    pub secrets: Vec<SecretEntry>,
    pub trusted_origins: TrustedOriginOptions,
    pub disabled_paths: Vec<String>,
    pub session: SessionOptions,
    pub user: UserOptions,
    pub email_verification: EmailVerificationOptions,
    pub password: PasswordOptions,
    pub account: AccountOptions,
    pub advanced: AdvancedOptions,
    pub rate_limit: RateLimitOptions,
    pub plugins: Vec<AuthPlugin>,
    pub social_providers: Vec<Arc<dyn SocialOAuthProvider>>,
    pub production: bool,
    pub telemetry: TelemetryOptions,
    pub experimental: ExperimentalOptions,
}

impl fmt::Debug for OpenAuthOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAuthOptions")
            .field("base_url", &self.base_url)
            .field("base_path", &self.base_path)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field(
                "secrets",
                &format_args!("{} secret(s) redacted", self.secrets.len()),
            )
            .field("trusted_origins", &self.trusted_origins)
            .field("disabled_paths", &self.disabled_paths)
            .field("session", &self.session)
            .field("user", &self.user)
            .field("email_verification", &self.email_verification)
            .field("password", &self.password)
            .field("account", &self.account)
            .field("advanced", &self.advanced)
            .field("rate_limit", &self.rate_limit)
            .field("plugins", &self.plugins)
            .field(
                "social_providers",
                &self
                    .social_providers
                    .iter()
                    .map(|provider| provider.id())
                    .collect::<Vec<_>>(),
            )
            .field("production", &self.production)
            .field("telemetry", &self.telemetry)
            .field("experimental", &self.experimental)
            .finish()
    }
}

/// Account and OAuth account behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountOptions {
    pub update_account_on_sign_in: bool,
    pub encrypt_oauth_tokens: bool,
    pub store_account_cookie: bool,
    pub store_state_strategy: OAuthStateStoreStrategy,
    pub account_linking: AccountLinkingOptions,
}

impl Default for AccountOptions {
    fn default() -> Self {
        Self {
            update_account_on_sign_in: true,
            encrypt_oauth_tokens: false,
            store_account_cookie: false,
            store_state_strategy: OAuthStateStoreStrategy::Cookie,
            account_linking: AccountLinkingOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OAuthStateStoreStrategy {
    #[default]
    Cookie,
    Database,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLinkingOptions {
    pub enabled: bool,
    pub disable_implicit_linking: bool,
    pub trusted_providers: Vec<String>,
    pub allow_different_emails: bool,
    pub allow_unlinking_all: bool,
    pub update_user_info_on_link: bool,
}

impl Default for AccountLinkingOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            disable_implicit_linking: false,
            trusted_providers: Vec::new(),
            allow_different_emails: false,
            allow_unlinking_all: false,
            update_user_info_on_link: false,
        }
    }
}

/// User lifecycle configuration.
#[derive(Debug, Clone, Default)]
pub struct UserOptions {
    pub change_email: ChangeEmailOptions,
    pub delete_user: DeleteUserOptions,
}

/// Email change behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeEmailOptions {
    pub enabled: bool,
    pub update_email_without_verification: bool,
}

/// User deletion behavior.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteUserOptions {
    pub enabled: bool,
}

/// Payload passed to an email verification sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationEmail {
    pub user: User,
    pub url: String,
    pub token: String,
}

/// Synchronous email verification sender hook.
pub trait SendVerificationEmail: Send + Sync + 'static {
    fn send_verification_email(
        &self,
        email: VerificationEmail,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError>;
}

impl<F> SendVerificationEmail for F
where
    F: for<'a> Fn(VerificationEmail, Option<&'a Request<Vec<u8>>>) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn send_verification_email(
        &self,
        email: VerificationEmail,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self(email, request)
    }
}

/// Email verification configuration.
#[derive(Clone, Default)]
pub struct EmailVerificationOptions {
    pub send_verification_email: Option<Arc<dyn SendVerificationEmail>>,
    pub expires_in: Option<u64>,
    pub auto_sign_in_after_verification: bool,
}

impl fmt::Debug for EmailVerificationOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailVerificationOptions")
            .field(
                "send_verification_email",
                &self
                    .send_verification_email
                    .as_ref()
                    .map(|_| "<send-verification-email>"),
            )
            .field("expires_in", &self.expires_in)
            .field(
                "auto_sign_in_after_verification",
                &self.auto_sign_in_after_verification,
            )
            .finish()
    }
}

/// Request-aware trusted origin provider.
pub trait TrustedOriginsProvider: Send + Sync + 'static {
    fn trusted_origins(
        &self,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<Vec<String>, OpenAuthError>;
}

impl<F> TrustedOriginsProvider for F
where
    F: for<'a> Fn(Option<&'a Request<Vec<u8>>>) -> Result<Vec<String>, OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn trusted_origins(
        &self,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<Vec<String>, OpenAuthError> {
        self(request)
    }
}

#[derive(Clone, Default)]
pub enum TrustedOriginOptions {
    #[default]
    None,
    Static(Vec<String>),
    Dynamic {
        origins: Vec<String>,
        provider: Arc<dyn TrustedOriginsProvider>,
    },
}

impl TrustedOriginOptions {
    pub fn dynamic<P>(provider: P) -> Self
    where
        P: TrustedOriginsProvider,
    {
        Self::Dynamic {
            origins: Vec::new(),
            provider: Arc::new(provider),
        }
    }

    pub fn dynamic_with_static<P>(origins: Vec<String>, provider: P) -> Self
    where
        P: TrustedOriginsProvider,
    {
        Self::Dynamic {
            origins,
            provider: Arc::new(provider),
        }
    }

    pub fn as_static_slice(&self) -> &[String] {
        match self {
            Self::None => &[],
            Self::Static(origins) => origins,
            Self::Dynamic { origins, .. } => origins,
        }
    }

    pub fn provider(&self) -> Option<&dyn TrustedOriginsProvider> {
        match self {
            Self::Dynamic { provider, .. } => Some(provider.as_ref()),
            Self::None | Self::Static(_) => None,
        }
    }
}

impl fmt::Debug for TrustedOriginOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("None"),
            Self::Static(origins) => formatter.debug_tuple("Static").field(origins).finish(),
            Self::Dynamic { origins, .. } => formatter
                .debug_struct("Dynamic")
                .field("origins", origins)
                .field("provider", &"<request-aware>")
                .finish(),
        }
    }
}

/// Session configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionOptions {
    pub expires_in: Option<u64>,
    pub update_age: Option<u64>,
    pub fresh_age: Option<u64>,
    pub cookie_cache: CookieCacheOptions,
    pub additional_fields: BTreeMap<String, SessionAdditionalField>,
}

/// Runtime metadata for custom session fields accepted by `/update-session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAdditionalField {
    pub field_type: DbFieldType,
    pub input: bool,
    pub returned: bool,
}

impl SessionAdditionalField {
    pub fn new(field_type: DbFieldType) -> Self {
        Self {
            field_type,
            input: true,
            returned: true,
        }
    }

    #[must_use]
    pub fn generated(mut self) -> Self {
        self.input = false;
        self
    }

    #[must_use]
    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }
}

/// Session cookie cache configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieCacheOptions {
    pub enabled: bool,
    pub max_age: Option<u64>,
    pub strategy: CookieCacheStrategy,
    pub refresh_cache: bool,
    pub version: Option<String>,
}

impl Default for CookieCacheOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: None,
            strategy: CookieCacheStrategy::Compact,
            refresh_cache: false,
            version: None,
        }
    }
}

/// Cookie cache encoding strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieCacheStrategy {
    Compact,
    Jwt,
    Jwe,
}

/// Cross-subdomain cookie configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CookieConfig {
    pub enabled: bool,
    pub domain: Option<String>,
}

/// Advanced configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvancedOptions {
    pub use_secure_cookies: Option<bool>,
    pub cookie_prefix: Option<String>,
    pub cross_subdomain_cookies: Option<CookieConfig>,
    pub default_cookie_attributes: CookieAttributesOverride,
    pub disable_csrf_check: bool,
    pub disable_origin_check: bool,
    pub skip_trailing_slashes: bool,
    pub ip_address: IpAddressOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressOptions {
    pub headers: Vec<String>,
    pub disable_ip_tracking: bool,
    pub ipv6_subnet: Ipv6Subnet,
}

impl Default for IpAddressOptions {
    fn default() -> Self {
        Self {
            headers: vec!["x-forwarded-for".to_owned()],
            disable_ip_tracking: false,
            ipv6_subnet: Ipv6Subnet::Prefix64,
        }
    }
}

/// User-supplied cookie attribute defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CookieAttributesOverride {
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub max_age: Option<u64>,
    pub partitioned: Option<bool>,
}

/// Password policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordOptions {
    pub min_password_length: usize,
    pub max_password_length: usize,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            min_password_length: 8,
            max_password_length: 128,
        }
    }
}

/// Rate limiting defaults.
#[derive(Clone)]
pub struct RateLimitOptions {
    pub enabled: Option<bool>,
    pub window: u64,
    pub max: u64,
    pub storage: RateLimitStorageOption,
    pub custom_rules: Vec<RateLimitPathRule>,
    pub dynamic_rules: Vec<DynamicRateLimitPathRule>,
    pub custom_storage: Option<Arc<dyn RateLimitStorage>>,
}

impl Default for RateLimitOptions {
    fn default() -> Self {
        Self {
            enabled: None,
            window: 10,
            max: 100,
            storage: RateLimitStorageOption::Memory,
            custom_rules: Vec::new(),
            dynamic_rules: Vec::new(),
            custom_storage: None,
        }
    }
}

impl fmt::Debug for RateLimitOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitOptions")
            .field("enabled", &self.enabled)
            .field("window", &self.window)
            .field("max", &self.max)
            .field("storage", &self.storage)
            .field("custom_rules", &self.custom_rules)
            .field("dynamic_rules", &self.dynamic_rules)
            .field(
                "custom_storage",
                &self.custom_storage.as_ref().map(|_| "<custom-storage>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRule {
    pub window: u64,
    pub max: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitPathRule {
    pub path: String,
    pub rule: Option<RateLimitRule>,
}

pub trait RateLimitRuleProvider: Send + Sync + 'static {
    fn resolve(
        &self,
        request: &Request<Vec<u8>>,
        current_rule: &RateLimitRule,
    ) -> Result<Option<RateLimitRule>, OpenAuthError>;
}

impl<F> RateLimitRuleProvider for F
where
    F: Fn(&Request<Vec<u8>>, &RateLimitRule) -> Result<Option<RateLimitRule>, OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn resolve(
        &self,
        request: &Request<Vec<u8>>,
        current_rule: &RateLimitRule,
    ) -> Result<Option<RateLimitRule>, OpenAuthError> {
        self(request, current_rule)
    }
}

#[derive(Clone)]
pub struct DynamicRateLimitPathRule {
    pub path: String,
    pub provider: Arc<dyn RateLimitRuleProvider>,
}

impl DynamicRateLimitPathRule {
    pub fn new<P>(path: impl Into<String>, provider: P) -> Self
    where
        P: RateLimitRuleProvider,
    {
        Self {
            path: path.into(),
            provider: Arc::new(provider),
        }
    }
}

impl fmt::Debug for DynamicRateLimitPathRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynamicRateLimitPathRule")
            .field("path", &self.path)
            .field("provider", &"<request-aware>")
            .finish()
    }
}

/// Rate limit storage record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRecord {
    pub key: String,
    pub count: u64,
    pub last_request: i64,
}

/// Synchronous storage contract for router-level rate limiting.
pub trait RateLimitStorage: Send + Sync + 'static {
    fn get(&self, key: &str) -> Result<Option<RateLimitRecord>, OpenAuthError>;
    fn set(
        &self,
        key: &str,
        value: RateLimitRecord,
        ttl_seconds: u64,
        update: bool,
    ) -> Result<(), OpenAuthError>;
}

/// Rate limit storage selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitStorageOption {
    Memory,
    Database,
    SecondaryStorage,
}
