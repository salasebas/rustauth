use std::fmt;
use std::sync::Arc;

use openauth_oauth::oauth2::SocialOAuthProvider;

use super::storage::SecondaryStorage;
use crate::crypto::SecretEntry;
use crate::plugin::AuthPlugin;

use super::account::AccountOptions;
use super::advanced::AdvancedOptions;
use super::email_verification::EmailVerificationOptions;
use super::origins::TrustedOriginOptions;
use super::password::PasswordOptions;
use super::rate_limit::RateLimitOptions;
use super::session::SessionOptions;
use super::user::UserOptions;

/// Telemetry collection settings (parity with Better Auth `telemetry` init option).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TelemetryOptions {
    /// When `None`, option-side telemetry is off unless overridden by environment.
    pub enabled: Option<bool>,
    pub debug: bool,
}

impl TelemetryOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    #[must_use]
    pub fn debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }
}

/// Experimental feature flags.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExperimentalOptions {
    pub joins: bool,
}

impl ExperimentalOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn joins(mut self, enabled: bool) -> Self {
        self.joins = enabled;
        self
    }
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
    pub secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    pub plugins: Vec<AuthPlugin>,
    pub social_providers: Vec<Arc<dyn SocialOAuthProvider>>,
    pub production: bool,
    pub telemetry: TelemetryOptions,
    pub experimental: ExperimentalOptions,
}

impl OpenAuthOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    #[must_use]
    pub fn base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = Some(base_path.into());
        self
    }

    #[must_use]
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    #[must_use]
    pub fn secrets(mut self, secrets: Vec<SecretEntry>) -> Self {
        self.secrets = secrets;
        self
    }

    #[must_use]
    pub fn trusted_origins(mut self, trusted_origins: TrustedOriginOptions) -> Self {
        self.trusted_origins = trusted_origins;
        self
    }

    #[must_use]
    pub fn disabled_path(mut self, path: impl Into<String>) -> Self {
        self.disabled_paths.push(path.into());
        self
    }

    #[must_use]
    pub fn disabled_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.disabled_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn session(mut self, session: SessionOptions) -> Self {
        self.session = session;
        self
    }

    #[must_use]
    pub fn user(mut self, user: UserOptions) -> Self {
        self.user = user;
        self
    }

    #[must_use]
    pub fn email_verification(mut self, email_verification: EmailVerificationOptions) -> Self {
        self.email_verification = email_verification;
        self
    }

    #[must_use]
    pub fn password(mut self, password: PasswordOptions) -> Self {
        self.password = password;
        self
    }

    #[must_use]
    pub fn account(mut self, account: AccountOptions) -> Self {
        self.account = account;
        self
    }

    #[must_use]
    pub fn advanced(mut self, advanced: AdvancedOptions) -> Self {
        self.advanced = advanced;
        self
    }

    #[must_use]
    pub fn rate_limit(mut self, rate_limit: RateLimitOptions) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    #[must_use]
    pub fn secondary_storage(mut self, storage: Arc<dyn SecondaryStorage>) -> Self {
        self.secondary_storage = Some(storage);
        self
    }

    #[must_use]
    pub fn plugin(mut self, plugin: AuthPlugin) -> Self {
        self.plugins.push(plugin);
        self
    }

    #[must_use]
    pub fn plugins(mut self, plugins: Vec<AuthPlugin>) -> Self {
        self.plugins = plugins;
        self
    }

    #[must_use]
    pub fn social_provider<P>(mut self, provider: P) -> Self
    where
        P: SocialOAuthProvider,
    {
        self.social_providers.push(Arc::new(provider));
        self
    }

    #[must_use]
    pub fn social_provider_arc(mut self, provider: Arc<dyn SocialOAuthProvider>) -> Self {
        self.social_providers.push(provider);
        self
    }

    #[must_use]
    pub fn production(mut self, production: bool) -> Self {
        self.production = production;
        self
    }

    #[must_use]
    pub fn telemetry(mut self, telemetry: TelemetryOptions) -> Self {
        self.telemetry = telemetry;
        self
    }

    #[must_use]
    pub fn experimental(mut self, experimental: ExperimentalOptions) -> Self {
        self.experimental = experimental;
        self
    }
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
            .field(
                "secondary_storage",
                &self
                    .secondary_storage
                    .as_ref()
                    .map(|_| "<secondary-storage>"),
            )
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
