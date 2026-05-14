use std::fmt;
use std::sync::Arc;

use openauth_oauth::oauth2::SocialOAuthProvider;

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
