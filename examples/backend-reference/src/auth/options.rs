//! Core [`RustAuthOptions`] for the reference stack: sessions, email/password,
//! trusted origins, rate limits, and lifecycle hooks.

use std::sync::Arc;

use http::Method;
use rustauth::api::ApiRequest;
use rustauth::context::AuthContext;
#[cfg(feature = "telemetry")]
use rustauth::options::TelemetryOptions;
use rustauth::options::{
    AdvancedOptions, ChangeEmailOptions, DeploymentMode, EmailPasswordOptions,
    EmailVerificationOptions, GlobalHookAction, GlobalHooksOptions, MissingIpPolicy,
    RustAuthOptions, RateLimitOptions, RateLimitRule, SessionOptions, TrustedOriginOptions,
    TrustedOriginsProvider, UserOptions, VerificationEmail,
};
use rustauth::prelude::RustAuthError;
use rustauth_core::OutboundSendFuture;
use time::Duration;
use tracing::info;

use crate::auth::plugins;
use crate::auth::social_providers;
use crate::config::{AppConfig, DEFAULT_SECRET};
use crate::error::AppResult;

/// Compose the effective RustAuth configuration for this application.
pub fn build_rustauth_options(config: &AppConfig) -> AppResult<RustAuthOptions> {
    let plugins = plugins::all_plugins()?;
    let mode = AppConfig::deployment_mode();
    let relax_security = !matches!(mode, DeploymentMode::Production);
    let mut options = RustAuthOptions::new()
        .app_name("RustAuth Backend Reference")
        .base_url(config.base_url.clone())
        .base_path(config.auth_base_path.clone())
        .secret(config.secret.clone())
        .deployment_mode(mode)
        .trusted_origins(trusted_origins(config))
        .session(
            SessionOptions::new()
                .expires_in(Duration::days(7))
                .update_age(Duration::seconds(60 * 60 * 24))
                .fresh_age(Duration::seconds(60 * 60 * 24)),
        )
        .user(UserOptions::new().change_email(ChangeEmailOptions::new().enabled(true)))
        .email_password(
            EmailPasswordOptions::new()
                .enabled(true)
                .auto_sign_in(true)
                .require_email_verification(false),
        )
        .email_verification(
            EmailVerificationOptions::new().send_verification_email(stub_verification_email),
        )
        .hooks(GlobalHooksOptions {
            before: Some(Arc::new(log_before_hook)),
            ..GlobalHooksOptions::default()
        })
        .rate_limit(rate_limit_options())
        .advanced(
            AdvancedOptions::builder()
                .cookie_prefix("rustauth-reference")
                .disable_csrf_check(relax_security)
                .disable_origin_check(relax_security),
        )
        .plugins(plugins);

    options = social_providers::apply_social_providers(options, config)?;
    options = apply_optional_telemetry(options);

    #[cfg(debug_assertions)]
    {
        options = rustauth_core::test_utils::apply_fast_password_defaults(options);
    }

    if matches!(mode, DeploymentMode::Production) && config.secret == DEFAULT_SECRET {
        return Err(crate::error::AppError::Config(
            "set RUSTAUTH_SECRET to a production-strength value when RUST_ENV=production"
                .to_owned(),
        ));
    }

    Ok(options)
}

/// Enable telemetry when the `telemetry` feature is on and `RUSTAUTH_TELEMETRY=1`.
#[cfg(feature = "telemetry")]
fn apply_optional_telemetry(options: RustAuthOptions) -> RustAuthOptions {
    let enabled = std::env::var("RUSTAUTH_TELEMETRY")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE"));
    if enabled {
        options.telemetry(TelemetryOptions::new().enabled(true))
    } else {
        options
    }
}

#[cfg(not(feature = "telemetry"))]
fn apply_optional_telemetry(options: RustAuthOptions) -> RustAuthOptions {
    options
}

/// Options used to derive the database schema before connecting Postgres.
pub fn schema_seed_options() -> AppResult<RustAuthOptions> {
    let config = AppConfig {
        host: "127.0.0.1".to_owned(),
        port: 3000,
        auth_base_path: crate::config::AUTH_BASE_PATH.to_owned(),
        base_url: format!("http://127.0.0.1:3000{}", crate::config::AUTH_BASE_PATH),
        secret: DEFAULT_SECRET.to_owned(),
        database_url: String::new(),
        trusted_origins: vec!["http://127.0.0.1:3000".to_owned()],
        cognito_domain: "rustauth-reference.auth.example.com".to_owned(),
        cognito_region: "us-east-1".to_owned(),
        cognito_user_pool_id: "us-east-1_rustauth_reference".to_owned(),
    };
    build_rustauth_options(&config)
}

fn trusted_origins(config: &AppConfig) -> TrustedOriginOptions {
    if config.trusted_origins.is_empty() {
        return TrustedOriginOptions::None;
    }

    let origins = config.trusted_origins.clone();
    TrustedOriginOptions::dynamic_with_static(origins.clone(), StaticOrigins(origins))
}

fn rate_limit_options() -> RateLimitOptions {
    apply_rate_limit_rules(RateLimitOptions::memory())
}

/// Apply shared reference rate-limit policy on top of any storage backend.
pub fn apply_rate_limit_rules(options: RateLimitOptions) -> RateLimitOptions {
    let sign_in_rule = RateLimitRule::new(time::Duration::seconds(60), 30);
    options
        .enabled(true)
        .window(Duration::seconds(60))
        .max(120)
        .missing_ip_policy(MissingIpPolicy::SharedBucket)
        .custom_rule("/sign-in/*", sign_in_rule.clone())
        .custom_rule("/sign-up/*", sign_in_rule)
}

#[derive(Clone)]
struct StaticOrigins(Vec<String>);

impl TrustedOriginsProvider for StaticOrigins {
    fn trusted_origins(
        &self,
        _request: Option<&http::Request<Vec<u8>>>,
    ) -> Result<Vec<String>, rustauth::error::RustAuthError> {
        Ok(self.0.clone())
    }
}

/// Return plugin ids for introspection without building the full plugin vec.
pub fn enabled_plugin_ids() -> &'static [&'static str] {
    plugins::ENABLED_PLUGIN_IDS
}

fn stub_verification_email(
    email: VerificationEmail,
    _request: Option<&http::Request<Vec<u8>>>,
) -> OutboundSendFuture {
    Box::pin(async move {
        info!(
            user_id = %email.user.id,
            email = %email.user.email,
            url = %email.url,
            "verification email stub"
        );
        Ok(())
    })
}

fn log_before_hook(
    _ctx: &AuthContext,
    request: ApiRequest,
    _method: &Method,
    path: &str,
) -> Result<GlobalHookAction, RustAuthError> {
    tracing::debug!(path, "auth request");
    Ok(GlobalHookAction::Continue(request))
}
