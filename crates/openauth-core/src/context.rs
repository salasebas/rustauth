//! Request and runtime context contracts.

use crate::auth::trusted_origins::{matches_origin_pattern, OriginMatchSettings};
use crate::cookies::{get_cookies, AuthCookies};
use crate::crypto::password::{hash_password, verify_password};
use crate::crypto::{build_secret_config, parse_secrets_env, JweSecretSource, SecretConfig};
use crate::db::DbAdapter;
use crate::env::is_production;
use crate::env::logger::{create_logger, Logger, LoggerOptions};
use crate::error::OpenAuthError;
use crate::options::{
    DynamicRateLimitPathRule, OpenAuthOptions, RateLimitPathRule, RateLimitStorage,
    RateLimitStorageOption,
};
use crate::plugin::AuthPlugin;
use crate::rate_limit::MemoryRateLimitStorage;
use http::Request;
use openauth_oauth::oauth2::SocialOAuthProvider;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

pub mod request_state;

const DEFAULT_SECRET: &str = "better-auth-secret-12345678901234567890";

#[derive(Clone)]
pub struct AuthContext {
    pub app_name: String,
    pub base_url: String,
    pub base_path: String,
    pub options: OpenAuthOptions,
    pub auth_cookies: AuthCookies,
    pub session_config: SessionConfig,
    pub secret: String,
    pub secret_config: SecretMaterial,
    pub password: PasswordContext,
    pub rate_limit: RateLimitContext,
    pub trusted_origins: Vec<String>,
    pub disabled_paths: Vec<String>,
    pub plugins: Vec<AuthPlugin>,
    pub adapter: Option<Arc<dyn DbAdapter>>,
    pub social_providers: BTreeMap<String, Arc<dyn SocialOAuthProvider>>,
    pub logger: Logger,
}

/// Environment values used by context initialization.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuthEnvironment {
    pub better_auth_secret: Option<String>,
    pub auth_secret: Option<String>,
    pub better_auth_secrets: Option<String>,
}

impl fmt::Debug for AuthEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthEnvironment")
            .field(
                "better_auth_secret",
                &self.better_auth_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "auth_secret",
                &self.auth_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "better_auth_secrets",
                &self.better_auth_secrets.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl AuthEnvironment {
    pub fn from_process() -> Self {
        Self {
            better_auth_secret: std::env::var("BETTER_AUTH_SECRET").ok(),
            auth_secret: std::env::var("AUTH_SECRET").ok(),
            better_auth_secrets: std::env::var("BETTER_AUTH_SECRETS").ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub update_age: u64,
    pub expires_in: u64,
    pub fresh_age: u64,
    pub cookie_refresh_cache: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub enum SecretMaterial {
    Single(String),
    Rotating(SecretConfig),
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(_) => formatter
                .debug_tuple("Single")
                .field(&"<redacted>")
                .finish(),
            Self::Rotating(config) => formatter.debug_tuple("Rotating").field(config).finish(),
        }
    }
}

impl JweSecretSource for SecretMaterial {
    fn current_jwe_secret(&self) -> Result<String, OpenAuthError> {
        match self {
            Self::Single(secret) => secret.current_jwe_secret(),
            Self::Rotating(config) => config.current_jwe_secret(),
        }
    }

    fn all_jwe_secrets(&self) -> Result<Vec<crate::crypto::jwe::JweSecret>, OpenAuthError> {
        match self {
            Self::Single(secret) => secret.all_jwe_secrets(),
            Self::Rotating(config) => config.all_jwe_secrets(),
        }
    }
}

#[derive(Clone)]
pub struct PasswordContext {
    pub config: PasswordPolicy,
    pub hash: fn(&str) -> Result<String, OpenAuthError>,
    pub verify: fn(&str, &str) -> Result<bool, OpenAuthError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_password_length: usize,
    pub max_password_length: usize,
}

#[derive(Clone)]
pub struct RateLimitContext {
    pub enabled: bool,
    pub window: u64,
    pub max: u64,
    pub storage: RateLimitStorageOption,
    pub custom_rules: Vec<RateLimitPathRule>,
    pub dynamic_rules: Vec<DynamicRateLimitPathRule>,
    pub custom_storage: Option<Arc<dyn RateLimitStorage>>,
    pub memory_storage: Arc<MemoryRateLimitStorage>,
}

impl AuthContext {
    pub fn adapter(&self) -> Option<Arc<dyn DbAdapter>> {
        self.adapter.clone()
    }

    pub fn social_provider(&self, id: &str) -> Option<Arc<dyn SocialOAuthProvider>> {
        self.social_providers.get(id).cloned()
    }

    pub fn has_plugin(&self, id: &str) -> bool {
        self.plugins.iter().any(|plugin| plugin.id == id)
    }

    pub fn is_trusted_origin(&self, url: &str, settings: Option<OriginMatchSettings>) -> bool {
        self.trusted_origins
            .iter()
            .any(|origin| matches_origin_pattern(url, origin, settings))
    }

    pub fn trusted_origins_for_request(
        &self,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<Vec<String>, OpenAuthError> {
        let mut origins = self.trusted_origins.clone();
        if let Some(provider) = self.options.trusted_origins.provider() {
            for origin in provider.trusted_origins(request)? {
                push_trusted_origin(&mut origins, origin);
            }
        }
        Ok(origins)
    }

    pub fn is_trusted_origin_for_request(
        &self,
        url: &str,
        settings: Option<OriginMatchSettings>,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<bool, OpenAuthError> {
        Ok(self
            .trusted_origins_for_request(request)?
            .iter()
            .any(|origin| matches_origin_pattern(url, origin, settings)))
    }
}

pub fn create_auth_context(options: OpenAuthOptions) -> Result<AuthContext, OpenAuthError> {
    create_auth_context_with_environment_and_adapter(options, AuthEnvironment::from_process(), None)
}

pub fn create_auth_context_with_adapter(
    options: OpenAuthOptions,
    adapter: Arc<dyn DbAdapter>,
) -> Result<AuthContext, OpenAuthError> {
    create_auth_context_with_environment_and_adapter(
        options,
        AuthEnvironment::from_process(),
        Some(adapter),
    )
}

pub fn create_auth_context_with_environment(
    options: OpenAuthOptions,
    environment: AuthEnvironment,
) -> Result<AuthContext, OpenAuthError> {
    create_auth_context_with_environment_and_adapter(options, environment, None)
}

pub fn create_auth_context_with_environment_and_adapter(
    options: OpenAuthOptions,
    environment: AuthEnvironment,
    adapter: Option<Arc<dyn DbAdapter>>,
) -> Result<AuthContext, OpenAuthError> {
    let logger = create_logger(LoggerOptions::default());
    let production = options.production || is_production();
    let env_secrets = parse_secrets_env(environment.better_auth_secrets.as_deref())?;
    let secrets = if options.secrets.is_empty() {
        env_secrets.unwrap_or_default()
    } else {
        options.secrets.clone()
    };
    let legacy_secret = resolve_legacy_secret(&options, &environment);

    let (secret, secret_config) = if secrets.is_empty() {
        let secret = legacy_secret.unwrap_or_else(|| DEFAULT_SECRET.to_owned());
        validate_secret(&secret, production)?;
        (secret.clone(), SecretMaterial::Single(secret))
    } else {
        let config = build_secret_config(&secrets, legacy_secret.as_deref().unwrap_or(""))?;
        let current = config
            .keys
            .get(&config.current_version)
            .cloned()
            .ok_or_else(|| {
                OpenAuthError::InvalidSecretConfig(format!(
                    "secret version {} not found in keys",
                    config.current_version
                ))
            })?;
        (current, SecretMaterial::Rotating(config))
    };

    let base_path = options
        .base_path
        .clone()
        .unwrap_or_else(|| "/api/auth".to_owned());
    let base_url = options.base_url.clone().unwrap_or_default();
    let trusted_origins = resolve_trusted_origins(&base_url, &options);
    let auth_cookies = get_cookies(&options)?;
    let social_providers = resolve_social_providers(&options)?;
    let session_config = SessionConfig {
        update_age: options.session.update_age.unwrap_or(24 * 60 * 60),
        expires_in: options.session.expires_in.unwrap_or(60 * 60 * 24 * 7),
        fresh_age: options.session.fresh_age.unwrap_or(60 * 60 * 24),
        cookie_refresh_cache: options.session.cookie_cache.refresh_cache,
    };
    let password = PasswordContext {
        config: PasswordPolicy {
            min_password_length: options.password.min_password_length,
            max_password_length: options.password.max_password_length,
        },
        hash: hash_password,
        verify: verify_password,
    };
    validate_rate_limit_storage(&options)?;
    let rate_limit = RateLimitContext {
        enabled: options.rate_limit.enabled.unwrap_or(production),
        window: options.rate_limit.window,
        max: options.rate_limit.max,
        storage: options.rate_limit.storage,
        custom_rules: options.rate_limit.custom_rules.clone(),
        dynamic_rules: options.rate_limit.dynamic_rules.clone(),
        custom_storage: options.rate_limit.custom_storage.clone(),
        memory_storage: Arc::new(MemoryRateLimitStorage::new()),
    };

    Ok(AuthContext {
        app_name: "OpenAuth".to_owned(),
        base_url,
        base_path,
        options: options.clone(),
        auth_cookies,
        session_config,
        secret,
        secret_config,
        password,
        rate_limit,
        trusted_origins,
        disabled_paths: options.disabled_paths,
        plugins: options.plugins,
        adapter,
        social_providers,
        logger,
    })
}

fn resolve_social_providers(
    options: &OpenAuthOptions,
) -> Result<BTreeMap<String, Arc<dyn SocialOAuthProvider>>, OpenAuthError> {
    let mut providers = BTreeMap::new();
    for provider in &options.social_providers {
        let id = provider.id().to_owned();
        if id.trim().is_empty() {
            return Err(OpenAuthError::InvalidConfig(
                "social provider id cannot be empty".to_owned(),
            ));
        }
        if providers.insert(id.clone(), provider.clone()).is_some() {
            return Err(OpenAuthError::InvalidConfig(format!(
                "duplicate social provider `{id}`"
            )));
        }
    }
    Ok(providers)
}

fn resolve_trusted_origins(base_url: &str, options: &OpenAuthOptions) -> Vec<String> {
    let mut origins = Vec::new();
    if let Some(origin) = origin_from_url(base_url) {
        push_trusted_origin(&mut origins, origin);
    }
    for origin in options.trusted_origins.as_static_slice() {
        push_trusted_origin(&mut origins, origin.clone());
    }
    origins
}

fn push_trusted_origin(origins: &mut Vec<String>, origin: String) {
    if origin.trim().is_empty() {
        return;
    }
    if !origins.iter().any(|existing| existing == &origin) {
        origins.push(origin);
    }
}

fn origin_from_url(url: &str) -> Option<String> {
    let (protocol, rest) = url.split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    let host = host.split('?').next().unwrap_or(host);
    (!host.is_empty()).then(|| format!("{protocol}://{host}"))
}

fn resolve_legacy_secret(
    options: &OpenAuthOptions,
    environment: &AuthEnvironment,
) -> Option<String> {
    options
        .secret
        .clone()
        .or_else(|| environment.better_auth_secret.clone())
        .or_else(|| environment.auth_secret.clone())
}

fn validate_secret(secret: &str, production: bool) -> Result<(), OpenAuthError> {
    if secret.is_empty() {
        return Err(OpenAuthError::InvalidConfig(
            "OpenAuth secret is missing".to_owned(),
        ));
    }
    if production && secret == DEFAULT_SECRET {
        return Err(OpenAuthError::InvalidConfig(
            "default secret cannot be used in production".to_owned(),
        ));
    }
    Ok(())
}

fn validate_rate_limit_storage(options: &OpenAuthOptions) -> Result<(), OpenAuthError> {
    if options.rate_limit.custom_storage.is_some() {
        return Ok(());
    }
    if matches!(
        options.rate_limit.storage,
        RateLimitStorageOption::Database | RateLimitStorageOption::SecondaryStorage
    ) {
        return Err(OpenAuthError::InvalidConfig(
            "rate_limit.custom_storage is required when using database or secondary-storage rate limiting without a concrete adapter".to_owned(),
        ));
    }
    Ok(())
}
