use std::collections::BTreeMap;
use std::sync::Arc;

use openauth_oauth::oauth2::SocialOAuthProvider;

use crate::cookies::get_cookies;
use crate::crypto::password::{hash_password, verify_password};
use crate::crypto::{build_secret_config, parse_secrets_env};
use crate::db::RateLimitStorage as DbRateLimitStorage;
use crate::db::{auth_schema, AuthSchemaOptions, DbAdapter, HookedAdapter};
use crate::env::is_production;
use crate::env::logger::{create_logger, LoggerOptions};
use crate::error::OpenAuthError;
use crate::options::RateLimitStore;
use crate::options::{OpenAuthOptions, RateLimitStorageOption};
use crate::rate_limit::{LegacyRateLimitStorageAdapter, TokioMemoryRateLimitStore};

use super::origins::resolve_trusted_origins;
use super::plugins::initialize_plugins;
use super::secrets::{resolve_legacy_secret, validate_secret, DEFAULT_SECRET};
use super::{
    AuthContext, AuthEnvironment, PasswordContext, PasswordPolicy, RateLimitContext,
    SecretMaterial, SessionConfig,
};

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
        plugin_rules: Vec::new(),
        custom_store: options.rate_limit.custom_store.clone().or_else(|| {
            options.rate_limit.custom_storage.clone().map(|storage| {
                Arc::new(LegacyRateLimitStorageAdapter::new(storage)) as Arc<dyn RateLimitStore>
            })
        }),
        hybrid: options.rate_limit.hybrid.clone(),
        memory_idle_ttl: options.rate_limit.memory_idle_ttl,
        memory_store: Arc::new(TokioMemoryRateLimitStore::with_idle_ttl(
            options.rate_limit.memory_idle_ttl,
        )),
    };

    let schema_options = schema_options_from_auth_options(&options);
    let mut context = AuthContext {
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
        db_schema: auth_schema(schema_options),
        plugin_error_codes: BTreeMap::new(),
        plugin_database_hooks: Vec::new(),
        plugin_migrations: Vec::new(),
        logger,
    };
    initialize_plugins(&mut context)?;
    if !context.plugin_database_hooks.is_empty() {
        if let Some(adapter) = context.adapter.clone() {
            context.adapter = Some(Arc::new(HookedAdapter::new(
                adapter,
                context.plugin_database_hooks.clone(),
            )));
        }
    }
    Ok(context)
}

fn resolve_social_providers(
    options: &OpenAuthOptions,
) -> Result<BTreeMap<String, Arc<dyn SocialOAuthProvider>>, OpenAuthError> {
    let mut providers = BTreeMap::new();
    for provider in &options.social_providers {
        insert_social_provider(&mut providers, provider.clone())?;
    }
    Ok(providers)
}

pub(super) fn insert_social_provider(
    providers: &mut BTreeMap<String, Arc<dyn SocialOAuthProvider>>,
    provider: Arc<dyn SocialOAuthProvider>,
) -> Result<(), OpenAuthError> {
    let id = provider.id().to_owned();
    if id.trim().is_empty() {
        return Err(OpenAuthError::InvalidConfig(
            "social provider id cannot be empty".to_owned(),
        ));
    }
    if providers.insert(id.clone(), provider).is_some() {
        return Err(OpenAuthError::InvalidConfig(format!(
            "duplicate social provider `{id}`"
        )));
    }
    Ok(())
}

fn validate_rate_limit_storage(options: &OpenAuthOptions) -> Result<(), OpenAuthError> {
    if options.rate_limit.custom_store.is_some() || options.rate_limit.custom_storage.is_some() {
        return Ok(());
    }
    if matches!(
        options.rate_limit.storage,
        RateLimitStorageOption::Database | RateLimitStorageOption::SecondaryStorage
    ) {
        return Err(OpenAuthError::InvalidConfig(
            "rate_limit.custom_store or rate_limit.custom_storage is required when using database or secondary-storage rate limiting without a concrete adapter".to_owned(),
        ));
    }
    Ok(())
}

fn schema_options_from_auth_options(options: &OpenAuthOptions) -> AuthSchemaOptions {
    AuthSchemaOptions {
        rate_limit_storage: match options.rate_limit.storage {
            RateLimitStorageOption::Memory => DbRateLimitStorage::Memory,
            RateLimitStorageOption::Database => DbRateLimitStorage::Database,
            RateLimitStorageOption::SecondaryStorage => DbRateLimitStorage::SecondaryStorage,
        },
        ..AuthSchemaOptions::default()
    }
}
