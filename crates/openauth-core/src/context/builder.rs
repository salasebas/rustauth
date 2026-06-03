use std::collections::BTreeMap;
use std::sync::Arc;

#[cfg(feature = "oauth")]
use openauth_oauth::oauth2::SocialOAuthProvider;

use crate::cookies::get_cookies;
use crate::crypto::password::{hash_password, verify_password};
use crate::crypto::{build_secret_config, parse_secrets_env};
use crate::db::RateLimitStorage as DbRateLimitStorage;
use crate::db::{auth_schema, AuthSchemaOptions, DbAdapter, DbField, HookedAdapter};
use crate::env::is_production;
use crate::env::logger::create_logger;
use crate::error::OpenAuthError;
use crate::options::hooks::{plugin_after_hooks, plugin_before_hooks};
use crate::options::RateLimitStore;
use crate::options::{
    OpenAuthOptions, RateLimitStorageOption, SessionAdditionalField, UserAdditionalField,
};
use crate::plugin::AuthPlugin;
use crate::rate_limit::{GovernorMemoryRateLimitStore, LegacyRateLimitStorageAdapter};

use super::origins::resolve_trusted_origins;
use super::plugins::initialize_plugins;
use super::secrets::{resolve_legacy_secret, validate_secret, DEFAULT_SECRET};
use super::{
    noop_telemetry_publisher, AuthContext, AuthEnvironment, PasswordContext, PasswordPolicy,
    RateLimitContext, SecretMaterial, SessionConfig,
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
    let logger = create_logger(options.logger.clone());
    let production = options.production || is_production();
    let env_secrets = parse_secrets_env(environment.openauth_secrets.as_deref())?;
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
    #[cfg(feature = "oauth")]
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
        hash: options.password.hash_password.unwrap_or(hash_password),
        verify: options.password.verify_password.unwrap_or(verify_password),
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
        memory_cleanup_interval: options.rate_limit.memory_cleanup_interval,
        memory_store: Arc::new(GovernorMemoryRateLimitStore::with_cleanup_interval(
            options.rate_limit.memory_cleanup_interval,
        )),
        missing_ip_policy: options.rate_limit.missing_ip_policy,
    };

    let schema_options = schema_options_from_auth_options(&options);
    let app_name = options
        .app_name
        .clone()
        .unwrap_or_else(|| "OpenAuth".to_owned());
    let mut context = AuthContext {
        app_name,
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
        secondary_storage: options.secondary_storage.clone(),
        background_tasks: options.advanced.background_tasks.clone(),
        #[cfg(feature = "oauth")]
        social_providers,
        db_schema: auth_schema(schema_options),
        plugin_error_codes: BTreeMap::new(),
        plugin_database_hooks: options.database_hooks.clone(),
        plugin_migrations: Vec::new(),
        telemetry_publisher: noop_telemetry_publisher(),
        logger,
    };
    apply_global_hooks(&mut context);
    initialize_plugins(&mut context)?;
    if !context.plugin_database_hooks.is_empty() {
        if let Some(adapter) = context.adapter.clone() {
            context.adapter = Some(Arc::new(HookedAdapter::with_logger(
                adapter,
                context.plugin_database_hooks.clone(),
                context.logger.clone(),
            )));
        }
    }
    Ok(context)
}

fn apply_global_hooks(context: &mut AuthContext) {
    let before = plugin_before_hooks(&context.options.hooks);
    let after = plugin_after_hooks(&context.options.hooks);
    if before.is_empty() && after.is_empty() {
        return;
    }
    let mut plugin = AuthPlugin::new("__openauth_global__");
    plugin.hooks.before = before;
    plugin.hooks.after = after;
    context.plugins.insert(0, plugin);
}

#[cfg(feature = "oauth")]
fn resolve_social_providers(
    options: &OpenAuthOptions,
) -> Result<BTreeMap<String, Arc<dyn SocialOAuthProvider>>, OpenAuthError> {
    let mut providers = BTreeMap::new();
    for provider in &options.social_providers {
        insert_social_provider(&mut providers, provider.clone())?;
    }
    Ok(providers)
}

#[cfg(feature = "oauth")]
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
    let mut schema_options = AuthSchemaOptions {
        has_secondary_storage: options.secondary_storage.is_some(),
        store_session_in_database: options.session.store_session_in_database,
        rate_limit_storage: match options.rate_limit.storage {
            RateLimitStorageOption::Memory => DbRateLimitStorage::Memory,
            RateLimitStorageOption::Database => DbRateLimitStorage::Database,
            RateLimitStorageOption::SecondaryStorage => DbRateLimitStorage::SecondaryStorage,
        },
        ..AuthSchemaOptions::default()
    };
    for (name, field) in &options.user.additional_fields {
        schema_options
            .user
            .additional_fields
            .insert(name.clone(), user_additional_field_to_db_field(name, field));
    }
    for (name, field) in &options.session.additional_fields {
        schema_options.session.additional_fields.insert(
            name.clone(),
            session_additional_field_to_db_field(name, field),
        );
    }
    schema_options
}

pub(super) fn user_additional_field_to_db_field(
    logical_name: &str,
    field: &UserAdditionalField,
) -> DbField {
    additional_field_to_db_field(
        logical_name,
        field.db_name.as_deref(),
        field.field_type.clone(),
        field.required,
        field.input,
        field.returned,
    )
}

pub(super) fn session_additional_field_to_db_field(
    logical_name: &str,
    field: &SessionAdditionalField,
) -> DbField {
    additional_field_to_db_field(
        logical_name,
        field.db_name.as_deref(),
        field.field_type.clone(),
        field.required,
        field.input,
        field.returned,
    )
}

fn additional_field_to_db_field(
    logical_name: &str,
    db_name: Option<&str>,
    field_type: crate::db::DbFieldType,
    required: bool,
    input: bool,
    returned: bool,
) -> DbField {
    let mut field = DbField::new(db_name.unwrap_or(logical_name), field_type);
    if !required {
        field = field.optional();
    }
    if !input {
        field = field.generated();
    }
    if !returned {
        field = field.hidden();
    }
    field
}
