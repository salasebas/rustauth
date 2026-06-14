//! Maps [`rustauth_core::options::RustAuthOptions`] into the anonymized JSON snapshot
//! expected by Better Auth telemetry (`getTelemetryAuthConfig`).
//!
//! Maps modeled [`RustAuthOptions`] branches into the anonymized Better Auth telemetry snapshot.

use std::collections::BTreeMap;

use rustauth_core::env::logger::LogLevel;
use rustauth_core::options::{
    CookieCacheStrategy, DatabaseModelHooks, InitDatabaseHooksOptions, ModelSchemaOptions,
    RateLimitStorageOption, RustAuthOptions, SessionAdditionalField, TrustedOriginOptions,
    UserAdditionalField,
};
use serde_json::{json, Map, Value};

use crate::types::TelemetryContext;

fn telemetry_model_name(model_name: &Option<String>) -> Value {
    if model_name.is_some() {
        Value::Bool(true)
    } else {
        Value::Null
    }
}

fn telemetry_field_names(field_names: &BTreeMap<String, String>) -> Value {
    if field_names.is_empty() {
        Value::Null
    } else {
        Value::Object(
            field_names
                .keys()
                .map(|name| (name.clone(), Value::Bool(true)))
                .collect(),
        )
    }
}

fn telemetry_model_schema(schema: &ModelSchemaOptions) -> (Value, Value) {
    (
        telemetry_model_name(&schema.model_name),
        telemetry_field_names(&schema.field_names),
    )
}

fn telemetry_operation_hooks(hooks: &rustauth_core::options::DatabaseOperationHooks) -> Value {
    json!({
        "before": hooks.before.is_some(),
        "after": hooks.after.is_some(),
    })
}

fn telemetry_model_hooks(hooks: &DatabaseModelHooks) -> Value {
    json!({
        "create": telemetry_operation_hooks(&hooks.create),
        "update": telemetry_operation_hooks(&hooks.update),
    })
}

fn telemetry_database_hooks(hooks: &InitDatabaseHooksOptions) -> Value {
    json!({
        "user": telemetry_model_hooks(&hooks.user),
        "session": telemetry_model_hooks(&hooks.session),
        "account": telemetry_model_hooks(&hooks.account),
        "verification": telemetry_model_hooks(&hooks.verification),
    })
}

fn telemetry_log_level(level: LogLevel) -> Value {
    Value::String(
        match level {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Success => "success",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
        .to_owned(),
    )
}

fn telemetry_throw_flag(enabled: bool) -> Value {
    if enabled {
        Value::Bool(true)
    } else {
        Value::Null
    }
}

fn user_additional_fields(
    fields: &std::collections::BTreeMap<String, UserAdditionalField>,
) -> Value {
    if fields.is_empty() {
        return Value::Null;
    }

    Value::Object(
        fields
            .iter()
            .map(|(name, field)| {
                (
                    name.clone(),
                    json!({
                        "type": field.field_type,
                        "required": field.required,
                        "input": field.input,
                        "returned": field.returned,
                        "defaultValue": field.default_value.is_some(),
                        "dbName": field.db_name.is_some(),
                    }),
                )
            })
            .collect::<Map<_, _>>(),
    )
}

fn session_additional_fields(
    fields: &std::collections::BTreeMap<String, SessionAdditionalField>,
) -> Value {
    if fields.is_empty() {
        return Value::Null;
    }

    Value::Object(
        fields
            .iter()
            .map(|(name, field)| {
                (
                    name.clone(),
                    json!({
                        "type": field.field_type,
                        "required": field.required,
                        "input": field.input,
                        "returned": field.returned,
                        "defaultValue": field.default_value.is_some(),
                        "dbName": field.db_name.is_some(),
                    }),
                )
            })
            .collect::<Map<_, _>>(),
    )
}

#[cfg(feature = "oauth")]
fn social_providers(options: &RustAuthOptions) -> Value {
    Value::Array(
        options
            .social_providers
            .iter()
            .map(|provider| {
                let provider_options = provider.provider_options();
                json!({
                    "id": provider.id(),
                    "mapProfileToUser": false,
                    "disableDefaultScope": provider_options.disable_default_scope,
                    "disableIdTokenSignIn": provider_options.disable_id_token_sign_in,
                    "disableImplicitSignUp": provider_options.disable_implicit_sign_up,
                    "disableSignUp": provider_options.disable_sign_up,
                    "getUserInfo": true,
                    "overrideUserInfoOnSignIn": provider_options.override_user_info_on_sign_in,
                    "prompt": provider_options.prompt,
                    "verifyIdToken": false,
                    "scope": if provider_options.scope.is_empty() {
                        Value::Null
                    } else {
                        json!(provider_options.scope)
                    },
                    "refreshAccessToken": false,
                })
            })
            .collect(),
    )
}

#[cfg(not(feature = "oauth"))]
fn social_providers(_options: &RustAuthOptions) -> Value {
    Value::Array(vec![])
}

pub fn get_telemetry_auth_config(options: &RustAuthOptions, context: &TelemetryContext) -> Value {
    let (user_model_name, user_fields) = telemetry_model_schema(&options.user.schema);
    let (session_model_name, session_fields) = telemetry_model_schema(&options.session.schema);
    let (account_model_name, account_fields) = telemetry_model_schema(&options.account.schema);
    let (verification_model_name, verification_fields) =
        telemetry_model_schema(&options.verification.schema);
    let (rate_limit_model_name, _) = telemetry_model_schema(&options.rate_limit.schema);

    let trusted_origins_len = match &options.trusted_origins {
        TrustedOriginOptions::None => Value::Null,
        TrustedOriginOptions::Static(v) => json!(v.len()),
        TrustedOriginOptions::Dynamic { origins, .. } => json!(origins.len()),
    };

    let cookie_strategy = match options.session.cookie_cache.strategy {
        CookieCacheStrategy::Compact => Value::String("compact".to_owned()),
        CookieCacheStrategy::Jwt => Value::String("jwt".to_owned()),
        CookieCacheStrategy::Jwe => Value::String("jwe".to_owned()),
    };

    let rate_storage = match options.rate_limit.storage {
        RateLimitStorageOption::Memory => Value::String("memory".to_owned()),
        RateLimitStorageOption::Database => Value::String("database".to_owned()),
        RateLimitStorageOption::SecondaryStorage => Value::String("secondaryStorage".to_owned()),
    };

    json!({
        "database": context.database,
        "adapter": context.adapter,
        "emailVerification": {
            "sendVerificationEmail": options.email_verification.send_verification_email.is_some(),
            "sendOnSignUp": options.email_verification.send_on_sign_up,
            "sendOnSignIn": options.email_verification.send_on_sign_in,
            "autoSignInAfterVerification": options.email_verification.auto_sign_in_after_verification,
            "expiresIn": options.email_verification.expires_in.map(|duration| duration.whole_seconds()),
            "beforeEmailVerification": options.email_verification.before_email_verification.is_some(),
            "afterEmailVerification": options.email_verification.after_email_verification.is_some(),
        },
        "emailAndPassword": {
            "enabled": options.email_password.enabled,
            "disableSignUp": options.email_password.disable_sign_up,
            "requireEmailVerification": options.email_password.require_email_verification,
            "maxPasswordLength": options.password.max_password_length,
            "minPasswordLength": options.password.min_password_length,
            "sendResetPassword": options.password.send_reset_password.is_some(),
            "resetPasswordTokenExpiresIn": options.password.reset_password_token_expires_in.map(|duration| duration.whole_seconds()),
            "onPasswordReset": options.password.on_password_reset.is_some(),
            "password": {
                "hash": options.password.hash_password.is_some(),
                "verify": options.password.verify_password.is_some(),
            },
            "autoSignIn": options.email_password.auto_sign_in,
            "revokeSessionsOnPasswordReset": options.password.revoke_sessions_on_password_reset,
        },
        "socialProviders": social_providers(options),
        "plugins": if options.plugins.is_empty() {
            Value::Null
        } else {
            json!(options.plugins.iter().map(|p| p.id.clone()).collect::<Vec<_>>())
        },
        "user": {
            "modelName": user_model_name,
            "fields": user_fields,
            "additionalFields": user_additional_fields(&options.user.additional_fields),
            "changeEmail": {
                "enabled": options.user.change_email.enabled,
                "sendChangeEmailConfirmation": options
                    .user
                    .change_email
                    .send_change_email_confirmation
                    .is_some(),
            },
        },
        "verification": {
            "modelName": verification_model_name,
            "disableCleanup": options.verification.disable_cleanup,
            "fields": verification_fields,
        },
        "session": {
            "modelName": session_model_name,
            "additionalFields": session_additional_fields(&options.session.additional_fields),
            "cookieCache": {
                "enabled": options.session.cookie_cache.enabled,
                "maxAge": options.session.cookie_cache.max_age.map(|duration| duration.whole_seconds()),
                "strategy": cookie_strategy,
            },
            "disableSessionRefresh": options.session.disable_session_refresh,
            "expiresIn": options.session.expires_in.map(|duration| duration.whole_seconds()),
            "fields": session_fields,
            "freshAge": options.session.fresh_age.map(|duration| duration.whole_seconds()),
            "preserveSessionInDatabase": options.session.preserve_session_in_database,
            "storeSessionInDatabase": options.session.store_session_in_database,
            "updateAge": options.session.update_age.map(|duration| duration.whole_seconds()),
        },
        "account": {
            "modelName": account_model_name,
            "fields": account_fields,
            "encryptOAuthTokens": options.account.encrypt_oauth_tokens,
            "updateAccountOnSignIn": options.account.update_account_on_sign_in,
            "accountLinking": {
                "enabled": options.account.account_linking.enabled,
                "trustedProviders": options.account.account_linking.trusted_providers,
                "updateUserInfoOnLink": options.account.account_linking.update_user_info_on_link,
                "allowUnlinkingAll": options.account.account_linking.allow_unlinking_all,
            },
        },
        "hooks": {
            "after": options.hooks.after.is_some(),
            "before": options.hooks.before.is_some(),
        },
        "secondaryStorage": options.secondary_storage.is_some(),
        "advanced": {
            "cookiePrefix": options.advanced.cookie_prefix.is_some(),
            "cookies": false,
            "crossSubDomainCookies": {
                "domain": options.advanced.cross_subdomain_cookies.as_ref().and_then(|c| c.domain.as_ref()).is_some(),
                "enabled": options.advanced.cross_subdomain_cookies.as_ref().is_some_and(|c| c.enabled),
                "additionalCookies": Value::Null,
            },
            "database": {
                "generateId": Value::Null,
                "defaultFindManyLimit": Value::Null,
            },
            "useSecureCookies": options.advanced.use_secure_cookies,
            "ipAddress": {
                "disableIpTracking": options.advanced.ip_address.disable_ip_tracking,
                "ipAddressHeaders": options.advanced.ip_address.headers,
            },
            "disableCSRFCheck": options.advanced.disable_csrf_check,
            "cookieAttributes": {
                "expires": options.advanced.default_cookie_attributes.max_age.map(|duration| duration.whole_seconds()),
                "secure": options.advanced.default_cookie_attributes.secure,
                "sameSite": options.advanced.default_cookie_attributes.same_site,
                "domain": options.advanced.default_cookie_attributes.domain.is_some(),
                "path": options.advanced.default_cookie_attributes.path,
                "httpOnly": options.advanced.default_cookie_attributes.http_only,
            },
        },
        "trustedOrigins": trusted_origins_len,
        "rateLimit": {
            "storage": rate_storage,
            "modelName": rate_limit_model_name,
            "window": options.rate_limit.window.whole_seconds(),
            "customStorage": options.rate_limit.custom_storage.is_some(),
            "enabled": options.rate_limit.enabled,
            "max": options.rate_limit.max,
        },
        "onAPIError": {
            "errorURL": if options.on_api_error.error_url.is_some() {
                Value::Bool(true)
            } else {
                Value::Null
            },
            "onError": options.on_api_error.on_error.is_some(),
            "throw": telemetry_throw_flag(options.on_api_error.throw),
        },
        "logger": {
            "disabled": options.logger.is_disabled(),
            "level": telemetry_log_level(options.logger.level()),
            "log": options.logger.has_custom_handler(),
        },
        "databaseHooks": telemetry_database_hooks(&options.init_database_hooks),
    })
}
