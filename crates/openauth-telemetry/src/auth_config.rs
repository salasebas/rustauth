//! Maps [`openauth_core::options::OpenAuthOptions`] into the anonymized JSON snapshot
//! expected by Better Auth telemetry (`getTelemetryAuthConfig`).
//!
//! Many Better Auth fields are not modeled in OpenAuth core yet; those branches emit the same
//! defaults as upstream integration tests until the Rust option surface grows.

use openauth_core::options::{
    CookieCacheStrategy, OpenAuthOptions, RateLimitStorageOption, SessionAdditionalField,
    TrustedOriginOptions, UserAdditionalField,
};
use serde_json::{json, Map, Value};

use crate::types::TelemetryContext;

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
fn social_providers(options: &OpenAuthOptions) -> Value {
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
fn social_providers(_options: &OpenAuthOptions) -> Value {
    Value::Array(vec![])
}

pub fn get_telemetry_auth_config(options: &OpenAuthOptions, context: &TelemetryContext) -> Value {
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
            "expiresIn": options.email_verification.expires_in,
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
            "resetPasswordTokenExpiresIn": options.password.reset_password_token_expires_in,
            "onPasswordReset": options.password.on_password_reset.is_some(),
            "password": { "hash": false, "verify": false },
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
            "modelName": Value::Null,
            "fields": Value::Null,
            "additionalFields": user_additional_fields(&options.user.additional_fields),
            "changeEmail": {
                "enabled": options.user.change_email.enabled,
                "sendChangeEmailConfirmation": false,
            },
        },
        "verification": {
            "modelName": Value::Null,
            "disableCleanup": Value::Null,
            "fields": Value::Null,
        },
        "session": {
            "modelName": Value::Null,
            "additionalFields": session_additional_fields(&options.session.additional_fields),
            "cookieCache": {
                "enabled": options.session.cookie_cache.enabled,
                "maxAge": options.session.cookie_cache.max_age,
                "strategy": cookie_strategy,
            },
            "disableSessionRefresh": options.session.disable_session_refresh,
            "expiresIn": options.session.expires_in,
            "fields": Value::Null,
            "freshAge": options.session.fresh_age,
            "preserveSessionInDatabase": options.session.preserve_session_in_database,
            "storeSessionInDatabase": options.session.store_session_in_database,
            "updateAge": options.session.update_age,
        },
        "account": {
            "modelName": Value::Null,
            "fields": Value::Null,
            "encryptOAuthTokens": options.account.encrypt_oauth_tokens,
            "updateAccountOnSignIn": options.account.update_account_on_sign_in,
            "accountLinking": {
                "enabled": options.account.account_linking.enabled,
                "trustedProviders": options.account.account_linking.trusted_providers,
                "updateUserInfoOnLink": options.account.account_linking.update_user_info_on_link,
                "allowUnlinkingAll": options.account.account_linking.allow_unlinking_all,
            },
        },
        "hooks": { "after": false, "before": false },
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
                "expires": options.advanced.default_cookie_attributes.max_age,
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
            "modelName": Value::Null,
            "window": options.rate_limit.window,
            "customStorage": options.rate_limit.custom_storage.is_some(),
            "enabled": options.rate_limit.enabled,
            "max": options.rate_limit.max,
        },
        "onAPIError": {
            "errorURL": Value::Null,
            "onError": false,
            "throw": Value::Null,
        },
        "logger": {
            "disabled": Value::Null,
            "level": Value::Null,
            "log": false,
        },
        "databaseHooks": {
            "user": {
                "create": { "after": false, "before": false },
                "update": { "after": false, "before": false },
            },
            "session": {
                "create": { "after": false, "before": false },
                "update": { "after": false, "before": false },
            },
            "account": {
                "create": { "after": false, "before": false },
                "update": { "after": false, "before": false },
            },
            "verification": {
                "create": { "after": false, "before": false },
                "update": { "after": false, "before": false },
            },
        },
    })
}
