//! Maps [`openauth_core::options::OpenAuthOptions`] into the anonymized JSON snapshot
//! expected by Better Auth telemetry (`getTelemetryAuthConfig`).
//!
//! Many Better Auth fields are not modeled in OpenAuth core yet; those branches emit the same
//! defaults as upstream integration tests until the Rust option surface grows.

use openauth_core::options::{
    CookieCacheStrategy, OpenAuthOptions, RateLimitStorageOption, TrustedOriginOptions,
};
use serde_json::{json, Value};

use crate::types::TelemetryContext;

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
            "sendOnSignUp": false,
            "sendOnSignIn": false,
            "autoSignInAfterVerification": options.email_verification.auto_sign_in_after_verification,
            "expiresIn": options.email_verification.expires_in,
            "onEmailVerification": false,
            "afterEmailVerification": false,
        },
        "emailAndPassword": {
            "enabled": false,
            "disableSignUp": false,
            "requireEmailVerification": false,
            "maxPasswordLength": options.password.max_password_length,
            "minPasswordLength": options.password.min_password_length,
            "sendResetPassword": false,
            "resetPasswordTokenExpiresIn": Value::Null,
            "onPasswordReset": false,
            "password": { "hash": false, "verify": false },
            "autoSignIn": false,
            "revokeSessionsOnPasswordReset": false,
        },
        "socialProviders": Value::Array(vec![]),
        "plugins": if options.plugins.is_empty() {
            Value::Null
        } else {
            json!(options.plugins.iter().map(|p| p.id.clone()).collect::<Vec<_>>())
        },
        "user": {
            "modelName": Value::Null,
            "fields": Value::Null,
            "additionalFields": Value::Null,
            "changeEmail": {
                "enabled": options.user.change_email.enabled,
                "sendChangeEmailVerification": false,
            },
        },
        "verification": {
            "modelName": Value::Null,
            "disableCleanup": Value::Null,
            "fields": Value::Null,
        },
        "session": {
            "modelName": Value::Null,
            "additionalFields": Value::Null,
            "cookieCache": {
                "enabled": options.session.cookie_cache.enabled,
                "maxAge": options.session.cookie_cache.max_age,
                "strategy": cookie_strategy,
            },
            "disableSessionRefresh": Value::Null,
            "expiresIn": options.session.expires_in,
            "fields": Value::Null,
            "freshAge": options.session.fresh_age,
            "preserveSessionInDatabase": Value::Null,
            "storeSessionInDatabase": Value::Null,
            "updateAge": options.session.update_age,
        },
        "account": {
            "modelName": Value::Null,
            "fields": Value::Null,
            "encryptOAuthTokens": Value::Null,
            "updateAccountOnSignIn": Value::Null,
            "accountLinking": {
                "enabled": Value::Null,
                "trustedProviders": Value::Null,
                "updateUserInfoOnLink": Value::Null,
                "allowUnlinkingAll": Value::Null,
            },
        },
        "hooks": { "after": false, "before": false },
        "secondaryStorage": false,
        "advanced": {
            "cookiePrefix": options.advanced.cookie_prefix.is_some(),
            "cookies": false,
            "crossSubDomainCookies": {
                "domain": options.advanced.cross_subdomain_cookies.as_ref().and_then(|c| c.domain.as_ref()).is_some(),
                "enabled": options.advanced.cross_subdomain_cookies.as_ref().is_some_and(|c| c.enabled),
                "additionalCookies": Value::Null,
            },
            "database": {
                "useNumberId": false,
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
