//! Default official plugin instances for CLI schema and migration planning.
//!
//! These builders use development-friendly defaults so `rustauth db` can derive the
//! same database shape as a typical integration without custom app wiring.

use rustauth_core::error::RustAuthError;
use rustauth_core::plugin::AuthPlugin;

use crate::{
    admin::{admin, AdminOptions},
    anonymous::{anonymous, AnonymousOptions},
    api_key::{api_key, ApiKeyOptions},
    device_authorization::{device_authorization, DeviceAuthorizationOptions},
    jwt::{jwt, JwtOptions},
    last_login_method::{last_login_method, LastLoginMethodOptions},
    organization::{organization, DynamicAccessControlOptions, OrganizationOptions, TeamOptions},
    phone_number::{phone_number, PhoneNumberOptions},
    siwe::siwe_dev,
    two_factor::{two_factor, TwoFactorOptions},
    username::{username, UsernameOptions},
    PLUGIN_IDS,
};

/// Plugin ids that may be enabled in an app but never contribute fixed database DDL.
///
/// CLI schema planning skips these intentionally — they rely on core tables, in-memory
/// state, or app-specific wiring only.
pub const NO_FIXED_SCHEMA_PLUGIN_IDS: &[&str] = &[
    "bearer",
    "captcha",
    "custom-session",
    "email-otp",
    "generic-oauth",
    "have-i-been-pwned",
    "magic-link",
    "multi-session",
    "oauth-proxy",
    "one-tap",
    "one-time-token",
    "open-api",
];

/// Plugin ids whose database shape depends on per-app field configuration.
///
/// [`official_schema_plugin`] cannot infer columns from the id alone; integrators must
/// align migrations with their `additional_fields(...)` options.
pub const APP_CONFIGURED_SCHEMA_PLUGIN_IDS: &[&str] = &["additional-fields"];

fn schema_planning_organization_options() -> OrganizationOptions {
    OrganizationOptions::builder()
        .teams(TeamOptions {
            enabled: true,
            ..TeamOptions::default()
        })
        .dynamic_access_control(DynamicAccessControlOptions {
            enabled: true,
            ..DynamicAccessControlOptions::default()
        })
        .build()
}

/// Returns true when `plugin_id` is recognized by [`official_schema_plugin`].
pub fn is_official_schema_plugin(plugin_id: &str) -> bool {
    official_schema_plugin(plugin_id).is_some()
}

/// Build a schema-planning plugin instance with official defaults, when the plugin contributes database schema.
pub fn official_schema_plugin(plugin_id: &str) -> Option<Result<AuthPlugin, RustAuthError>> {
    match plugin_id {
        "admin" => Some(admin(AdminOptions::default())),
        "anonymous" => Some(Ok(anonymous(AnonymousOptions::default()))),
        "api-key" => Some(api_key(ApiKeyOptions::default())),
        "device-authorization" => Some(device_authorization(DeviceAuthorizationOptions::default())),
        "jwt" => Some(jwt(JwtOptions::default())),
        "last-login-method" => Some(Ok(last_login_method(
            LastLoginMethodOptions::default().store_in_database(true),
        ))),
        "organization" => Some(Ok(organization(schema_planning_organization_options()))),
        "phone-number" => Some(phone_number(PhoneNumberOptions::new(|_phone, _otp| Ok(())))),
        "siwe" => Some(siwe_dev()),
        "two-factor" => Some(Ok(two_factor(TwoFactorOptions::default()))),
        "username" => Some(Ok(username(UsernameOptions::default()))),
        _ => None,
    }
}

/// Instantiate official schema plugins for the ids configured in `rustauth.toml`.
pub fn configured_official_schema_plugins(
    plugin_ids: &[String],
) -> Result<Vec<AuthPlugin>, RustAuthError> {
    let mut plugins = Vec::new();
    for plugin_id in plugin_ids {
        let Some(plugin) = official_schema_plugin(plugin_id) else {
            continue;
        };
        plugins.push(plugin?);
    }
    Ok(plugins)
}

/// All plugin ids that [`official_schema_plugin`] can materialize for schema planning.
pub fn official_schema_plugin_ids() -> Vec<&'static str> {
    PLUGIN_IDS
        .iter()
        .copied()
        .filter(|id| official_schema_plugin(id).is_some())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use rustauth_core::context::create_auth_context_with_adapter;
    use rustauth_core::db::MemoryAdapter;
    use rustauth_core::options::RustAuthOptions;
    use std::sync::Arc;

    use super::*;

    fn is_catalog_plugin_id(plugin_id: &str) -> bool {
        PLUGIN_IDS.contains(&plugin_id) || plugin_id == "have-i-been-pwned"
    }

    #[test]
    fn schema_exemption_lists_are_official_plugin_ids() {
        for id in NO_FIXED_SCHEMA_PLUGIN_IDS {
            assert!(
                is_catalog_plugin_id(id),
                "{id} is not an official plugin id"
            );
            assert!(
                official_schema_plugin(id).is_none(),
                "{id} should not have a fixed schema factory"
            );
        }
        for id in APP_CONFIGURED_SCHEMA_PLUGIN_IDS {
            assert!(
                is_catalog_plugin_id(id),
                "{id} is not an official plugin id"
            );
            assert!(
                official_schema_plugin(id).is_none(),
                "{id} schema depends on app configuration"
            );
        }
    }

    #[test]
    fn organization_schema_planning_includes_optional_tables() {
        let plugin = official_schema_plugin("organization")
            .expect("organization contributes schema")
            .expect("organization defaults");
        let context = create_auth_context_with_adapter(
            RustAuthOptions::new().plugins(vec![plugin]),
            Arc::new(MemoryAdapter::new()),
        )
        .expect("auth context");
        assert!(context.db_schema.table("team").is_some());
        assert!(context.db_schema.table("team_member").is_some());
        assert!(context.db_schema.table("organization_role").is_some());
    }
}
