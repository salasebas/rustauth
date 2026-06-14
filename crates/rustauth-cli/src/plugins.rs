use rustauth_core::error::RustAuthError;
use rustauth_core::plugin::{AuthPlugin, PluginMigration};
#[cfg(feature = "oauth-provider")]
use rustauth_oauth_provider::{oauth_provider, OAuthProviderOptions};
#[cfg(feature = "passkey")]
use rustauth_passkey::{passkey, PasskeyOptions};
#[cfg(feature = "plugins")]
use rustauth_plugins::official_schema_plugin;
#[cfg(feature = "scim")]
use rustauth_scim::{scim, ScimOptions};
#[cfg(feature = "sso")]
use rustauth_sso::{sso, SsoOptions};
#[cfg(feature = "stripe")]
use rustauth_stripe::{stripe, OrganizationStripeOptions, StripeOptions, SubscriptionOptions};
use serde::Serialize;

const CLI_SCHEMA_EXTENSION_PLUGIN_IDS: &[&str] =
    &["oauth-provider", "passkey", "scim", "sso", "stripe"];

/// Keep in sync with `rustauth_plugins::PLUGIN_IDS` in `rustauth-plugins/src/lib.rs`.
#[cfg(not(feature = "plugins"))]
const STATIC_OFFICIAL_PLUGIN_IDS: &[&str] = &[
    "access",
    "additional-fields",
    "admin",
    "anonymous",
    "api-key",
    "bearer",
    "captcha",
    "custom-session",
    "device-authorization",
    "email-otp",
    "generic-oauth",
    "have-i-been-pwned",
    "jwt",
    "last-login-method",
    "magic-link",
    "multi-session",
    "oauth-proxy",
    "one-tap",
    "one-time-token",
    "open-api",
    "organization",
    "phone-number",
    "siwe",
    "two-factor",
    "username",
];

/// Plugin ids that [`official_schema_plugin`] materializes when the `plugins` feature is on.
const STATIC_OFFICIAL_SCHEMA_PLUGIN_IDS: &[&str] = &[
    "admin",
    "anonymous",
    "api-key",
    "device-authorization",
    "jwt",
    "last-login-method",
    "organization",
    "phone-number",
    "siwe",
    "two-factor",
    "username",
];

#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    pub id: &'static str,
    pub official: bool,
    pub schema_supported: bool,
    pub snippet_supported: bool,
    pub migration_impact: bool,
}

pub fn official_plugins() -> Vec<PluginInfo> {
    official_plugin_ids()
        .iter()
        .map(|id| plugin_info(id))
        .chain(
            CLI_SCHEMA_EXTENSION_PLUGIN_IDS
                .iter()
                .map(|id| plugin_info(id)),
        )
        .collect()
}

fn official_plugin_ids() -> &'static [&'static str] {
    #[cfg(feature = "plugins")]
    {
        rustauth_plugins::PLUGIN_IDS
    }
    #[cfg(not(feature = "plugins"))]
    {
        STATIC_OFFICIAL_PLUGIN_IDS
    }
}

fn plugin_info(id: &'static str) -> PluginInfo {
    let schema_supported = supports_schema_planning(id);
    PluginInfo {
        id,
        official: true,
        schema_supported,
        snippet_supported: rust_snippet(id).is_some(),
        migration_impact: schema_supported,
    }
}

pub fn is_official_plugin(plugin: &str) -> bool {
    official_plugin_ids().contains(&plugin) || CLI_SCHEMA_EXTENSION_PLUGIN_IDS.contains(&plugin)
}

pub fn schema_plugin(plugin: &str) -> Option<AuthPlugin> {
    cli_schema_plugin(plugin).and_then(|result| result.ok())
}

/// Returns true when `rustauth db` can derive schema for this plugin id.
pub fn supports_schema_planning(plugin: &str) -> bool {
    matches!(cli_schema_plugin(plugin), Some(Ok(_)))
}

/// Plugin ids that intentionally have no fixed CLI schema (or are app-configured).
pub(crate) fn is_schema_planning_exception(plugin: &str) -> bool {
    #[cfg(feature = "plugins")]
    {
        use rustauth_plugins::{APP_CONFIGURED_SCHEMA_PLUGIN_IDS, NO_FIXED_SCHEMA_PLUGIN_IDS};
        NO_FIXED_SCHEMA_PLUGIN_IDS.contains(&plugin)
            || APP_CONFIGURED_SCHEMA_PLUGIN_IDS.contains(&plugin)
    }
    #[cfg(not(feature = "plugins"))]
    {
        const NO_FIXED_SCHEMA_PLUGIN_IDS: &[&str] = &[
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
        const APP_CONFIGURED_SCHEMA_PLUGIN_IDS: &[&str] = &["additional-fields"];
        NO_FIXED_SCHEMA_PLUGIN_IDS.contains(&plugin)
            || APP_CONFIGURED_SCHEMA_PLUGIN_IDS.contains(&plugin)
    }
}

fn cli_schema_plugin(plugin: &str) -> Option<Result<AuthPlugin, RustAuthError>> {
    if let Err(error) = ensure_plugin_feature_enabled(plugin) {
        return Some(Err(error));
    }

    #[cfg(feature = "plugins")]
    if let Some(plugin) = official_schema_plugin(plugin) {
        return Some(plugin);
    }

    match plugin {
        #[cfg(feature = "oauth-provider")]
        "oauth-provider" => Some(
            oauth_provider(OAuthProviderOptions {
                login_page: "/login".to_owned(),
                consent_page: "/consent".to_owned(),
                disable_jwt_plugin: true,
                ..OAuthProviderOptions::default()
            })
            .map_err(|error| RustAuthError::InvalidConfig(error.to_string())),
        ),
        #[cfg(feature = "passkey")]
        "passkey" => Some(Ok(passkey(PasskeyOptions::default()))),
        #[cfg(feature = "scim")]
        "scim" => Some(Ok(scim(ScimOptions::default()))),
        #[cfg(feature = "sso")]
        "sso" => Some(Ok(sso(SsoOptions::default()))),
        #[cfg(feature = "stripe")]
        "stripe" => Some(
            stripe(
                StripeOptions::dev()
                    .subscription(SubscriptionOptions::enabled(Vec::new()))
                    .organization(OrganizationStripeOptions::enabled()),
            )
            .map_err(|error| RustAuthError::InvalidConfig(error.to_string())),
        ),
        _ => None,
    }
}

fn ensure_plugin_feature_enabled(plugin: &str) -> Result<(), RustAuthError> {
    let Some(feature) = required_cargo_feature(plugin) else {
        return Ok(());
    };
    if is_cargo_feature_enabled(feature) {
        Ok(())
    } else {
        Err(RustAuthError::FeatureDisabled { feature })
    }
}

pub(crate) fn required_cargo_feature(plugin: &str) -> Option<&'static str> {
    if STATIC_OFFICIAL_SCHEMA_PLUGIN_IDS.contains(&plugin) {
        return Some("plugins");
    }
    match plugin {
        "oauth-provider" => Some("oauth-provider"),
        "passkey" => Some("passkey"),
        "scim" => Some("scim"),
        "sso" => Some("sso"),
        "stripe" => Some("stripe"),
        _ => None,
    }
}

#[allow(clippy::match_like_matches_macro)]
pub(crate) fn is_cargo_feature_enabled(feature: &str) -> bool {
    match feature {
        "plugins" => cfg!(feature = "plugins"),
        "oauth-provider" => cfg!(feature = "oauth-provider"),
        "passkey" => cfg!(feature = "passkey"),
        "scim" => cfg!(feature = "scim"),
        "sso" => cfg!(feature = "sso"),
        "stripe" => cfg!(feature = "stripe"),
        _ => false,
    }
}

pub fn schema_context_for_config(
    plugin_ids: &[String],
) -> Result<rustauth_core::context::AuthContext, RustAuthError> {
    use std::sync::Arc;

    use rustauth_core::context::create_auth_context_with_adapter;
    use rustauth_core::db::MemoryAdapter;
    use rustauth_core::options::RustAuthOptions;

    let mut plugins = Vec::new();
    for plugin_id in plugin_ids {
        let Some(plugin) = cli_schema_plugin(plugin_id) else {
            continue;
        };
        plugins.push(plugin?);
    }
    create_auth_context_with_adapter(
        RustAuthOptions::new()
            .development(true)
            .secret("rustauth-cli-schema-planning-secret-32ch")
            .plugins(plugins),
        Arc::new(MemoryAdapter::new()),
    )
}

pub fn plugin_migrations_for_config(
    plugin_ids: &[String],
) -> Result<Vec<PluginMigration>, RustAuthError> {
    Ok(schema_context_for_config(plugin_ids)?.plugin_migrations)
}

pub fn rust_snippet(plugin: &str) -> Option<&'static str> {
    match plugin {
        "two-factor" => Some("rustauth::plugins::two_factor::two_factor(TwoFactorOptions::default())"),
        "organization" => Some("rustauth::plugins::organization::organization(OrganizationOptions::default())"),
        "username" => Some("rustauth::plugins::username::username(UsernameOptions::default())"),
        "admin" => Some("rustauth::plugins::admin::admin(AdminOptions::default())?"),
        "api-key" => Some("rustauth::plugins::api_key::api_key(ApiKeyOptions::default())?"),
        "device-authorization" => {
            Some("rustauth::plugins::device_authorization::device_authorization(DeviceAuthorizationOptions::default())?")
        }
        "anonymous" => Some("rustauth::plugins::anonymous::anonymous(AnonymousOptions::default())"),
        "jwt" => Some("rustauth::plugins::jwt::jwt(JwtOptions::default())?"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_plugins_lists_static_ids_without_plugins_feature() {
        let plugins = official_plugins();
        assert!(plugins.iter().any(|plugin| plugin.id == "admin"));
        assert!(plugins.iter().any(|plugin| plugin.id == "passkey"));
        assert!(plugins.iter().any(|plugin| plugin.id == "username"));
    }

    #[cfg(feature = "plugins")]
    #[test]
    fn official_schema_registry_covers_extension_plugins() {
        for id in CLI_SCHEMA_EXTENSION_PLUGIN_IDS {
            assert!(
                cli_schema_plugin(id).is_some(),
                "missing schema plugin for {id}"
            );
        }
    }

    #[cfg(feature = "plugins")]
    #[test]
    fn official_schema_plugin_ids_match_registry() {
        use rustauth_plugins::{is_official_schema_plugin, official_schema_plugin_ids};

        for id in official_schema_plugin_ids() {
            assert!(is_official_schema_plugin(id));
        }
    }

    #[cfg(not(feature = "passkey"))]
    #[test]
    fn passkey_schema_requires_passkey_feature() {
        assert!(matches!(
            cli_schema_plugin("passkey"),
            Some(Err(RustAuthError::FeatureDisabled { feature: "passkey" }))
        ));
        assert!(!supports_schema_planning("passkey"));
    }
}
