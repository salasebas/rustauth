use openauth_core::db::DbSchema;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::AuthPlugin;
use openauth_plugins::{
    admin::{admin, AdminOptions},
    anonymous::{anonymous, AnonymousOptions},
    device_authorization::device_authorization,
    jwt::jwt,
    organization::organization,
    two_factor::{two_factor, TwoFactorOptions},
    username::username,
    PLUGIN_IDS,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    pub id: &'static str,
    pub schema: bool,
    pub scaffold_supported: bool,
}

pub fn official_plugins() -> Vec<PluginInfo> {
    PLUGIN_IDS
        .iter()
        .map(|id| PluginInfo {
            id,
            schema: schema_plugin(id).is_some(),
            scaffold_supported: schema_plugin(id).is_some(),
        })
        .collect()
}

pub fn is_official_plugin(plugin: &str) -> bool {
    PLUGIN_IDS.contains(&plugin)
}

pub fn apply_configured_plugins(
    schema: &mut DbSchema,
    plugins: &[String],
) -> Result<(), OpenAuthError> {
    for plugin in plugins {
        let Some(auth_plugin) = schema_plugin(plugin) else {
            continue;
        };
        for contribution in auth_plugin.schema {
            contribution.apply(schema)?;
        }
    }
    Ok(())
}

pub fn schema_plugin(plugin: &str) -> Option<AuthPlugin> {
    match plugin {
        "admin" => Some(admin(AdminOptions::default())),
        "anonymous" => Some(anonymous(AnonymousOptions::default())),
        "device-authorization" => Some(device_authorization()),
        "jwt" => jwt().ok(),
        "organization" => Some(organization()),
        "two-factor" => Some(two_factor(TwoFactorOptions::default())),
        "username" => Some(username()),
        _ => None,
    }
}

pub fn rust_snippet(plugin: &str) -> Option<&'static str> {
    match plugin {
        "two-factor" => {
            Some("openauth::plugins::two_factor::two_factor(TwoFactorOptions::default())")
        }
        "organization" => Some("openauth::plugins::organization::organization()"),
        "username" => Some("openauth::plugins::username::username()"),
        "admin" => Some("openauth::plugins::admin::admin(AdminOptions::default())"),
        "api-key" => Some("openauth::plugins::api_key::api_key()"),
        "device-authorization" => {
            Some("openauth::plugins::device_authorization::device_authorization()")
        }
        "anonymous" => Some("openauth::plugins::anonymous::anonymous(AnonymousOptions::default())"),
        "jwt" => Some("openauth::plugins::jwt::jwt()?"),
        _ => None,
    }
}
