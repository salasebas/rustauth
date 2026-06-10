use openauth_core::db::DbSchema;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::AuthPlugin;
use openauth_plugins::{
    admin::admin,
    anonymous::anonymous,
    api_key::api_key,
    device_authorization::device_authorization,
    jwt::jwt,
    organization::organization,
    phone_number::{phone_number_with, PhoneNumberOptions},
    siwe::{siwe_with, SiweOptions},
    two_factor::two_factor,
    username::username,
    PLUGIN_IDS,
};
use serde::Serialize;
#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    pub id: &'static str,
    pub official: bool,
    pub schema_supported: bool,
    pub snippet_supported: bool,
    pub migration_impact: bool,
}

pub fn official_plugins() -> Vec<PluginInfo> {
    PLUGIN_IDS
        .iter()
        .map(|id| PluginInfo {
            id,
            official: true,
            schema_supported: schema_plugin(id).is_some(),
            snippet_supported: rust_snippet(id).is_some(),
            migration_impact: schema_plugin(id).is_some(),
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
        "admin" => Some(admin()),
        "anonymous" => Some(anonymous()),
        "api-key" => Some(api_key()),
        "device-authorization" => Some(device_authorization()),
        "jwt" => jwt().ok(),
        "organization" => Some(organization()),
        "phone-number" => Some(phone_number_with(PhoneNumberOptions::default())),
        "siwe" => siwe_with(SiweOptions::new(
            "localhost",
            || async { Ok("nonce".to_owned()) },
            |_| async { Ok(true) },
        ))
        .ok(),
        "two-factor" => Some(two_factor()),
        "username" => Some(username()),
        _ => None,
    }
}

pub fn rust_snippet(plugin: &str) -> Option<&'static str> {
    match plugin {
        "two-factor" => Some("openauth::plugins::two_factor::two_factor()"),
        "organization" => Some("openauth::plugins::organization::organization()"),
        "username" => Some("openauth::plugins::username::username()"),
        "admin" => Some("openauth::plugins::admin::admin()"),
        "api-key" => Some("openauth::plugins::api_key::api_key()"),
        "device-authorization" => {
            Some("openauth::plugins::device_authorization::device_authorization()")
        }
        "anonymous" => Some("openauth::plugins::anonymous::anonymous()"),
        "jwt" => Some("openauth::plugins::jwt::jwt()?"),
        _ => None,
    }
}
