use openauth_core::db::DbSchema;
use openauth_core::db::MemoryAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::AuthPlugin;
use openauth_plugins::{
    admin::{admin, AdminOptions},
    anonymous::{anonymous, AnonymousOptions},
    api_key::api_key,
    device_authorization::device_authorization,
    jwt::jwt,
    mcp::{mcp, McpOptions},
    organization::organization,
    phone_number::{phone_number, PhoneNumberOptions},
    siwe::{siwe, SiweOptions},
    two_factor::{two_factor, TwoFactorOptions},
    username::username,
    PLUGIN_IDS,
};
use serde::Serialize;
use std::sync::Arc;

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
        "admin" => Some(admin(AdminOptions::default())),
        "anonymous" => Some(anonymous(AnonymousOptions::default())),
        "api-key" => Some(api_key()),
        "device-authorization" => Some(device_authorization()),
        "jwt" => jwt().ok(),
        "mcp" => mcp(McpOptions {
            login_page: "/login".to_owned(),
            ..McpOptions::default()
        })
        .ok()
        .map(|plugin| plugin.into_auth_plugin()),
        "organization" => Some(organization()),
        "phone-number" => Some(phone_number(
            Arc::new(MemoryAdapter::new()),
            PhoneNumberOptions::default(),
        )),
        "siwe" => siwe(SiweOptions::new(
            "localhost",
            || async { Ok("nonce".to_owned()) },
            |_| async { Ok(true) },
        ))
        .ok(),
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
