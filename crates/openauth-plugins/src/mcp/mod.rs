//! Model Context Protocol OAuth plugin.

mod authorize;
mod claims;
pub mod client;
mod consent;
mod metadata;
mod register;
mod schema;
mod session;
mod shared;
mod token;
mod userinfo;

use openauth_core::plugin::AuthPlugin;
use openauth_core::plugin::{PluginAfterHookAction, PluginAfterHookFuture};
use openauth_core::{db::User, error::OpenAuthError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::Arc;
use thiserror::Error;

pub const UPSTREAM_PLUGIN_ID: &str = "mcp";

const DEFAULT_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

pub type McpClientIdGenerator = Arc<dyn Fn() -> String + Send + Sync>;
pub type McpClientSecretGenerator = Arc<dyn Fn() -> String + Send + Sync>;
pub type McpAdditionalIdTokenClaims =
    Arc<dyn Fn(&User, &[String]) -> Result<Map<String, Value>, OpenAuthError> + Send + Sync>;

/// Token endpoint authentication methods accepted by dynamic registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }
}

/// Optional OIDC-style settings used by the MCP plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpOidcConfig {
    pub scopes: Vec<String>,
    pub default_scope: String,
    pub code_expires_in: u64,
    pub access_token_expires_in: u64,
    pub refresh_token_expires_in: u64,
    pub allow_plain_code_challenge_method: bool,
    pub require_pkce: bool,
}

impl Default for McpOidcConfig {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            default_scope: "openid".to_owned(),
            code_expires_in: 600,
            access_token_expires_in: 3600,
            refresh_token_expires_in: 604800,
            allow_plain_code_challenge_method: true,
            require_pkce: false,
        }
    }
}

/// Metadata extension points for OAuth discovery responses.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct McpMetadataOverrides {
    pub authorization_server: Map<String, Value>,
    pub protected_resource: Map<String, Value>,
}

/// User-facing MCP plugin options.
#[derive(Clone, Default)]
pub struct McpOptions {
    pub login_page: String,
    pub consent_page: Option<String>,
    pub resource: Option<String>,
    pub oidc_config: McpOidcConfig,
    pub metadata: McpMetadataOverrides,
    pub client_id_generator: Option<McpClientIdGenerator>,
    pub client_secret_generator: Option<McpClientSecretGenerator>,
    pub additional_id_token_claims: Option<McpAdditionalIdTokenClaims>,
}

/// Resolved MCP options after upstream-compatible defaults are applied.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedMcpOptions {
    pub login_page: String,
    pub consent_page: Option<String>,
    pub resource: Option<String>,
    pub scopes: Vec<String>,
    pub default_scope: Vec<String>,
    pub code_expires_in: u64,
    pub access_token_expires_in: u64,
    pub refresh_token_expires_in: u64,
    pub allow_plain_code_challenge_method: bool,
    pub require_pkce: bool,
    pub metadata: McpMetadataOverrides,
}

/// Typed MCP plugin returned by [`mcp`].
#[derive(Debug, Clone)]
pub struct McpPlugin {
    pub id: String,
    pub version: String,
    pub options: ResolvedMcpOptions,
    auth_plugin: AuthPlugin,
}

impl McpPlugin {
    pub fn into_auth_plugin(self) -> AuthPlugin {
        self.auth_plugin
    }

    pub fn as_auth_plugin(&self) -> &AuthPlugin {
        &self.auth_plugin
    }
}

/// MCP configuration errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum McpConfigError {
    #[error("login_page is required")]
    MissingLoginPage,
}

/// Build the MCP OAuth plugin.
pub fn mcp(options: McpOptions) -> Result<McpPlugin, McpConfigError> {
    if options.login_page.is_empty() {
        return Err(McpConfigError::MissingLoginPage);
    }
    let client_id_generator = options.client_id_generator.clone();
    let client_secret_generator = options.client_secret_generator.clone();
    let additional_id_token_claims = options.additional_id_token_claims.clone();

    let mut scopes = DEFAULT_SCOPES
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for scope in options.oidc_config.scopes {
        if !scope.is_empty() && !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }

    let mut default_scope = options
        .oidc_config
        .default_scope
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if default_scope.is_empty() {
        default_scope.push("openid".to_owned());
    }

    let resolved = ResolvedMcpOptions {
        login_page: options.login_page,
        consent_page: options.consent_page,
        resource: options.resource,
        scopes,
        default_scope,
        code_expires_in: options.oidc_config.code_expires_in,
        access_token_expires_in: options.oidc_config.access_token_expires_in,
        refresh_token_expires_in: options.oidc_config.refresh_token_expires_in,
        allow_plain_code_challenge_method: options.oidc_config.allow_plain_code_challenge_method,
        require_pkce: options.oidc_config.require_pkce,
        metadata: options.metadata,
    };

    let auth_plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_options(serde_json::to_value(&resolved).unwrap_or(serde_json::Value::Null))
        .with_schema(schema::oauth_application_schema())
        .with_schema(schema::oauth_access_token_schema())
        .with_schema(schema::oauth_consent_schema())
        .with_endpoint(metadata::authorization_server_endpoint(resolved.clone()))
        .with_endpoint(metadata::protected_resource_endpoint(resolved.clone()))
        .with_endpoint(register::register_endpoint(
            resolved.clone(),
            client_id_generator,
            client_secret_generator,
        ))
        .with_endpoint(authorize::authorize_endpoint(resolved.clone()))
        .with_endpoint(consent::consent_endpoint(resolved.clone()))
        .with_endpoint(token::token_endpoint(
            resolved.clone(),
            additional_id_token_claims.clone(),
        ))
        .with_endpoint(userinfo::userinfo_endpoint(additional_id_token_claims))
        .with_endpoint(userinfo::jwks_endpoint())
        .with_endpoint(session::get_session_endpoint())
        .with_async_after_hook("*", {
            let resolved = resolved.clone();
            move |context, request, response| -> PluginAfterHookFuture<'_> {
                let resolved = resolved.clone();
                Box::pin(async move {
                    let response =
                        authorize::resume_after_login(context, request, response, &resolved)
                            .await?;
                    Ok(PluginAfterHookAction::Continue(response))
                })
            }
        });

    Ok(McpPlugin {
        id: UPSTREAM_PLUGIN_ID.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        options: resolved,
        auth_plugin,
    })
}
