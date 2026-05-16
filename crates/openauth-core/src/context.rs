//! Request and runtime context contracts.

pub mod request_state;

mod builder;
mod origins;
mod plugins;
mod secrets;

use crate::auth::trusted_origins::{matches_origin_pattern, OriginMatchSettings};
use crate::cookies::AuthCookies;
use crate::db::{DbAdapter, DbSchema};
use crate::env::logger::Logger;
use crate::error::OpenAuthError;
use crate::options::{
    DynamicRateLimitPathRule, HybridRateLimitOptions, OpenAuthOptions, RateLimitPathRule,
    RateLimitStorageOption, RateLimitStore,
};
use crate::plugin::{AuthPlugin, PluginErrorCode};
use crate::rate_limit::TokioMemoryRateLimitStore;
use http::Request;
use openauth_oauth::oauth2::SocialOAuthProvider;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

pub use builder::{
    create_auth_context, create_auth_context_with_adapter, create_auth_context_with_environment,
    create_auth_context_with_environment_and_adapter,
};
pub use secrets::SecretMaterial;

use origins::push_trusted_origin;

#[derive(Clone)]
pub struct AuthContext {
    pub app_name: String,
    pub base_url: String,
    pub base_path: String,
    pub options: OpenAuthOptions,
    pub auth_cookies: AuthCookies,
    pub session_config: SessionConfig,
    pub secret: String,
    pub secret_config: SecretMaterial,
    pub password: PasswordContext,
    pub rate_limit: RateLimitContext,
    pub trusted_origins: Vec<String>,
    pub disabled_paths: Vec<String>,
    pub plugins: Vec<AuthPlugin>,
    pub adapter: Option<Arc<dyn DbAdapter>>,
    pub social_providers: BTreeMap<String, Arc<dyn SocialOAuthProvider>>,
    pub db_schema: DbSchema,
    pub plugin_error_codes: BTreeMap<String, PluginErrorCode>,
    pub plugin_database_hooks: Vec<crate::plugin::PluginDatabaseHook>,
    pub plugin_migrations: Vec<crate::plugin::PluginMigration>,
    pub logger: Logger,
}

/// Environment values used by context initialization.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuthEnvironment {
    pub better_auth_secret: Option<String>,
    pub auth_secret: Option<String>,
    pub better_auth_secrets: Option<String>,
}

impl fmt::Debug for AuthEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthEnvironment")
            .field(
                "better_auth_secret",
                &self.better_auth_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "auth_secret",
                &self.auth_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "better_auth_secrets",
                &self.better_auth_secrets.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl AuthEnvironment {
    pub fn from_process() -> Self {
        Self {
            better_auth_secret: std::env::var("BETTER_AUTH_SECRET").ok(),
            auth_secret: std::env::var("AUTH_SECRET").ok(),
            better_auth_secrets: std::env::var("BETTER_AUTH_SECRETS").ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    pub update_age: u64,
    pub expires_in: u64,
    pub fresh_age: u64,
    pub cookie_refresh_cache: bool,
}

#[derive(Clone)]
pub struct PasswordContext {
    pub config: PasswordPolicy,
    pub hash: fn(&str) -> Result<String, OpenAuthError>,
    pub verify: fn(&str, &str) -> Result<bool, OpenAuthError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_password_length: usize,
    pub max_password_length: usize,
}

#[derive(Clone)]
pub struct RateLimitContext {
    pub enabled: bool,
    pub window: u64,
    pub max: u64,
    pub storage: RateLimitStorageOption,
    pub custom_rules: Vec<RateLimitPathRule>,
    pub dynamic_rules: Vec<DynamicRateLimitPathRule>,
    pub plugin_rules: Vec<crate::plugin::PluginRateLimitRule>,
    pub custom_store: Option<Arc<dyn RateLimitStore>>,
    pub hybrid: HybridRateLimitOptions,
    pub memory_idle_ttl: Option<Duration>,
    pub memory_store: Arc<TokioMemoryRateLimitStore>,
}

impl AuthContext {
    pub fn adapter(&self) -> Option<Arc<dyn DbAdapter>> {
        self.adapter.clone()
    }

    pub fn social_provider(&self, id: &str) -> Option<Arc<dyn SocialOAuthProvider>> {
        self.social_providers.get(id).cloned()
    }

    pub fn has_plugin(&self, id: &str) -> bool {
        self.plugins.iter().any(|plugin| plugin.id == id)
    }

    pub fn is_trusted_origin(&self, url: &str, settings: Option<OriginMatchSettings>) -> bool {
        self.trusted_origins
            .iter()
            .any(|origin| matches_origin_pattern(url, origin, settings))
    }

    pub fn trusted_origins_for_request(
        &self,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<Vec<String>, OpenAuthError> {
        let mut origins = self.trusted_origins.clone();
        if let Some(provider) = self.options.trusted_origins.provider() {
            for origin in provider.trusted_origins(request)? {
                push_trusted_origin(&mut origins, origin);
            }
        }
        Ok(origins)
    }

    pub fn is_trusted_origin_for_request(
        &self,
        url: &str,
        settings: Option<OriginMatchSettings>,
        request: Option<&Request<Vec<u8>>>,
    ) -> Result<bool, OpenAuthError> {
        Ok(self
            .trusted_origins_for_request(request)?
            .iter()
            .any(|origin| matches_origin_pattern(url, origin, settings)))
    }
}
