//! Request and runtime context contracts.

pub mod request_state;

mod builder;
mod origins;
mod plugins;
mod secrets;

use crate::auth::trusted_origins::{matches_origin_pattern, OriginMatchSettings};
use crate::cookies::{AuthCookie, AuthCookies};
use crate::db::{DbAdapter, DbSchema};
use crate::env::logger::Logger;
use crate::error::OpenAuthError;
use crate::options::{
    BackgroundTaskFuture, BackgroundTaskRunner, DynamicRateLimitPathRule, HybridRateLimitOptions,
    MissingIpPolicy, OpenAuthOptions, RateLimitPathRule, RateLimitStorageOption, RateLimitStore,
    SecondaryStorage,
};
use crate::plugin::{AuthPlugin, PluginErrorCode};
use crate::rate_limit::GovernorMemoryRateLimitStore;
use http::Request;
#[cfg(feature = "oauth")]
use openauth_oauth::oauth2::SocialOAuthProvider;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub use builder::{
    create_auth_context, create_auth_context_with_adapter, create_auth_context_with_environment,
    create_auth_context_with_environment_and_adapter,
};
pub use secrets::SecretMaterial;

use origins::push_trusted_origin;

pub type ContextTelemetryFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
pub type ContextTelemetryPublisher =
    Arc<dyn Fn(ContextTelemetryEvent) -> ContextTelemetryFuture + Send + Sync>;

#[derive(Clone, Debug, PartialEq)]
pub struct ContextTelemetryEvent {
    pub event_type: String,
    pub anonymous_id: Option<String>,
    pub payload: serde_json::Value,
}

pub(super) fn noop_telemetry_publisher() -> ContextTelemetryPublisher {
    Arc::new(|_| Box::pin(async move {}))
}

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
    pub secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    pub background_tasks: Option<Arc<dyn BackgroundTaskRunner>>,
    #[cfg(feature = "oauth")]
    pub social_providers: BTreeMap<String, Arc<dyn SocialOAuthProvider>>,
    pub db_schema: DbSchema,
    pub plugin_error_codes: BTreeMap<String, PluginErrorCode>,
    pub plugin_database_hooks: Vec<crate::plugin::PluginDatabaseHook>,
    pub plugin_migrations: Vec<crate::plugin::PluginMigration>,
    pub telemetry_publisher: ContextTelemetryPublisher,
    pub logger: Logger,
}

/// Environment values used by context initialization.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuthEnvironment {
    pub openauth_secret: Option<String>,
    pub openauth_secrets: Option<String>,
}

impl fmt::Debug for AuthEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthEnvironment")
            .field(
                "openauth_secret",
                &self.openauth_secret.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "openauth_secrets",
                &self.openauth_secrets.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl AuthEnvironment {
    pub fn from_process() -> Self {
        Self {
            openauth_secret: std::env::var("OPENAUTH_SECRET").ok(),
            openauth_secrets: std::env::var("OPENAUTH_SECRETS").ok(),
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
    pub memory_cleanup_interval: Option<Duration>,
    pub memory_store: Arc<GovernorMemoryRateLimitStore>,
    pub missing_ip_policy: MissingIpPolicy,
}

impl AuthContext {
    pub fn adapter(&self) -> Option<Arc<dyn DbAdapter>> {
        self.adapter.clone()
    }

    /// Build a plugin auth cookie definition that inherits the core cookie
    /// naming and attribute policy (`cookie_prefix`, secure-name prefix,
    /// cross-subdomain `domain`, and `default_cookie_attributes`), exactly as
    /// the core session cookies produced by `get_cookies`.
    pub fn create_auth_cookie(
        &self,
        name: &str,
        max_age: Option<u64>,
    ) -> Result<AuthCookie, OpenAuthError> {
        crate::cookies::create_auth_cookie(&self.options, name, max_age)
    }

    pub fn secondary_storage(&self) -> Option<Arc<dyn SecondaryStorage>> {
        self.secondary_storage.clone()
    }

    pub fn run_background_task(&self, task: BackgroundTaskFuture) -> bool {
        let Some(runner) = &self.background_tasks else {
            return false;
        };
        runner.spawn(task);
        true
    }

    pub async fn publish_telemetry(&self, event: ContextTelemetryEvent) {
        (self.telemetry_publisher)(event).await;
    }

    #[cfg(feature = "oauth")]
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
