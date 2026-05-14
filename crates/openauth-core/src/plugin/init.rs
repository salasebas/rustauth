//! Plugin initialization contracts.

use super::db::{PluginDatabaseHook, PluginMigration};
use super::error::PluginErrorCode;
use super::rate_limit::PluginRateLimitRule;
use super::schema::PluginSchemaContribution;
use crate::context::AuthContext;
use crate::error::OpenAuthError;
use crate::options::{SessionAdditionalField, UserAdditionalField};
use openauth_oauth::oauth2::SocialOAuthProvider;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

pub type PluginInitHandler =
    Arc<dyn Fn(&AuthContext) -> Result<PluginInitOutput, OpenAuthError> + Send + Sync>;

/// Typed, additive output from a plugin init handler.
#[derive(Clone, Default)]
pub struct PluginInitOutput {
    pub trusted_origins: Vec<String>,
    pub disabled_paths: Vec<String>,
    pub schema: Vec<PluginSchemaContribution>,
    pub rate_limit: Vec<PluginRateLimitRule>,
    pub error_codes: Vec<PluginErrorCode>,
    pub database_hooks: Vec<PluginDatabaseHook>,
    pub migrations: Vec<PluginMigration>,
    pub social_providers: Vec<Arc<dyn SocialOAuthProvider>>,
    pub user_additional_fields: BTreeMap<String, UserAdditionalField>,
    pub session_additional_fields: BTreeMap<String, SessionAdditionalField>,
}

impl fmt::Debug for PluginInitOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginInitOutput")
            .field("trusted_origins", &self.trusted_origins)
            .field("disabled_paths", &self.disabled_paths)
            .field("schema", &self.schema)
            .field("rate_limit", &self.rate_limit)
            .field("error_codes", &self.error_codes)
            .field("database_hooks", &self.database_hooks)
            .field("migrations", &self.migrations)
            .field("user_additional_fields", &self.user_additional_fields)
            .field("session_additional_fields", &self.session_additional_fields)
            .field(
                "social_providers",
                &self
                    .social_providers
                    .iter()
                    .map(|provider| provider.id())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PluginInitOutput {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn trusted_origin(mut self, origin: impl Into<String>) -> Self {
        self.trusted_origins.push(origin.into());
        self
    }

    #[must_use]
    pub fn disabled_path(mut self, path: impl Into<String>) -> Self {
        self.disabled_paths.push(path.into());
        self
    }

    #[must_use]
    pub fn schema(mut self, contribution: PluginSchemaContribution) -> Self {
        self.schema.push(contribution);
        self
    }

    #[must_use]
    pub fn rate_limit(mut self, rule: PluginRateLimitRule) -> Self {
        self.rate_limit.push(rule);
        self
    }

    #[must_use]
    pub fn error_code(mut self, code: PluginErrorCode) -> Self {
        self.error_codes.push(code);
        self
    }

    #[must_use]
    pub fn database_hook(mut self, hook: PluginDatabaseHook) -> Self {
        self.database_hooks.push(hook);
        self
    }

    #[must_use]
    pub fn migration(mut self, migration: PluginMigration) -> Self {
        self.migrations.push(migration);
        self
    }

    #[must_use]
    pub fn social_provider(mut self, provider: impl Into<Arc<dyn SocialOAuthProvider>>) -> Self {
        self.social_providers.push(provider.into());
        self
    }

    #[must_use]
    pub fn user_additional_field(
        mut self,
        name: impl Into<String>,
        field: UserAdditionalField,
    ) -> Self {
        self.user_additional_fields.insert(name.into(), field);
        self
    }

    #[must_use]
    pub fn session_additional_field(
        mut self,
        name: impl Into<String>,
        field: SessionAdditionalField,
    ) -> Self {
        self.session_additional_fields.insert(name.into(), field);
        self
    }
}
