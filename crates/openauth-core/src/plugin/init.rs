//! Plugin initialization contracts.

use super::db::{PluginDatabaseHook, PluginMigration};
use super::error::PluginErrorCode;
use super::rate_limit::PluginRateLimitRule;
use super::schema::PluginSchemaContribution;
use crate::context::AuthContext;
use crate::error::OpenAuthError;
use std::sync::Arc;

pub type PluginInitHandler =
    Arc<dyn Fn(&AuthContext) -> Result<PluginInitOutput, OpenAuthError> + Send + Sync>;

/// Typed, additive output from a plugin init handler.
#[derive(Debug, Clone, Default)]
pub struct PluginInitOutput {
    pub trusted_origins: Vec<String>,
    pub disabled_paths: Vec<String>,
    pub schema: Vec<PluginSchemaContribution>,
    pub rate_limit: Vec<PluginRateLimitRule>,
    pub error_codes: Vec<PluginErrorCode>,
    pub database_hooks: Vec<PluginDatabaseHook>,
    pub migrations: Vec<PluginMigration>,
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
}
