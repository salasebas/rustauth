//! Bundled database adapter + SQL-backed rate-limit store for `tokio-postgres`.

use std::sync::Arc;

use rustauth_core::db::{auth_schema, AuthSchemaOptions, DbAdapter, DbSchema};
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{RateLimitOptions, RustAuthOptions};

use crate::adapter::TokioPostgresAdapter;
use crate::rate_limit::TokioPostgresRateLimitStore;

/// Configures and connects a [`TokioPostgresStores`] bundle.
#[derive(Debug, Clone)]
pub struct TokioPostgresStoresBuilder {
    schema: DbSchema,
}

impl Default for TokioPostgresStoresBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TokioPostgresStoresBuilder {
    pub fn new() -> Self {
        Self {
            schema: auth_schema(AuthSchemaOptions::default()),
        }
    }

    #[must_use]
    pub fn schema(mut self, schema: DbSchema) -> Self {
        self.schema = schema;
        self
    }

    pub async fn connect(self, database_url: &str) -> Result<TokioPostgresStores, RustAuthError> {
        let adapter = TokioPostgresAdapter::connect_with_schema(database_url, self.schema).await?;
        let rate_limit = TokioPostgresRateLimitStore::from(&adapter);
        Ok(TokioPostgresStores {
            adapter,
            rate_limit,
        })
    }
}

/// Database adapter and matching SQL-backed rate-limit store sharing one client.
#[derive(Clone)]
pub struct TokioPostgresStores {
    pub adapter: TokioPostgresAdapter,
    pub rate_limit: TokioPostgresRateLimitStore,
}

impl std::fmt::Debug for TokioPostgresStores {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokioPostgresStores")
            .field("adapter", &self.adapter)
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl TokioPostgresStores {
    pub fn builder() -> TokioPostgresStoresBuilder {
        TokioPostgresStoresBuilder::new()
    }

    pub async fn connect(database_url: &str) -> Result<Self, RustAuthError> {
        Self::builder().connect(database_url).await
    }

    pub async fn connect_with_schema(
        database_url: &str,
        schema: DbSchema,
    ) -> Result<Self, RustAuthError> {
        Self::builder().schema(schema).connect(database_url).await
    }

    /// Wires the SQL-backed rate-limit store into [`RustAuthOptions`].
    #[must_use]
    pub fn apply_to_options(&self, options: RustAuthOptions) -> RustAuthOptions {
        options.rate_limit(RateLimitOptions::database(self.rate_limit.clone()))
    }

    pub fn adapter(&self) -> Arc<dyn DbAdapter> {
        Arc::new(self.adapter.clone())
    }

    pub fn adapter_ref(&self) -> &TokioPostgresAdapter {
        &self.adapter
    }
}
