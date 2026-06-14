use deadpool_postgres::{Config, Pool};
use rustauth_core::db::{auth_schema, AuthSchemaOptions, DbSchema};
use rustauth_core::error::RustAuthError;
use tokio_postgres::{
    tls::{MakeTlsConnect, TlsConnect},
    NoTls, Socket,
};

use crate::adapter::DeadpoolPostgresAdapter;
use crate::config::{apply_default_pool_config, create_pool, DEFAULT_POOL_MAX_SIZE};

/// Configures and connects a [`DeadpoolPostgresAdapter`].
///
/// Prefer the [`DeadpoolPostgresStoresBuilder`] name when building
/// [`DeadpoolPostgresStores`]; both names refer to the same type.
#[derive(Debug, Clone)]
pub struct DeadpoolPostgresBuilder {
    schema: DbSchema,
    max_size: usize,
    checked: bool,
    database_url: Option<String>,
    config: Option<Config>,
}

/// Preferred name for [`DeadpoolPostgresBuilder`] when configuring
/// [`DeadpoolPostgresStores`].
pub type DeadpoolPostgresStoresBuilder = DeadpoolPostgresBuilder;

impl Default for DeadpoolPostgresBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadpoolPostgresBuilder {
    pub fn new() -> Self {
        Self {
            schema: auth_schema(AuthSchemaOptions::default()),
            max_size: DEFAULT_POOL_MAX_SIZE,
            checked: false,
            database_url: None,
            config: None,
        }
    }

    #[must_use]
    pub fn schema(mut self, schema: DbSchema) -> Self {
        self.schema = schema;
        self
    }

    #[must_use]
    pub fn max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Validates the pool with `SELECT 1` after connecting.
    #[must_use]
    pub fn checked(mut self, checked: bool) -> Self {
        self.checked = checked;
        self
    }

    #[must_use]
    pub fn database_url(mut self, database_url: impl Into<String>) -> Self {
        self.database_url = Some(database_url.into());
        self
    }

    #[must_use]
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Builds the adapter without validating the pool connection.
    pub fn build_adapter(self) -> Result<DeadpoolPostgresAdapter, RustAuthError> {
        self.build(NoTls)
    }

    pub fn build_adapter_tls<T>(self, tls: T) -> Result<DeadpoolPostgresAdapter, RustAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        self.build(tls)
    }

    pub async fn connect(self) -> Result<DeadpoolPostgresAdapter, RustAuthError> {
        let checked = self.checked;
        let adapter = self.build_adapter()?;
        if checked {
            adapter.validate_connection().await?;
        }
        Ok(adapter)
    }

    pub async fn connect_tls<T>(self, tls: T) -> Result<DeadpoolPostgresAdapter, RustAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let checked = self.checked;
        let adapter = self.build_adapter_tls(tls)?;
        if checked {
            adapter.validate_connection().await?;
        }
        Ok(adapter)
    }

    fn build<T>(self, tls: T) -> Result<DeadpoolPostgresAdapter, RustAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let mut config = self.config.unwrap_or_default();
        if let Some(database_url) = self.database_url {
            if config.url.is_some() {
                return Err(RustAuthError::InvalidConfig(
                    "deadpool-postgres builder: set either `database_url` or `config`, not both"
                        .to_owned(),
                ));
            }
            config.url = Some(database_url);
        }
        if config.url.is_none() && config.host.is_none() {
            return Err(RustAuthError::InvalidConfig(
                "deadpool-postgres builder: `database_url` or `config` is required".to_owned(),
            ));
        }
        apply_default_pool_config(&mut config, self.max_size);
        let pool = create_pool(config, tls)?;
        Ok(DeadpoolPostgresAdapter::with_schema(pool, self.schema))
    }
}

/// Database adapter and matching SQL-backed rate-limit store sharing one pool.
#[derive(Clone)]
pub struct DeadpoolPostgresStores {
    pub adapter: DeadpoolPostgresAdapter,
    pub rate_limit: crate::DeadpoolPostgresRateLimitStore,
}

impl std::fmt::Debug for DeadpoolPostgresStores {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeadpoolPostgresStores")
            .field("adapter", &self.adapter)
            .field("rate_limit", &self.rate_limit)
            .finish()
    }
}

impl DeadpoolPostgresStores {
    pub fn builder() -> DeadpoolPostgresBuilder {
        DeadpoolPostgresBuilder::new()
    }

    pub async fn connect(database_url: &str) -> Result<Self, RustAuthError> {
        Self::builder()
            .database_url(database_url)
            .build_stores()
            .await
    }

    pub async fn connect_with_schema(
        database_url: &str,
        schema: DbSchema,
    ) -> Result<Self, RustAuthError> {
        Self::builder()
            .database_url(database_url)
            .schema(schema)
            .build_stores()
            .await
    }

    pub async fn connect_checked(database_url: &str) -> Result<Self, RustAuthError> {
        Self::builder()
            .database_url(database_url)
            .checked(true)
            .build_stores()
            .await
    }

    pub async fn connect_with_schema_checked(
        database_url: &str,
        schema: DbSchema,
    ) -> Result<Self, RustAuthError> {
        Self::builder()
            .database_url(database_url)
            .schema(schema)
            .checked(true)
            .build_stores()
            .await
    }

    /// Wires the SQL-backed rate-limit store into [`RustAuthOptions`].
    #[must_use]
    pub fn apply_to_options(
        &self,
        options: rustauth_core::options::RustAuthOptions,
    ) -> rustauth_core::options::RustAuthOptions {
        use rustauth_core::options::RateLimitOptions;
        options.rate_limit(RateLimitOptions::database(self.rate_limit.clone()))
    }

    pub fn adapter(&self) -> std::sync::Arc<dyn rustauth_core::db::DbAdapter> {
        std::sync::Arc::new(self.adapter.clone())
    }

    pub fn adapter_ref(&self) -> &DeadpoolPostgresAdapter {
        &self.adapter
    }

    pub fn pool(&self) -> &Pool {
        self.adapter.pool()
    }
}

impl DeadpoolPostgresBuilder {
    pub async fn build_stores(self) -> Result<DeadpoolPostgresStores, RustAuthError> {
        let adapter = self.connect().await?;
        let rate_limit = crate::DeadpoolPostgresRateLimitStore::from(&adapter);
        Ok(DeadpoolPostgresStores {
            adapter,
            rate_limit,
        })
    }

    pub async fn build_stores_tls<T>(self, tls: T) -> Result<DeadpoolPostgresStores, RustAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let checked = self.checked;
        let adapter = self.build_adapter_tls(tls)?;
        if checked {
            adapter.validate_connection().await?;
        }
        let rate_limit = crate::DeadpoolPostgresRateLimitStore::from(&adapter);
        Ok(DeadpoolPostgresStores {
            adapter,
            rate_limit,
        })
    }
}
