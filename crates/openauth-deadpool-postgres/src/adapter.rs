use std::sync::Arc;

use deadpool_postgres::{Config, Pool};
use openauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, AuthSchemaOptions, Count, Create, DbAdapter,
    DbRecord, DbSchema, Delete, DeleteMany, FindMany, FindOne, JoinAdapter, SchemaCreation,
    TransactionCallback, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use openauth_tokio_postgres::driver::{postgres_error, PostgresSqlState};
use tokio::sync::Mutex;
use tokio_postgres::{
    tls::{MakeTlsConnect, TlsConnect},
    Socket,
};

use crate::config::{
    apply_default_pool_config, create_pool, create_pool_no_tls, deadpool_error, pg_client,
    DEFAULT_POOL_MAX_SIZE,
};
use crate::transaction::DeadpoolPostgresTxAdapter;
use crate::SchemaMigrationPlan;

/// Production-oriented Postgres adapter backed by a `deadpool-postgres` pool.
#[derive(Clone)]
pub struct DeadpoolPostgresAdapter {
    pub(crate) pool: Pool,
    pub(crate) schema: Arc<DbSchema>,
}

impl std::fmt::Debug for DeadpoolPostgresAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeadpoolPostgresAdapter")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

impl DeadpoolPostgresAdapter {
    pub fn new(pool: Pool) -> Self {
        Self::with_schema(pool, auth_schema(AuthSchemaOptions::default()))
    }

    pub fn with_schema(pool: Pool, schema: DbSchema) -> Self {
        Self {
            pool,
            schema: Arc::new(schema),
        }
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub async fn connect(database_url: &str) -> Result<Self, OpenAuthError> {
        Self::connect_with_schema(database_url, auth_schema(AuthSchemaOptions::default())).await
    }

    pub async fn connect_checked(database_url: &str) -> Result<Self, OpenAuthError> {
        let adapter = Self::connect(database_url).await?;
        adapter.validate_connection().await?;
        Ok(adapter)
    }

    pub async fn connect_with_schema(
        database_url: &str,
        schema: DbSchema,
    ) -> Result<Self, OpenAuthError> {
        let mut config = Config::new();
        config.url = Some(database_url.to_owned());
        Self::from_config_with_schema(config, schema, DEFAULT_POOL_MAX_SIZE)
    }

    pub async fn connect_with_schema_checked(
        database_url: &str,
        schema: DbSchema,
    ) -> Result<Self, OpenAuthError> {
        let adapter = Self::connect_with_schema(database_url, schema).await?;
        adapter.validate_connection().await?;
        Ok(adapter)
    }

    pub async fn connect_tls<T>(database_url: &str, tls: T) -> Result<Self, OpenAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        Self::connect_with_schema_tls(database_url, auth_schema(AuthSchemaOptions::default()), tls)
            .await
    }

    pub async fn connect_tls_checked<T>(database_url: &str, tls: T) -> Result<Self, OpenAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let adapter = Self::connect_tls(database_url, tls).await?;
        adapter.validate_connection().await?;
        Ok(adapter)
    }

    pub async fn connect_with_schema_tls<T>(
        database_url: &str,
        schema: DbSchema,
        tls: T,
    ) -> Result<Self, OpenAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let mut config = Config::new();
        config.url = Some(database_url.to_owned());
        Self::from_config_with_schema_tls(config, schema, DEFAULT_POOL_MAX_SIZE, tls)
    }

    pub async fn connect_with_schema_tls_checked<T>(
        database_url: &str,
        schema: DbSchema,
        tls: T,
    ) -> Result<Self, OpenAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let adapter = Self::connect_with_schema_tls(database_url, schema, tls).await?;
        adapter.validate_connection().await?;
        Ok(adapter)
    }

    pub fn from_config(config: Config, max_size: usize) -> Result<Self, OpenAuthError> {
        Self::from_config_with_schema(config, auth_schema(AuthSchemaOptions::default()), max_size)
    }

    pub fn from_config_tls<T>(
        config: Config,
        max_size: usize,
        tls: T,
    ) -> Result<Self, OpenAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        Self::from_config_with_schema_tls(
            config,
            auth_schema(AuthSchemaOptions::default()),
            max_size,
            tls,
        )
    }

    pub fn from_config_with_schema(
        mut config: Config,
        schema: DbSchema,
        max_size: usize,
    ) -> Result<Self, OpenAuthError> {
        apply_default_pool_config(&mut config, max_size);
        let pool = create_pool_no_tls(config)?;
        Ok(Self::with_schema(pool, schema))
    }

    pub fn from_config_with_schema_tls<T>(
        mut config: Config,
        schema: DbSchema,
        max_size: usize,
        tls: T,
    ) -> Result<Self, OpenAuthError>
    where
        T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
        T::Stream: Sync + Send,
        T::TlsConnect: Sync + Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        apply_default_pool_config(&mut config, max_size);
        let pool = create_pool(config, tls)?;
        Ok(Self::with_schema(pool, schema))
    }

    pub async fn plan_migrations(
        &self,
        schema: &DbSchema,
    ) -> Result<SchemaMigrationPlan, OpenAuthError> {
        let client = self.pool.get().await.map_err(deadpool_error)?;
        openauth_tokio_postgres::driver::plan_migrations(pg_client(&client), schema).await
    }

    pub async fn validate_connection(&self) -> Result<(), OpenAuthError> {
        let client = self.pool.get().await.map_err(deadpool_error)?;
        client
            .simple_query("SELECT 1")
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    pub async fn compile_migrations(&self, schema: &DbSchema) -> Result<String, OpenAuthError> {
        Ok(self.plan_migrations(schema).await?.compile())
    }

    async fn run_with_state<T>(
        &self,
        f: impl for<'a> FnOnce(PostgresSqlState<'a>) -> AdapterFuture<'a, T> + Send,
    ) -> Result<T, OpenAuthError>
    where
        T: Send + 'static,
    {
        let client = self.pool.get().await.map_err(deadpool_error)?;
        f(PostgresSqlState::new(
            self.schema.as_ref(),
            pg_client(&client),
        ))
        .await
    }
}

impl DbAdapter for DeadpoolPostgresAdapter {
    fn id(&self) -> &str {
        "deadpool-postgres"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("deadpool-postgres")
            .with_uuid_ids()
            .with_json()
            .with_arrays()
            .with_joins()
            .with_transactions()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.create(query)))
                .await
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.find_one(query)))
                .await
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            if query.joins.len() <= 1 {
                self.run_with_state(|state| Box::pin(state.find_many(query)))
                    .await
            } else {
                let adapter =
                    JoinAdapter::new(self.schema.as_ref().clone(), Arc::new(self.clone()), false);
                adapter.find_many(query).await
            }
        })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.count(query)))
                .await
        })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.update(query)))
                .await
        })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.update_many(query)))
                .await
        })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.delete(query)))
                .await
        })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.delete_many(query)))
                .await
        })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(deadpool_error)?;
            client
                .batch_execute("BEGIN")
                .await
                .map_err(postgres_error)?;
            let client = Arc::new(Mutex::new(client));
            let adapter = DeadpoolPostgresTxAdapter {
                client: Arc::clone(&client),
                schema: Arc::clone(&self.schema),
            };
            let result = callback(Box::new(adapter)).await;

            let client = client.lock().await;
            match result {
                Ok(()) => {
                    if let Err(error) = client.batch_execute("COMMIT").await {
                        let _rollback_result = client.batch_execute("ROLLBACK").await;
                        return Err(postgres_error(error));
                    }
                    Ok(())
                }
                Err(error) => {
                    let _rollback_result = client.batch_execute("ROLLBACK").await;
                    Err(error)
                }
            }
        })
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        _file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(deadpool_error)?;
            openauth_tokio_postgres::driver::create_schema(pg_client(&client), schema).await?;
            Ok(None)
        })
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(deadpool_error)?;
            openauth_tokio_postgres::driver::execute_migration_plan(pg_client(&client), schema)
                .await
        })
    }
}
