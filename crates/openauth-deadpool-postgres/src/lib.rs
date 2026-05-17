//! Pooled Postgres database adapter for OpenAuth.
//!
//! This crate is the recommended Postgres adapter for production deployments.
//! It keeps pooling in `deadpool-postgres` and reuses OpenAuth's shared SQL
//! planning plus `openauth-tokio-postgres` driver helpers.

pub mod migration;

use std::fmt;
use std::sync::Arc;

use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use openauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, AuthSchemaOptions, Count, Create, DbAdapter,
    DbRecord, DbSchema, Delete, DeleteMany, FindMany, FindOne, JoinAdapter, SchemaCreation,
    SqlRateLimitNames, TransactionCallback, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitStore,
};
use openauth_tokio_postgres::driver::{
    consume_postgres_rate_limit_in_tx, postgres_error, postgres_rate_limit_plan, PostgresSqlState,
};
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};

const DEFAULT_POOL_MAX_SIZE: usize = 16;

/// Production-oriented Postgres adapter backed by a `deadpool-postgres` pool.
#[derive(Clone)]
pub struct DeadpoolPostgresAdapter {
    pool: Pool,
    schema: Arc<DbSchema>,
}

/// Database-backed rate-limit store backed by a `deadpool-postgres` pool.
#[derive(Clone)]
pub struct DeadpoolPostgresRateLimitStore {
    pool: Pool,
    names: SqlRateLimitNames,
}

impl fmt::Debug for DeadpoolPostgresAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeadpoolPostgresAdapter")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DeadpoolPostgresRateLimitStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeadpoolPostgresRateLimitStore")
            .field("names", &self.names)
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

    pub async fn connect(database_url: &str) -> Result<Self, OpenAuthError> {
        Self::connect_with_schema(database_url, auth_schema(AuthSchemaOptions::default())).await
    }

    pub async fn connect_with_schema(
        database_url: &str,
        schema: DbSchema,
    ) -> Result<Self, OpenAuthError> {
        let mut config = Config::new();
        config.url = Some(database_url.to_owned());
        Self::from_config_with_schema(config, schema, DEFAULT_POOL_MAX_SIZE)
    }

    pub fn from_config(config: Config, max_size: usize) -> Result<Self, OpenAuthError> {
        Self::from_config_with_schema(config, auth_schema(AuthSchemaOptions::default()), max_size)
    }

    pub fn from_config_with_schema(
        mut config: Config,
        schema: DbSchema,
        max_size: usize,
    ) -> Result<Self, OpenAuthError> {
        config.pool = Some(PoolConfig::new(max_size));
        let pool = config
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(deadpool_error)?;
        Ok(Self::with_schema(pool, schema))
    }

    pub async fn plan_migrations(
        &self,
        schema: &DbSchema,
    ) -> Result<SchemaMigrationPlan, OpenAuthError> {
        let client = self.pool.get().await.map_err(deadpool_error)?;
        openauth_tokio_postgres::driver::plan_migrations(pg_client(&client), schema).await
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

impl DeadpoolPostgresRateLimitStore {
    pub fn new(pool: Pool) -> Self {
        Self::with_table(pool, "rate_limits")
    }

    pub fn with_table(pool: Pool, table: impl Into<String>) -> Self {
        Self {
            pool,
            names: SqlRateLimitNames::new(table),
        }
    }
}

impl From<&DeadpoolPostgresAdapter> for DeadpoolPostgresRateLimitStore {
    fn from(adapter: &DeadpoolPostgresAdapter) -> Self {
        Self {
            pool: adapter.pool.clone(),
            names: SqlRateLimitNames::from_schema(&adapter.schema),
        }
    }
}

impl RateLimitStore for DeadpoolPostgresRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move { consume_deadpool_rate_limit(self, input).await })
    }
}

impl DbAdapter for DeadpoolPostgresAdapter {
    fn id(&self) -> &str {
        "deadpool-postgres"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("deadpool-postgres")
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
                Ok(()) => client.batch_execute("COMMIT").await.map_err(postgres_error),
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

struct DeadpoolPostgresTxAdapter {
    client: Arc<Mutex<deadpool_postgres::Client>>,
    schema: Arc<DbSchema>,
}

impl DeadpoolPostgresTxAdapter {
    async fn run_with_state<T>(
        &self,
        f: impl for<'a> FnOnce(PostgresSqlState<'a>) -> AdapterFuture<'a, T> + Send,
    ) -> Result<T, OpenAuthError>
    where
        T: Send + 'static,
    {
        let client = self.client.lock().await;
        f(PostgresSqlState::new(
            self.schema.as_ref(),
            pg_client(&client),
        ))
        .await
    }
}

impl DbAdapter for DeadpoolPostgresTxAdapter {
    fn id(&self) -> &str {
        "deadpool-postgres-tx"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("deadpool-postgres transaction")
            .with_json()
            .with_arrays()
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
            self.run_with_state(|state| Box::pin(state.find_many(query)))
                .await
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

    fn transaction<'a>(&'a self, _callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        Box::pin(async {
            Err(OpenAuthError::Adapter(
                "nested deadpool-postgres transactions are not supported".to_owned(),
            ))
        })
    }
}

async fn consume_deadpool_rate_limit(
    store: &DeadpoolPostgresRateLimitStore,
    input: RateLimitConsumeInput,
) -> Result<RateLimitDecision, OpenAuthError> {
    let plan = postgres_rate_limit_plan(
        &store.names.table,
        &store.names.key,
        &store.names.count,
        &store.names.last_request,
    )?;
    let client = store.pool.get().await.map_err(deadpool_error)?;
    client
        .batch_execute("BEGIN")
        .await
        .map_err(postgres_error)?;
    let result = consume_postgres_rate_limit_in_tx(pg_client(&client), &plan, input).await;
    match result {
        Ok(decision) => {
            client
                .batch_execute("COMMIT")
                .await
                .map_err(postgres_error)?;
            Ok(decision)
        }
        Err(error) => {
            let _rollback_result = client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}

fn pg_client(client: &deadpool_postgres::Client) -> &Client {
    client
}

fn deadpool_error(error: impl fmt::Display) -> OpenAuthError {
    OpenAuthError::Adapter(format!("deadpool-postgres error: {error}"))
}

pub use self::migration::{
    ColumnToAdd, IndexToCreate, MigrationStatement, MigrationStatementKind, SchemaMigrationPlan,
    SchemaMigrationWarning, TableToCreate,
};
