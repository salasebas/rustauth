use std::sync::Arc;

use deadpool_postgres::Pool;
use rustauth_core::db::SchemaMigrationPlan;
use rustauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, AuthSchemaOptions, Count, Create, DbAdapter,
    DbRecord, DbSchema, Delete, DeleteMany, FindMany, FindOne, SchemaCreation, TransactionCallback,
    Update, UpdateMany,
};
use rustauth_core::error::RustAuthError;
use rustauth_tokio_postgres::driver::{postgres_error, PostgresSqlState};
use tokio::sync::Mutex;

use crate::builder::DeadpoolPostgresBuilder;
use crate::config::{deadpool_error, pg_client};
use crate::transaction::DeadpoolPostgresTxAdapter;
use crate::tx_guard::PooledClientRollbackGuard;

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

    pub fn builder() -> DeadpoolPostgresBuilder {
        DeadpoolPostgresBuilder::new()
    }

    pub async fn plan_migrations(
        &self,
        schema: &DbSchema,
    ) -> Result<SchemaMigrationPlan, RustAuthError> {
        let client = self.pool.get().await.map_err(deadpool_error)?;
        rustauth_tokio_postgres::driver::plan_migrations(pg_client(&client), schema).await
    }

    pub async fn validate_connection(&self) -> Result<(), RustAuthError> {
        let client = self.pool.get().await.map_err(deadpool_error)?;
        client
            .simple_query("SELECT 1")
            .await
            .map_err(postgres_error)?;
        Ok(())
    }

    pub async fn compile_migrations(&self, schema: &DbSchema) -> Result<String, RustAuthError> {
        Ok(self.plan_migrations(schema).await?.compile())
    }

    async fn run_with_state<T>(
        &self,
        f: impl for<'a> FnOnce(PostgresSqlState<'a>) -> AdapterFuture<'a, T> + Send,
    ) -> Result<T, RustAuthError>
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
            .with_native_joins()
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

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(deadpool_error)?;
            client
                .batch_execute("BEGIN")
                .await
                .map_err(postgres_error)?;
            let client = Arc::new(Mutex::new(client));
            let mut guard = PooledClientRollbackGuard::new(Arc::clone(&client));
            let adapter = DeadpoolPostgresTxAdapter {
                client: Arc::clone(&client),
                schema: Arc::clone(&self.schema),
            };
            let result = callback(Box::new(adapter)).await;

            let locked = client.lock().await;
            match result {
                Ok(()) => {
                    if let Err(error) = locked.batch_execute("COMMIT").await {
                        let _rollback_result = locked.batch_execute("ROLLBACK").await;
                        guard.disarm();
                        return Err(postgres_error(error));
                    }
                    guard.disarm();
                    Ok(())
                }
                Err(error) => {
                    let _rollback_result = locked.batch_execute("ROLLBACK").await;
                    guard.disarm();
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
            rustauth_tokio_postgres::driver::create_schema(pg_client(&client), schema).await?;
            Ok(None)
        })
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let client = self.pool.get().await.map_err(deadpool_error)?;
            rustauth_tokio_postgres::driver::execute_migration_plan(pg_client(&client), schema)
                .await
        })
    }
}
