use std::fmt;
use std::sync::Arc;

use openauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, AuthSchemaOptions, Count, Create, DbAdapter,
    DbRecord, DbSchema, Delete, DeleteMany, FindMany, FindOne, SchemaCreation, TransactionCallback,
    Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use tokio_postgres::Client;

use crate::connection::TokioPostgresConnection;
use crate::driver::PostgresSqlState;
use crate::errors::postgres_error;
use crate::rate_limit::TokioPostgresRateLimitStore;
use crate::schema::{
    create_schema, execute_migration_plan, plan_migrations as plan_schema_migrations,
};
use crate::transaction::TokioPostgresTxAdapter;
use crate::tx_guard::SharedClientRollbackGuard;
use crate::SchemaMigrationPlan;

#[derive(Clone)]
pub struct TokioPostgresAdapter {
    pub(crate) connection: TokioPostgresConnection,
    pub(crate) schema: Arc<DbSchema>,
}

impl fmt::Debug for TokioPostgresAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokioPostgresAdapter")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

impl TokioPostgresAdapter {
    pub fn new(client: Client) -> Self {
        Self::with_schema(client, auth_schema(AuthSchemaOptions::default()))
    }

    pub fn with_schema(client: Client, schema: DbSchema) -> Self {
        Self::with_connection(TokioPostgresConnection::from_client(client), schema)
    }

    pub fn with_connection(connection: TokioPostgresConnection, schema: DbSchema) -> Self {
        Self {
            connection,
            schema: Arc::new(schema),
        }
    }

    /// Returns the shared client and transaction gate used by this adapter.
    pub fn connection(&self) -> &TokioPostgresConnection {
        &self.connection
    }

    /// Builds a SQL-backed rate-limit store that shares this adapter's client
    /// and transaction gate.
    pub fn rate_limit_store(&self) -> TokioPostgresRateLimitStore {
        TokioPostgresRateLimitStore::from(self)
    }

    /// Connects to Postgres and spawns the `tokio-postgres` connection driver.
    pub async fn connect(database_url: &str) -> Result<Self, OpenAuthError> {
        Self::connect_with_schema(database_url, auth_schema(AuthSchemaOptions::default())).await
    }

    /// Connects to Postgres with a custom OpenAuth schema.
    ///
    /// The returned adapter owns the client handle and keeps the driver future
    /// running in a background task as required by `tokio-postgres`.
    pub async fn connect_with_schema(
        database_url: &str,
        schema: DbSchema,
    ) -> Result<Self, OpenAuthError> {
        Ok(Self::with_connection(
            TokioPostgresConnection::connect(database_url).await?,
            schema,
        ))
    }

    pub async fn plan_migrations(
        &self,
        schema: &DbSchema,
    ) -> Result<SchemaMigrationPlan, OpenAuthError> {
        let _gate = self.connection.tx_gate.write().await;
        plan_schema_migrations(self.connection.client.as_ref(), schema).await
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
        let _gate = self.connection.tx_gate.read().await;
        f(PostgresSqlState::new(
            self.schema.as_ref(),
            self.connection.client.as_ref(),
        ))
        .await
    }
}

impl DbAdapter for TokioPostgresAdapter {
    fn id(&self) -> &str {
        "tokio-postgres"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("tokio-postgres")
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
            let gate = Arc::clone(&self.connection.tx_gate).write_owned().await;
            self.connection
                .client
                .batch_execute("BEGIN")
                .await
                .map_err(postgres_error)?;
            let mut guard =
                SharedClientRollbackGuard::new(Arc::clone(&self.connection.client), gate);

            let adapter = TokioPostgresTxAdapter::new(
                Arc::clone(&self.connection.client),
                Arc::clone(&self.schema),
            );
            let result = callback(Box::new(adapter)).await;

            match result {
                Ok(()) => {
                    if let Err(error) = self.connection.client.batch_execute("COMMIT").await {
                        let _rollback_result =
                            self.connection.client.batch_execute("ROLLBACK").await;
                        guard.disarm();
                        return Err(postgres_error(error));
                    }
                    guard.disarm();
                    Ok(())
                }
                Err(error) => {
                    let _rollback_result = self.connection.client.batch_execute("ROLLBACK").await;
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
            let _gate = self.connection.tx_gate.write().await;
            create_schema(self.connection.client.as_ref(), schema).await?;
            Ok(None)
        })
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let _gate = self.connection.tx_gate.write().await;
            execute_migration_plan(self.connection.client.as_ref(), schema).await
        })
    }
}
