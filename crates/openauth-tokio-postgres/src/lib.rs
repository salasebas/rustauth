//! Minimal `tokio-postgres` database adapter for OpenAuth.
//!
//! This crate is useful when the application already owns a single
//! `tokio_postgres::Client` or wants the smallest async Postgres adapter.
//! Production applications that need pooling should prefer
//! `openauth-deadpool-postgres`.

pub mod driver;
mod errors;
pub mod migration;
mod query;
mod row;
mod schema;
mod state;

use std::fmt;
use std::sync::Arc;

use openauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, AuthSchemaOptions, Count, Create, DbAdapter,
    DbRecord, DbSchema, Delete, DeleteMany, FindMany, FindOne, JoinAdapter, SchemaCreation,
    SqlRateLimitNames, TransactionCallback, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitStore,
};
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};

use self::driver::{consume_postgres_rate_limit_in_tx, postgres_rate_limit_plan};
use self::errors::postgres_error;
use self::schema::{
    create_schema, execute_migration_plan, plan_migrations as plan_schema_migrations,
};
use self::state::TokioPostgresState;

#[derive(Clone)]
pub struct TokioPostgresAdapter {
    client: Arc<Mutex<Client>>,
    tx_gate: Arc<Mutex<()>>,
    schema: Arc<DbSchema>,
}

#[derive(Clone)]
pub struct TokioPostgresRateLimitStore {
    client: Arc<Mutex<Client>>,
    tx_gate: Arc<Mutex<()>>,
    names: SqlRateLimitNames,
}

impl fmt::Debug for TokioPostgresAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokioPostgresAdapter")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for TokioPostgresRateLimitStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokioPostgresRateLimitStore")
            .field("names", &self.names)
            .finish_non_exhaustive()
    }
}

impl TokioPostgresAdapter {
    pub fn new(client: Client) -> Self {
        Self::with_schema(client, auth_schema(AuthSchemaOptions::default()))
    }

    pub fn with_schema(client: Client, schema: DbSchema) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            tx_gate: Arc::new(Mutex::new(())),
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
        let (client, connection) = tokio_postgres::connect(database_url, NoTls)
            .await
            .map_err(postgres_error)?;
        tokio::spawn(async move {
            let _connection_result = connection.await;
        });
        Ok(Self::with_schema(client, schema))
    }

    pub async fn plan_migrations(
        &self,
        schema: &DbSchema,
    ) -> Result<SchemaMigrationPlan, OpenAuthError> {
        let _gate = self.tx_gate.lock().await;
        let client = self.client.lock().await;
        plan_schema_migrations(&client, schema).await
    }

    pub async fn compile_migrations(&self, schema: &DbSchema) -> Result<String, OpenAuthError> {
        Ok(self.plan_migrations(schema).await?.compile())
    }

    async fn run_with_state<T>(
        &self,
        f: impl for<'a> FnOnce(TokioPostgresState<'a>) -> AdapterFuture<'a, T> + Send,
    ) -> Result<T, OpenAuthError>
    where
        T: Send + 'static,
    {
        let _gate = self.tx_gate.lock().await;
        let client = self.client.lock().await;
        f(TokioPostgresState {
            schema: &self.schema,
            client,
        })
        .await
    }
}

impl TokioPostgresRateLimitStore {
    pub fn new(client: Client) -> Self {
        Self::with_table(client, "rate_limits")
    }

    pub fn with_table(client: Client, table: impl Into<String>) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
            tx_gate: Arc::new(Mutex::new(())),
            names: SqlRateLimitNames::new(table),
        }
    }
}

impl From<&TokioPostgresAdapter> for TokioPostgresRateLimitStore {
    fn from(adapter: &TokioPostgresAdapter) -> Self {
        Self {
            client: Arc::clone(&adapter.client),
            tx_gate: Arc::clone(&adapter.tx_gate),
            names: SqlRateLimitNames::from_schema(&adapter.schema),
        }
    }
}

impl RateLimitStore for TokioPostgresRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move { consume_postgres_rate_limit(self, input).await })
    }
}

impl DbAdapter for TokioPostgresAdapter {
    fn id(&self) -> &str {
        "tokio-postgres"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("tokio-postgres")
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
            let _gate = self.tx_gate.lock().await;
            let client = self.client.lock().await;
            client
                .batch_execute("BEGIN")
                .await
                .map_err(postgres_error)?;
            drop(client);

            let adapter = TokioPostgresTxAdapter {
                client: Arc::clone(&self.client),
                schema: Arc::clone(&self.schema),
            };
            let result = callback(Box::new(adapter)).await;

            let client = self.client.lock().await;
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
            let _gate = self.tx_gate.lock().await;
            let client = self.client.lock().await;
            create_schema(&client, schema).await?;
            Ok(None)
        })
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let _gate = self.tx_gate.lock().await;
            let client = self.client.lock().await;
            execute_migration_plan(&client, schema).await
        })
    }
}

struct TokioPostgresTxAdapter {
    client: Arc<Mutex<Client>>,
    schema: Arc<DbSchema>,
}

impl TokioPostgresTxAdapter {
    async fn run_with_state<T>(
        &self,
        f: impl for<'a> FnOnce(TokioPostgresState<'a>) -> AdapterFuture<'a, T> + Send,
    ) -> Result<T, OpenAuthError>
    where
        T: Send + 'static,
    {
        let client = self.client.lock().await;
        f(TokioPostgresState {
            schema: &self.schema,
            client,
        })
        .await
    }
}

impl DbAdapter for TokioPostgresTxAdapter {
    fn id(&self) -> &str {
        "tokio-postgres-tx"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("tokio-postgres transaction")
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
                "nested tokio-postgres transactions are not supported".to_owned(),
            ))
        })
    }
}

async fn consume_postgres_rate_limit(
    store: &TokioPostgresRateLimitStore,
    input: RateLimitConsumeInput,
) -> Result<RateLimitDecision, OpenAuthError> {
    let plan = postgres_rate_limit_plan(
        &store.names.table,
        &store.names.key,
        &store.names.count,
        &store.names.last_request,
    )?;
    let _gate = store.tx_gate.lock().await;
    let client = store.client.lock().await;
    client
        .batch_execute("BEGIN")
        .await
        .map_err(postgres_error)?;
    let result = consume_postgres_rate_limit_in_tx(&client, &plan, input).await;
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

pub use self::migration::{
    ColumnToAdd, IndexToCreate, MigrationStatement, MigrationStatementKind, SchemaMigrationPlan,
    SchemaMigrationWarning, TableToCreate,
};
