mod errors;
mod joins;
mod query;
mod row;
mod schema;
mod state;
mod support;

use std::sync::Arc;

use openauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, AuthSchemaOptions, Count, Create, DbAdapter,
    DbRecord, DbSchema, Delete, DeleteMany, FindMany, FindOne, JoinAdapter, SchemaCreation,
    TransactionCallback, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Mutex;

use self::errors::{inactive_transaction, sql_error};
use self::schema::create_schema;
use self::state::{PostgresExecutor, PostgresState};

#[derive(Debug, Clone)]
pub struct PostgresAdapter {
    pool: PgPool,
    schema: Arc<DbSchema>,
}

impl PostgresAdapter {
    pub fn new(pool: PgPool) -> Self {
        Self::with_schema(pool, auth_schema(AuthSchemaOptions::default()))
    }

    pub fn with_schema(pool: PgPool, schema: DbSchema) -> Self {
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
        let pool = PgPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sql_error)?;
        Ok(Self::with_schema(pool, schema))
    }

    fn state(&self) -> PostgresState<'_, '_> {
        PostgresState {
            schema: &self.schema,
            executor: PostgresExecutor::Pool(&self.pool),
        }
    }
}

impl DbAdapter for PostgresAdapter {
    fn id(&self) -> &str {
        "sqlx-postgres"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("SQLx Postgres")
            .with_uuid_ids()
            .with_json()
            .with_arrays()
            .with_joins()
            .with_transactions()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move { self.state().create(query).await })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move { self.state().find_one(query).await })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            if query.joins.len() <= 1 {
                self.state().find_many(query).await
            } else {
                let adapter =
                    JoinAdapter::new(self.schema.as_ref().clone(), Arc::new(self.clone()), false);
                adapter.find_many(query).await
            }
        })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().count(query).await })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move { self.state().update(query).await })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().update_many(query).await })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move { self.state().delete(query).await })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().delete_many(query).await })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let tx = self.pool.begin().await.map_err(sql_error)?;
            let adapter = Arc::new(PostgresTxAdapter {
                schema: Arc::clone(&self.schema),
                tx: Mutex::new(Some(tx)),
            });
            let result = callback(Box::new(Arc::clone(&adapter))).await;
            let mut guard = adapter.tx.lock().await;
            let Some(tx) = guard.take() else {
                return Err(OpenAuthError::Adapter(
                    "postgres transaction was already completed".to_owned(),
                ));
            };
            drop(guard);
            match result {
                Ok(()) => tx.commit().await.map_err(sql_error),
                Err(error) => {
                    let _rollback_result = tx.rollback().await;
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
            create_schema(PostgresExecutor::Pool(&self.pool), schema).await?;
            Ok(None)
        })
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.create_schema(schema, None).await?;
            Ok(())
        })
    }
}

struct PostgresTxAdapter<'tx> {
    schema: Arc<DbSchema>,
    tx: Mutex<Option<Transaction<'tx, Postgres>>>,
}

impl DbAdapter for PostgresTxAdapter<'_> {
    fn id(&self) -> &str {
        "sqlx-postgres"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("SQLx Postgres")
            .with_uuid_ids()
            .with_json()
            .with_arrays()
            .with_transactions()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move { self.state().await?.create(query).await })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move { self.state().await?.find_one(query).await })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move { self.state().await?.find_many(query).await })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().await?.count(query).await })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move { self.state().await?.update(query).await })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().await?.update_many(query).await })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move { self.state().await?.delete(query).await })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().await?.delete_many(query).await })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        callback(Box::new(self))
    }
}

impl<'tx> PostgresTxAdapter<'tx> {
    async fn state<'a>(&'a self) -> Result<PostgresState<'a, 'tx>, OpenAuthError> {
        let guard = self.tx.lock().await;
        if guard.is_none() {
            return Err(inactive_transaction());
        }
        Ok(PostgresState {
            schema: &self.schema,
            executor: PostgresExecutor::Transaction(guard),
        })
    }
}
