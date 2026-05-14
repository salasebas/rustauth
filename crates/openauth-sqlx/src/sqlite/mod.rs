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
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Executor, Sqlite, SqlitePool, Transaction};
use tokio::sync::Mutex;

use self::errors::sql_error;
use self::schema::create_schema;
use self::state::{SqliteExecutor, SqliteState};

#[derive(Debug, Clone)]
pub struct SqliteAdapter {
    pool: SqlitePool,
    schema: Arc<DbSchema>,
}

impl SqliteAdapter {
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_schema(pool, auth_schema(AuthSchemaOptions::default()))
    }

    pub fn with_schema(pool: SqlitePool, schema: DbSchema) -> Self {
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
        let pool = SqlitePoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sql_error)?;
        Ok(Self::with_schema(pool, schema))
    }

    fn state(&self) -> SqliteState<'_, '_> {
        SqliteState {
            schema: &self.schema,
            executor: SqliteExecutor::Pool(&self.pool),
        }
    }
}

impl DbAdapter for SqliteAdapter {
    fn id(&self) -> &str {
        "sqlx-sqlite"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("SQLx SQLite")
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
            let adapter = Arc::new(SqliteTxAdapter {
                schema: Arc::clone(&self.schema),
                tx: Mutex::new(Some(tx)),
            });
            let result = callback(Box::new(Arc::clone(&adapter))).await;
            let mut guard = adapter.tx.lock().await;
            let Some(tx) = guard.take() else {
                return Err(OpenAuthError::Adapter(
                    "sqlite transaction was already completed".to_owned(),
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
            self.pool
                .execute("PRAGMA foreign_keys = ON")
                .await
                .map_err(sql_error)?;
            create_schema(SqliteExecutor::Pool(&self.pool), schema).await?;
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

struct SqliteTxAdapter<'tx> {
    schema: Arc<DbSchema>,
    tx: Mutex<Option<Transaction<'tx, Sqlite>>>,
}

impl DbAdapter for SqliteTxAdapter<'_> {
    fn id(&self) -> &str {
        "sqlx-sqlite"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("SQLx SQLite")
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

impl<'tx> SqliteTxAdapter<'tx> {
    async fn state<'a>(&'a self) -> Result<SqliteState<'a, 'tx>, OpenAuthError> {
        let guard = self.tx.lock().await;
        if guard.is_none() {
            return Err(OpenAuthError::Adapter(
                "sqlite transaction is no longer active".to_owned(),
            ));
        }
        Ok(SqliteState {
            schema: &self.schema,
            executor: SqliteExecutor::Transaction(guard),
        })
    }
}
