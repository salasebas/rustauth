mod errors;
mod foreign_keys;
mod query;
mod row;
mod schema;
mod state;
mod support;

pub use foreign_keys::pool_options;

use std::sync::Arc;

use openauth_core::db::{
    auth_schema, rate_limit_consume_statements, AdapterCapabilities, AdapterFuture,
    AuthSchemaOptions, Count, Create, DbAdapter, DbRecord, DbSchema, Delete, DeleteMany, FindMany,
    FindOne, SchemaCreation, SqlDialect, TransactionCallback, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitRecord, RateLimitStore,
};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use tokio::sync::Mutex;

use self::errors::sql_error;
use self::schema::{create_schema, plan_migrations as plan_schema_migrations};
use self::state::{SqliteExecutor, SqliteState};
use crate::migration::SchemaMigrationPlan;
use crate::{consume_record, count_from_i64, count_to_i64, RateLimitSqlNames};

#[derive(Debug, Clone)]
pub struct SqliteAdapter {
    pool: SqlitePool,
    schema: Arc<DbSchema>,
}

#[derive(Debug, Clone)]
pub struct SqliteRateLimitStore {
    pool: SqlitePool,
    names: RateLimitSqlNames,
}

impl SqliteRateLimitStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_table(pool, "rate_limits")
    }

    pub fn with_table(pool: SqlitePool, table: impl Into<String>) -> Self {
        Self {
            pool,
            names: RateLimitSqlNames::new(table),
        }
    }
}

impl From<&SqliteAdapter> for SqliteRateLimitStore {
    fn from(adapter: &SqliteAdapter) -> Self {
        Self {
            pool: adapter.pool.clone(),
            names: RateLimitSqlNames::from_schema(&adapter.schema),
        }
    }
}

impl RateLimitStore for SqliteRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move { consume_sqlite_rate_limit(&self.pool, &self.names, input).await })
    }
}

async fn consume_sqlite_rate_limit(
    pool: &SqlitePool,
    names: &RateLimitSqlNames,
    input: RateLimitConsumeInput,
) -> Result<RateLimitDecision, OpenAuthError> {
    let plan = rate_limit_consume_statements(
        SqlDialect::Sqlite,
        &names.table,
        &names.key,
        &names.count,
        &names.last_request,
    )?;
    let mut tx = pool.begin().await.map_err(sql_error)?;
    foreign_keys::enable_on_transaction(&mut tx).await?;
    sqlx::query(&plan.insert_ignore.sql)
        .bind(&input.key)
        .bind(input.now_ms)
        .execute(&mut *tx)
        .await
        .map_err(sql_error)?;
    let row = sqlx::query(&plan.select.sql)
        .bind(&input.key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(sql_error)?
        .ok_or_else(|| OpenAuthError::Adapter("missing rate limit row".to_owned()))?;
    let (decision, record, update) = consume_record(input, Some(sqlite_record(row)?));
    if decision.permitted && update {
        sqlx::query(&plan.update.sql)
            .bind(count_to_i64(record.count)?)
            .bind(record.last_request)
            .bind(&record.key)
            .execute(&mut *tx)
            .await
            .map_err(sql_error)?;
    }
    tx.commit().await.map_err(sql_error)?;
    Ok(decision)
}

fn sqlite_record(row: sqlx::sqlite::SqliteRow) -> Result<RateLimitRecord, OpenAuthError> {
    Ok(RateLimitRecord {
        key: String::new(),
        count: count_from_i64(row.get::<i64, _>("count"))?,
        last_request: row.get("last_request"),
    })
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
        let pool = foreign_keys::pool_options()
            .connect(database_url)
            .await
            .map_err(sql_error)?;
        Ok(Self::with_schema(pool, schema))
    }

    pub async fn plan_migrations(
        &self,
        schema: &DbSchema,
    ) -> Result<SchemaMigrationPlan, OpenAuthError> {
        plan_schema_migrations(SqliteExecutor::Pool(&self.pool), schema).await
    }

    pub async fn compile_migrations(&self, schema: &DbSchema) -> Result<String, OpenAuthError> {
        Ok(self.plan_migrations(schema).await?.compile())
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
            .with_native_joins()
            .with_transactions()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move { self.state().create(query).await })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move { self.state().find_one(query).await })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move { self.state().find_many(query).await })
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
            let mut tx = self.pool.begin().await.map_err(sql_error)?;
            foreign_keys::enable_on_transaction(&mut tx).await?;
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
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        Box::pin(async move {
            let code = if file.is_some() {
                Some(self.compile_migrations(schema).await?)
            } else {
                None
            };
            create_schema(SqliteExecutor::Pool(&self.pool), schema).await?;
            match (file, code) {
                (Some(path), Some(code)) => {
                    Ok(Some(crate::migration::write_schema_file(path, code).await?))
                }
                _ => Ok(None),
            }
        })
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let plan = plan_schema_migrations(SqliteExecutor::Pool(&self.pool), schema).await?;
            crate::migration::ensure_executable(&plan)?;
            let mut tx = self.pool.begin().await.map_err(sql_error)?;
            foreign_keys::enable_on_transaction(&mut tx).await?;
            for statement in &plan.statements {
                sqlx::query(&statement.sql)
                    .execute(&mut *tx)
                    .await
                    .map_err(sql_error)?;
            }
            tx.commit().await.map_err(sql_error)?;
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
            .with_native_joins()
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
