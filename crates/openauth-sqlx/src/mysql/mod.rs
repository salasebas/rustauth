mod errors;
mod query;
mod row;
mod schema;
mod state;
mod support;

use std::sync::Arc;

use openauth_core::db::{
    auth_schema, rate_limit_consume_statements, AdapterCapabilities, AdapterFuture,
    AuthSchemaOptions, Count, Create, DbAdapter, DbRecord, DbSchema, Delete, DeleteMany, FindMany,
    FindOne, JoinAdapter, SchemaCreation, SqlDialect, TransactionCallback, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitRecord, RateLimitStore,
};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{MySql, MySqlPool, Row, Transaction};
use tokio::sync::Mutex;

use self::errors::{inactive_transaction, sql_error};
use self::schema::{
    create_schema, execute_migration_plan, plan_migrations as plan_schema_migrations,
};
use self::state::{MySqlExecutor, MySqlState};
use crate::migration::SchemaMigrationPlan;
use crate::{consume_record, RateLimitSqlNames};

#[derive(Debug, Clone)]
pub struct MySqlAdapter {
    pool: MySqlPool,
    schema: Arc<DbSchema>,
}

#[derive(Debug, Clone)]
pub struct MySqlRateLimitStore {
    pool: MySqlPool,
    names: RateLimitSqlNames,
}

impl MySqlRateLimitStore {
    pub fn new(pool: MySqlPool) -> Self {
        Self::with_table(pool, "rate_limits")
    }

    pub fn with_table(pool: MySqlPool, table: impl Into<String>) -> Self {
        Self {
            pool,
            names: RateLimitSqlNames::new(table),
        }
    }
}

impl From<&MySqlAdapter> for MySqlRateLimitStore {
    fn from(adapter: &MySqlAdapter) -> Self {
        Self {
            pool: adapter.pool.clone(),
            names: RateLimitSqlNames::from_schema(&adapter.schema),
        }
    }
}

impl RateLimitStore for MySqlRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move { consume_mysql_rate_limit(&self.pool, &self.names, input).await })
    }
}

async fn consume_mysql_rate_limit(
    pool: &MySqlPool,
    names: &RateLimitSqlNames,
    input: RateLimitConsumeInput,
) -> Result<RateLimitDecision, OpenAuthError> {
    let plan = rate_limit_consume_statements(
        SqlDialect::MySql,
        &names.table,
        &names.key,
        &names.count,
        &names.last_request,
    )?;
    let mut tx = pool.begin().await.map_err(sql_error)?;
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
    let (decision, record, update) = consume_record(input, Some(mysql_record(row)));
    if decision.permitted && update {
        sqlx::query(&plan.update.sql)
            .bind(record.count as i64)
            .bind(record.last_request)
            .bind(&record.key)
            .execute(&mut *tx)
            .await
            .map_err(sql_error)?;
    }
    tx.commit().await.map_err(sql_error)?;
    Ok(decision)
}

fn mysql_record(row: sqlx::mysql::MySqlRow) -> RateLimitRecord {
    RateLimitRecord {
        key: String::new(),
        count: row.get::<i64, _>("count") as u64,
        last_request: row.get("last_request"),
    }
}

impl MySqlAdapter {
    pub fn new(pool: MySqlPool) -> Self {
        Self::with_schema(pool, auth_schema(AuthSchemaOptions::default()))
    }

    pub fn with_schema(pool: MySqlPool, schema: DbSchema) -> Self {
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
        let pool = MySqlPoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sql_error)?;
        Ok(Self::with_schema(pool, schema))
    }

    pub async fn plan_migrations(
        &self,
        schema: &DbSchema,
    ) -> Result<SchemaMigrationPlan, OpenAuthError> {
        plan_schema_migrations(MySqlExecutor::Pool(&self.pool), schema).await
    }

    pub async fn compile_migrations(&self, schema: &DbSchema) -> Result<String, OpenAuthError> {
        Ok(self.plan_migrations(schema).await?.compile())
    }

    fn state(&self) -> MySqlState<'_, '_> {
        MySqlState {
            schema: &self.schema,
            executor: MySqlExecutor::Pool(&self.pool),
        }
    }
}

impl DbAdapter for MySqlAdapter {
    fn id(&self) -> &str {
        "sqlx-mysql"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("SQLx MySQL")
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
            let adapter = Arc::new(MySqlTxAdapter {
                schema: Arc::clone(&self.schema),
                tx: Mutex::new(Some(tx)),
            });
            let result = callback(Box::new(Arc::clone(&adapter))).await;
            let mut guard = adapter.tx.lock().await;
            let Some(tx) = guard.take() else {
                return Err(OpenAuthError::Adapter(
                    "mysql transaction was already completed".to_owned(),
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
            create_schema(MySqlExecutor::Pool(&self.pool), schema).await?;
            Ok(None)
        })
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let plan = plan_schema_migrations(MySqlExecutor::Pool(&self.pool), schema).await?;
            let mut executor = MySqlExecutor::Pool(&self.pool);
            execute_migration_plan(&mut executor, &plan).await?;
            Ok(())
        })
    }
}

struct MySqlTxAdapter<'tx> {
    schema: Arc<DbSchema>,
    tx: Mutex<Option<Transaction<'tx, MySql>>>,
}

impl DbAdapter for MySqlTxAdapter<'_> {
    fn id(&self) -> &str {
        "sqlx-mysql"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("SQLx MySQL")
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

impl<'tx> MySqlTxAdapter<'tx> {
    async fn state<'a>(&'a self) -> Result<MySqlState<'a, 'tx>, OpenAuthError> {
        let guard = self.tx.lock().await;
        if guard.is_none() {
            return Err(inactive_transaction());
        }
        Ok(MySqlState {
            schema: &self.schema,
            executor: MySqlExecutor::Transaction(guard),
        })
    }
}
