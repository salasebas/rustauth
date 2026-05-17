//! Shared tokio-postgres driver helpers for Postgres-based OpenAuth adapters.

use openauth_core::db::{
    consume_sql_rate_limit_record, rate_limit_consume_statements, AdapterFuture, Count, Create,
    DbField, DbRecord, DbSchema, DbValue, Delete, DeleteMany, FindMany, FindOne, SqlAdapterRunner,
    SqlDialect, SqlExecutor, SqlRateLimitPlan, SqlRowReader, SqlStatement, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{RateLimitConsumeInput, RateLimitDecision, RateLimitRecord};
use tokio_postgres::{Client, Row};

pub use crate::errors::{json_error, postgres_error};
pub use crate::query::{param_refs, postgres_params};
pub use crate::row::row_value_at;
pub use crate::schema::{
    create_schema, execute_migration_plan, plan_migrations, PostgresSchemaExecutor,
};

/// Shared Postgres executor state for adapters backed by `tokio-postgres`.
pub struct PostgresSqlState<'a> {
    schema: &'a DbSchema,
    client: &'a Client,
}

impl<'a> PostgresSqlState<'a> {
    pub fn new(schema: &'a DbSchema, client: &'a Client) -> Self {
        Self { schema, client }
    }

    pub async fn create(self, query: Create) -> Result<DbRecord, OpenAuthError> {
        postgres_runner(self).create(query).await
    }

    pub async fn find_one(self, query: FindOne) -> Result<Option<DbRecord>, OpenAuthError> {
        postgres_runner(self).find_one(query).await
    }

    pub async fn find_many(self, query: FindMany) -> Result<Vec<DbRecord>, OpenAuthError> {
        postgres_runner(self).find_many(query).await
    }

    pub async fn count(self, query: Count) -> Result<u64, OpenAuthError> {
        postgres_runner(self).count(query).await
    }

    pub async fn update(self, query: Update) -> Result<Option<DbRecord>, OpenAuthError> {
        postgres_runner(self).update(query).await
    }

    pub async fn update_many(self, query: UpdateMany) -> Result<u64, OpenAuthError> {
        postgres_runner(self).update_many(query).await
    }

    pub async fn delete(self, query: Delete) -> Result<(), OpenAuthError> {
        postgres_runner(self).delete(query).await
    }

    pub async fn delete_many(self, query: DeleteMany) -> Result<u64, OpenAuthError> {
        postgres_runner(self).delete_many(query).await
    }
}

impl SqlExecutor for PostgresSqlState<'_> {
    type Row = Row;

    fn execute<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let values = postgres_params(&statement.params)?;
            let params = param_refs(&values);
            self.client
                .execute(&statement.sql, &params)
                .await
                .map_err(postgres_error)
        })
    }

    fn fetch_all<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, Vec<Self::Row>> {
        Box::pin(async move {
            let values = postgres_params(&statement.params)?;
            let params = param_refs(&values);
            self.client
                .query(&statement.sql, &params)
                .await
                .map_err(postgres_error)
        })
    }

    fn fetch_optional<'a>(
        &'a mut self,
        statement: SqlStatement,
    ) -> AdapterFuture<'a, Option<Self::Row>> {
        Box::pin(async move {
            let values = postgres_params(&statement.params)?;
            let params = param_refs(&values);
            self.client
                .query_opt(&statement.sql, &params)
                .await
                .map_err(postgres_error)
        })
    }

    fn fetch_scalar_i64<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, i64> {
        Box::pin(async move {
            let values = postgres_params(&statement.params)?;
            let params = param_refs(&values);
            let row = self
                .client
                .query_one(&statement.sql, &params)
                .await
                .map_err(postgres_error)?;
            Ok(row.get::<_, i64>(0))
        })
    }
}

/// Shared Postgres row reader for OpenAuth SQL-selected fields.
pub struct PostgresRowReader;

impl SqlRowReader<Row> for PostgresRowReader {
    fn value_at(&self, row: &Row, field: &DbField, alias: &str) -> Result<DbValue, OpenAuthError> {
        row_value_at(row, field, alias)
    }
}

pub fn postgres_runner<'a>(
    state: PostgresSqlState<'a>,
) -> SqlAdapterRunner<'a, PostgresSqlState<'a>, PostgresRowReader> {
    SqlAdapterRunner::new(SqlDialect::Postgres, state.schema, state, PostgresRowReader)
}

/// Builds the shared Postgres rate-limit SQL plan.
pub fn postgres_rate_limit_plan(
    table: &str,
    key: &str,
    count: &str,
    last_request: &str,
) -> Result<SqlRateLimitPlan, OpenAuthError> {
    rate_limit_consume_statements(SqlDialect::Postgres, table, key, count, last_request)
}

/// Consumes one rate-limit record inside an already-open Postgres transaction.
pub async fn consume_postgres_rate_limit_in_tx(
    client: &Client,
    plan: &SqlRateLimitPlan,
    input: RateLimitConsumeInput,
) -> Result<RateLimitDecision, OpenAuthError> {
    client
        .execute(&plan.insert_ignore.sql, &[&input.key, &input.now_ms])
        .await
        .map_err(postgres_error)?;
    let row = client
        .query_opt(&plan.select.sql, &[&input.key])
        .await
        .map_err(postgres_error)?
        .ok_or_else(|| OpenAuthError::Adapter("missing rate limit row".to_owned()))?;
    let (decision, record, update) =
        consume_sql_rate_limit_record(input, Some(postgres_rate_limit_record(row)));
    if decision.permitted && update {
        let count = record.count as i64;
        client
            .execute(
                &plan.update.sql,
                &[&count, &record.last_request, &record.key],
            )
            .await
            .map_err(postgres_error)?;
    }
    Ok(decision)
}

/// Decodes the canonical OpenAuth rate-limit fields from a Postgres row.
pub fn postgres_rate_limit_record(row: Row) -> RateLimitRecord {
    RateLimitRecord {
        key: String::new(),
        count: row.get::<_, i64>("count") as u64,
        last_request: row.get("last_request"),
    }
}

/// Plans migrations for the current connection and target schema.
pub async fn plan_schema_migrations(
    client: &Client,
    schema: &DbSchema,
) -> Result<crate::migration::SchemaMigrationPlan, OpenAuthError> {
    plan_migrations(client, schema).await
}
