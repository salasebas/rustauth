//! Shared tokio-postgres driver helpers for Postgres-based OpenAuth adapters.

use openauth_core::db::{
    consume_sql_rate_limit_record, rate_limit_consume_statements, DbSchema, SqlDialect,
    SqlRateLimitPlan,
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
