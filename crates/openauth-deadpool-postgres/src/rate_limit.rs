use deadpool_postgres::Pool;
use openauth_core::db::SqlRateLimitNames;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitStore,
};
use openauth_tokio_postgres::driver::{
    consume_postgres_rate_limit_in_tx, postgres_error, postgres_rate_limit_plan,
};

use crate::adapter::DeadpoolPostgresAdapter;
use crate::config::{deadpool_error, pg_client};

/// Database-backed rate-limit store backed by a `deadpool-postgres` pool.
#[derive(Clone)]
pub struct DeadpoolPostgresRateLimitStore {
    pub(crate) pool: Pool,
    pub(crate) names: SqlRateLimitNames,
}

impl std::fmt::Debug for DeadpoolPostgresRateLimitStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeadpoolPostgresRateLimitStore")
            .field("names", &self.names)
            .finish_non_exhaustive()
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
