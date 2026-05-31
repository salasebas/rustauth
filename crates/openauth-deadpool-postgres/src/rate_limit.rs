use std::sync::Arc;

use deadpool_postgres::Pool;
use openauth_core::db::SqlRateLimitNames;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitStore,
};
use openauth_tokio_postgres::driver::{
    consume_postgres_rate_limit_in_tx, postgres_error, postgres_rate_limit_plan,
};
use tokio::sync::Mutex;

use crate::adapter::DeadpoolPostgresAdapter;
use crate::config::{deadpool_error, pg_client};
use crate::tx_guard::PooledClientRollbackGuard;

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
        Self::with_names(pool, SqlRateLimitNames::new(table))
    }

    pub fn with_names(pool: Pool, names: SqlRateLimitNames) -> Self {
        Self { pool, names }
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
    let client = Arc::new(Mutex::new(client));
    let mut guard = PooledClientRollbackGuard::new(Arc::clone(&client));
    let locked = client.lock().await;
    let result = consume_postgres_rate_limit_in_tx(pg_client(&locked), &plan, input).await;
    match result {
        Ok(decision) => {
            if let Err(error) = locked.batch_execute("COMMIT").await {
                let _rollback_result = locked.batch_execute("ROLLBACK").await;
                guard.disarm();
                return Err(postgres_error(error));
            }
            guard.disarm();
            Ok(decision)
        }
        Err(error) => {
            let _rollback_result = locked.batch_execute("ROLLBACK").await;
            guard.disarm();
            Err(error)
        }
    }
}
