use std::fmt;
use std::sync::Arc;

use openauth_core::db::SqlRateLimitNames;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitStore,
};
use tokio::sync::RwLock;
use tokio_postgres::Client;

use crate::adapter::TokioPostgresAdapter;
use crate::driver::{consume_postgres_rate_limit_in_tx, postgres_rate_limit_plan};
use crate::errors::postgres_error;

#[derive(Clone)]
pub struct TokioPostgresRateLimitStore {
    client: Arc<Client>,
    tx_gate: Arc<RwLock<()>>,
    names: SqlRateLimitNames,
}

impl fmt::Debug for TokioPostgresRateLimitStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokioPostgresRateLimitStore")
            .field("names", &self.names)
            .finish_non_exhaustive()
    }
}

impl TokioPostgresRateLimitStore {
    pub fn new(client: Client) -> Self {
        Self::with_table(client, "rate_limits")
    }

    pub fn with_table(client: Client, table: impl Into<String>) -> Self {
        Self {
            client: Arc::new(client),
            tx_gate: Arc::new(RwLock::new(())),
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
    let _gate = store.tx_gate.write().await;
    store
        .client
        .batch_execute("BEGIN")
        .await
        .map_err(postgres_error)?;
    let result = consume_postgres_rate_limit_in_tx(store.client.as_ref(), &plan, input).await;
    match result {
        Ok(decision) => {
            if let Err(error) = store.client.batch_execute("COMMIT").await {
                let _rollback_result = store.client.batch_execute("ROLLBACK").await;
                return Err(postgres_error(error));
            }
            Ok(decision)
        }
        Err(error) => {
            let _rollback_result = store.client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}
