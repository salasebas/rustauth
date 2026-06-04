use std::fmt;
use std::sync::Arc;

use openauth_core::db::SqlRateLimitNames;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitStore,
};

use crate::adapter::TokioPostgresAdapter;
use crate::connection::TokioPostgresConnection;
use crate::driver::{consume_postgres_rate_limit_in_tx, postgres_error, postgres_rate_limit_plan};
use crate::tx_guard::SharedClientRollbackGuard;

#[derive(Clone)]
pub struct TokioPostgresRateLimitStore {
    connection: TokioPostgresConnection,
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
    /// Builds a rate-limit store from a shared connection bundle.
    pub fn from_connection(connection: &TokioPostgresConnection, table: impl Into<String>) -> Self {
        Self {
            connection: connection.clone(),
            names: SqlRateLimitNames::new(table),
        }
    }

    /// Connects for rate-limit-only usage when no [`TokioPostgresAdapter`] is needed.
    pub async fn connect(
        database_url: &str,
        table: impl Into<String>,
    ) -> Result<Self, OpenAuthError> {
        Ok(Self::from_connection(
            &TokioPostgresConnection::connect(database_url).await?,
            table,
        ))
    }

    /// Returns the shared connection used by this store.
    pub fn connection(&self) -> &TokioPostgresConnection {
        &self.connection
    }
}

impl From<&TokioPostgresAdapter> for TokioPostgresRateLimitStore {
    fn from(adapter: &TokioPostgresAdapter) -> Self {
        Self {
            connection: adapter.connection.clone(),
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
    let gate = Arc::clone(&store.connection.tx_gate).write_owned().await;
    store
        .connection
        .client
        .batch_execute("BEGIN")
        .await
        .map_err(postgres_error)?;
    let mut guard = SharedClientRollbackGuard::new(Arc::clone(&store.connection.client), gate);
    let result =
        consume_postgres_rate_limit_in_tx(store.connection.client.as_ref(), &plan, input).await;
    match result {
        Ok(decision) => {
            if let Err(error) = store.connection.client.batch_execute("COMMIT").await {
                let _rollback_result = store.connection.client.batch_execute("ROLLBACK").await;
                guard.disarm();
                return Err(postgres_error(error));
            }
            guard.disarm();
            Ok(decision)
        }
        Err(error) => {
            let _rollback_result = store.connection.client.batch_execute("ROLLBACK").await;
            guard.disarm();
            Err(error)
        }
    }
}
