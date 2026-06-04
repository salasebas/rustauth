use std::fmt;
use std::sync::Arc;

use openauth_core::error::OpenAuthError;
use tokio::sync::RwLock;
use tokio_postgres::{Client, NoTls};

/// Shared `tokio-postgres` client handle and transaction gate.
///
/// Both [`crate::TokioPostgresAdapter`] and
/// [`crate::TokioPostgresRateLimitStore`] must use the same connection bundle
/// when they operate on the same physical Postgres connection. The gate
/// serializes explicit transactions, schema migrations, and rate-limit
/// consume operations so they cannot interleave on the shared client.
#[derive(Clone)]
pub struct TokioPostgresConnection {
    pub(crate) client: Arc<Client>,
    pub(crate) tx_gate: Arc<RwLock<()>>,
}

impl fmt::Debug for TokioPostgresConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokioPostgresConnection")
            .finish_non_exhaustive()
    }
}

impl TokioPostgresConnection {
    /// Wraps an application-owned client and a fresh transaction gate.
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Arc::new(client),
            tx_gate: Arc::new(RwLock::new(())),
        }
    }

    /// Connects to Postgres and spawns the `tokio-postgres` connection driver.
    pub async fn connect(database_url: &str) -> Result<Self, OpenAuthError> {
        let (client, connection) = tokio_postgres::connect(database_url, NoTls)
            .await
            .map_err(crate::errors::postgres_error)?;
        tokio::spawn(async move {
            let _connection_result = connection.await;
        });
        Ok(Self::from_client(client))
    }

    /// Reuses the client handle with a fresh transaction gate.
    ///
    /// This exists to demonstrate incorrect wiring in tests. Production code
    /// should share one connection bundle instead of duplicating the gate.
    #[doc(hidden)]
    pub fn duplicate_client_unshared_gate(connection: &Self) -> Self {
        Self {
            client: Arc::clone(&connection.client),
            tx_gate: Arc::new(RwLock::new(())),
        }
    }
}
