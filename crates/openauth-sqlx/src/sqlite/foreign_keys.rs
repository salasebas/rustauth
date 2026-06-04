use openauth_core::error::OpenAuthError;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Executor, Sqlite, SqlitePool, Transaction};

use super::errors::sql_error;

/// Recommended [`SqlitePoolOptions`] for OpenAuth SQLite adapters.
///
/// Enables `PRAGMA foreign_keys = ON` on every connection checked out from the pool.
pub fn pool_options() -> SqlitePoolOptions {
    SqlitePoolOptions::new().after_connect(|connection, _metadata| {
        Box::pin(async move {
            connection.execute("PRAGMA foreign_keys = ON").await?;
            Ok(())
        })
    })
}

pub(super) async fn acquire_with_foreign_keys(
    pool: &SqlitePool,
) -> Result<PoolConnection<Sqlite>, sqlx::Error> {
    let mut connection = pool.acquire().await?;
    connection
        .execute("PRAGMA foreign_keys = ON")
        .await
        .map(|_| ())?;
    Ok(connection)
}

pub(super) async fn enable_on_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<(), OpenAuthError> {
    transaction
        .execute("PRAGMA foreign_keys = ON")
        .await
        .map(|_| ())
        .map_err(sql_error)
}

/// Starts a write transaction that acquires SQLite's reserved lock immediately.
///
/// Rate-limit consumes must use this instead of a deferred `BEGIN` so concurrent
/// pool connections cannot read stale counts before another transaction commits.
pub(super) async fn begin_immediate_transaction(
    pool: &SqlitePool,
) -> Result<Transaction<'_, Sqlite>, OpenAuthError> {
    let connection = acquire_with_foreign_keys(pool).await.map_err(sql_error)?;
    Transaction::begin(connection, Some("BEGIN IMMEDIATE".into()))
        .await
        .map_err(sql_error)
}
