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
