//! Deadpool Postgres connection for durable users, sessions, and plugin data.

use rustauth::db::DbSchema;
use rustauth_deadpool_postgres::DeadpoolPostgresStores;

use crate::error::AppResult;

/// Open a checked Deadpool Postgres stores bundle against the plugin-augmented schema.
pub async fn connect_postgres(
    database_url: &str,
    schema: DbSchema,
) -> AppResult<DeadpoolPostgresStores> {
    Ok(DeadpoolPostgresStores::connect_with_schema_checked(database_url, schema).await?)
}
