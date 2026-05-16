use openauth_core::db::{auth_schema, AuthSchemaOptions, DbAdapter, RateLimitStorage};
use openauth_deadpool_postgres::{DeadpoolPostgresAdapter, DeadpoolPostgresRateLimitStore};

#[tokio::main]
async fn main() -> Result<(), openauth_core::error::OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });
    let adapter = DeadpoolPostgresAdapter::connect_with_schema(
        "postgres://user:password@localhost/openauth",
        schema.clone(),
    )
    .await?;

    adapter.run_migrations(&schema).await?;
    let _rate_limit_store = DeadpoolPostgresRateLimitStore::from(&adapter);
    Ok(())
}
