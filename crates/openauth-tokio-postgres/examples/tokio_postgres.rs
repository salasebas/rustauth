use openauth_core::db::{auth_schema, AuthSchemaOptions, DbAdapter, RateLimitStorage};
use openauth_tokio_postgres::TokioPostgresAdapter;

#[tokio::main]
async fn main() -> Result<(), openauth_core::error::OpenAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });
    let adapter = TokioPostgresAdapter::connect_with_schema(
        "postgres://user:password@localhost/openauth",
        schema.clone(),
    )
    .await?;

    adapter.run_migrations(&schema).await?;
    let _rate_limit_store = adapter.rate_limit_store();
    Ok(())
}
