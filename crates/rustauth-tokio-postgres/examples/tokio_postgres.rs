use rustauth_core::db::{auth_schema, AuthSchemaOptions, DbAdapter, RateLimitStorage};
use rustauth_tokio_postgres::TokioPostgresStores;

#[tokio::main]
async fn main() -> Result<(), rustauth_core::error::RustAuthError> {
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });
    let stores = TokioPostgresStores::connect_with_schema(
        "postgres://user:password@localhost/rustauth",
        schema.clone(),
    )
    .await?;

    // Apply schema with `rustauth db migrate` or `adapter.run_migrations` before serving traffic.
    stores.adapter_ref().run_migrations(&schema).await?;
    let _options = stores.apply_to_options(rustauth_core::options::RustAuthOptions::default());
    Ok(())
}
