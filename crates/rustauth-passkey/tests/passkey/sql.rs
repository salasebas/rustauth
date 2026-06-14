use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustauth_core::context::create_auth_context;
use rustauth_core::db::DbAdapter;
use rustauth_core::options::RustAuthOptions;
use rustauth_passkey::{passkey, PasskeyOptions};

static TEST_ID: AtomicU64 = AtomicU64::new(0);

const DEFAULT_POSTGRES_URL: &str = "postgres://user:password@localhost:5432/rustauth";
const DEFAULT_MYSQL_URL: &str = "mysql://user:password@localhost:3306/rustauth";

#[tokio::test]
#[ignore = "requires Docker Compose: docker compose up -d postgres"]
async fn postgres_schema_migration_creates_unique_credential_id_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let table = unique_table("passkeys_pg");
    let context = passkey_context(&table)?;
    let url = std::env::var("RUSTAUTH_TEST_POSTGRES_URL")
        .unwrap_or_else(|_| DEFAULT_POSTGRES_URL.to_owned());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let schema = context.db_schema.clone();
    let adapter = rustauth_sqlx::PostgresAdapter::with_schema(pool.clone(), schema.clone());

    adapter.create_schema(&schema, None).await?;

    let unique_indexes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_indexes \
         WHERE schemaname = current_schema() \
         AND tablename = $1 \
         AND indexdef ILIKE '%UNIQUE%' \
         AND indexdef ILIKE '%credential_id%'",
    )
    .bind(&table)
    .fetch_one(&pool)
    .await?;
    assert_eq!(unique_indexes, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker Compose: docker compose up -d mysql"]
async fn mysql_schema_migration_creates_unique_credential_id_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let table = unique_table("passkeys_my");
    let context = passkey_context(&table)?;
    let url =
        std::env::var("RUSTAUTH_TEST_MYSQL_URL").unwrap_or_else(|_| DEFAULT_MYSQL_URL.to_owned());
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let schema = context.db_schema.clone();
    let adapter = rustauth_sqlx::MySqlAdapter::with_schema(pool.clone(), schema.clone());

    adapter.create_schema(&schema, None).await?;

    let unique_indexes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.statistics \
         WHERE table_schema = DATABASE() \
         AND table_name = ? \
         AND column_name = 'credential_id' \
         AND non_unique = 0",
    )
    .bind(&table)
    .fetch_one(&pool)
    .await?;
    assert_eq!(unique_indexes, 1);
    Ok(())
}

fn passkey_context(
    table: &str,
) -> Result<rustauth_core::context::AuthContext, rustauth_core::error::RustAuthError> {
    create_auth_context(RustAuthOptions {
        plugins: vec![passkey(PasskeyOptions::default().passkey_table(table))],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    })
}

fn unique_table(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or_default();
    let process = std::process::id() & 0xffff;
    let sequence = TEST_ID.fetch_add(1, Ordering::Relaxed) & 0xfff;
    format!(
        "{prefix}_{process:x}_{:08x}_{sequence:x}",
        nanos & 0xffff_ffff
    )
}
