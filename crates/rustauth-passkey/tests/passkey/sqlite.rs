use rustauth_core::context::create_auth_context;
use rustauth_core::db::DbAdapter;
use rustauth_core::options::RustAuthOptions;
use rustauth_passkey::{passkey, PasskeyOptions, PasskeySchemaOptions};
use rustauth_sqlx::SqliteAdapter;
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn sqlite_schema_migration_creates_passkeys_table_and_columns(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(RustAuthOptions {
        plugins: vec![passkey(PasskeyOptions::default())],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    })?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let adapter = SqliteAdapter::with_schema(pool.clone(), context.db_schema.clone());

    adapter.create_schema(&context.db_schema, None).await?;

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'passkeys'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(table_count, 1);

    let columns = sqlx::query_scalar::<_, String>("SELECT name FROM pragma_table_info('passkeys')")
        .fetch_all(&pool)
        .await?;
    assert!(columns.iter().any(|column| column == "credential_id"));
    assert!(columns.iter().any(|column| column == "webauthn_credential"));
    assert!(columns
        .iter()
        .all(|column| !column.contains(char::is_uppercase)));

    let unique_credential_indexes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_index_list('passkeys') il \
         JOIN pragma_index_info(il.name) ii \
         WHERE il.\"unique\" = 1 AND ii.name = 'credential_id'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(unique_credential_indexes, 1);

    Ok(())
}

#[tokio::test]
async fn sqlite_schema_migration_uses_custom_passkey_schema_names(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(RustAuthOptions {
        plugins: vec![passkey(
            PasskeyOptions::default().schema(
                PasskeySchemaOptions::new()
                    .table_name("auth_passkeys")
                    .field_name("public_key", "publicKey")
                    .field_name("credential_id", "credentialID")
                    .field_name("user_id", "userId"),
            ),
        )],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..RustAuthOptions::default()
    })?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let adapter = SqliteAdapter::with_schema(pool.clone(), context.db_schema.clone());

    adapter.create_schema(&context.db_schema, None).await?;

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'auth_passkeys'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(table_count, 1);

    let columns =
        sqlx::query_scalar::<_, String>("SELECT name FROM pragma_table_info('auth_passkeys')")
            .fetch_all(&pool)
            .await?;
    assert!(columns.iter().any(|column| column == "publicKey"));
    assert!(columns.iter().any(|column| column == "credentialID"));
    assert!(columns.iter().any(|column| column == "userId"));
    assert!(columns.iter().all(|column| column != "public_key"));
    assert!(columns.iter().all(|column| column != "credential_id"));

    let unique_credential_indexes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_index_list('auth_passkeys') il \
         JOIN pragma_index_info(il.name) ii \
         WHERE il.\"unique\" = 1 AND ii.name = 'credentialID'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(unique_credential_indexes, 1);

    Ok(())
}
