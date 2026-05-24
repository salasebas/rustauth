use std::sync::Arc;

use deadpool_postgres::{Config, PoolConfig};
use http::{header, Method, Request, StatusCode};
use indexmap::IndexMap;
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::crypto::password::verify_password;
use openauth_core::db::{
    auth_schema, AuthSchemaOptions, Count, Create, DbAdapter, DbField, DbFieldType, DbRecord,
    DbSchema, DbTable, DbValue, DeleteMany, FindMany, FindOne, ForeignKey, IdGeneration, IdPolicy,
    OnDelete, RateLimitStorage, SqlRateLimitNames, TableOptions, Update, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, OpenAuthOptions, RateLimitConsumeInput, RateLimitRule, RateLimitStore,
};
use openauth_deadpool_postgres::migration::{MigrationStatementKind, SchemaMigrationWarning};
use openauth_deadpool_postgres::{DeadpoolPostgresAdapter, DeadpoolPostgresRateLimitStore};
use serde_json::Value;
use time::OffsetDateTime;
use tokio_postgres::NoTls;

#[path = "../../../tests/support/postgres_adapter_conformance.rs"]
mod postgres_adapter_conformance;

use postgres_adapter_conformance as conformance;
use postgres_adapter_conformance::seed_user;

fn database_url() -> String {
    conformance::database_url()
}

fn database_url_from_env(value: Option<String>) -> String {
    conformance::database_url_from_env(value)
}

#[test]
fn database_url_defaults_to_docker_compose_postgres_when_env_is_unset() {
    assert_eq!(
        database_url_from_env(None),
        conformance::DEFAULT_POSTGRES_URL
    );
}

#[test]
fn database_url_allows_postgres_env_override() {
    assert_eq!(
        database_url_from_env(Some("postgres://custom.example.test/db".to_owned())),
        "postgres://custom.example.test/db"
    );
}

async fn adapter() -> Result<DeadpoolPostgresAdapter, OpenAuthError> {
    let schema = test_schema();
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;
    Ok(adapter)
}

async fn raw_client() -> Result<tokio_postgres::Client, OpenAuthError> {
    conformance::raw_client().await
}

fn test_schema() -> DbSchema {
    conformance::test_schema("oa_dpg")
}

fn table_options(prefix: &str, table: &str) -> TableOptions {
    conformance::table_options(prefix, table)
}

fn unique_prefix() -> String {
    conformance::unique_prefix("oa_dpg")
}

fn prefixed_options(prefix: &str) -> AuthSchemaOptions {
    AuthSchemaOptions {
        user: table_options(prefix, "users"),
        account: table_options(prefix, "accounts"),
        session: table_options(prefix, "sessions"),
        verification: table_options(prefix, "verifications"),
        rate_limit: table_options(prefix, "rate_limits"),
        ..AuthSchemaOptions::default()
    }
}

#[tokio::test]
async fn deadpool_postgres_adapter_reports_public_capabilities() -> Result<(), OpenAuthError> {
    let capabilities = adapter().await?.capabilities();

    assert_eq!(capabilities.adapter_id, "deadpool-postgres");
    assert_eq!(
        capabilities.adapter_name.as_deref(),
        Some("deadpool-postgres")
    );
    assert!(capabilities.supports_json);
    assert!(capabilities.supports_arrays);
    assert!(capabilities.supports_joins);
    assert!(capabilities.supports_transactions);
    assert!(capabilities.supports_uuid_ids);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_validate_connection_checks_out_pool() -> Result<(), OpenAuthError>
{
    let adapter = DeadpoolPostgresAdapter::connect_checked(&database_url()).await?;

    adapter.validate_connection().await
}

#[tokio::test]
async fn deadpool_postgres_adapter_plans_and_runs_migrations() -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

    let plan = adapter.plan_migrations(&schema).await?;

    assert!(plan
        .statements
        .iter()
        .any(|statement| statement.kind == MigrationStatementKind::CreateTable));
    adapter.run_migrations(&schema).await?;
    let second_plan = adapter.plan_migrations(&schema).await?;
    assert!(second_plan.is_empty(), "{second_plan:#?}");
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_reports_missing_database_pool_errors(
) -> Result<(), OpenAuthError> {
    let missing_database = format!("missing_{}", unique_prefix());
    let url = format!("postgres://user:password@localhost:5432/{missing_database}");
    let adapter = DeadpoolPostgresAdapter::connect_with_schema(&url, test_schema()).await?;

    let error = match adapter.plan_migrations(&test_schema()).await {
        Ok(_) => {
            return Err(OpenAuthError::Adapter(
                "missing database should fail before planning migrations".to_owned(),
            ));
        }
        Err(error) => error,
    };
    let message = error.to_string();

    assert!(message.contains("deadpool-postgres error"));
    assert!(message.contains("detail:"));
    assert!(message.contains(&missing_database));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_connect_checked_reports_missing_database_pool_errors(
) -> Result<(), OpenAuthError> {
    let missing_database = format!("missing_{}", unique_prefix());
    let url = format!("postgres://user:password@localhost:5432/{missing_database}");

    let error = match DeadpoolPostgresAdapter::connect_checked(&url).await {
        Ok(_) => {
            return Err(OpenAuthError::Adapter(
                "checked connection should fail for missing database".to_owned(),
            ));
        }
        Err(error) => error,
    };
    let message = error.to_string();

    assert!(message.contains("deadpool-postgres error"));
    assert!(message.contains(&missing_database));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_returns_database_generated_uuid_ids() -> Result<(), OpenAuthError>
{
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Uuid).with_database_uuid_support(true),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;

    conformance::assert_returns_database_generated_uuid_ids(
        &adapter,
        format!("ada-{prefix}@example.com"),
    )
    .await
}

#[tokio::test]
async fn deadpool_postgres_adapter_supports_forced_uuid_ids() -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let forced_id = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Uuid)
            .with_database_uuid_support(true)
            .with_force_allow_id(true),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;

    conformance::assert_supports_forced_uuid_ids(
        &adapter,
        forced_id,
        format!("forced-{prefix}@example.com"),
    )
    .await
}

#[tokio::test]
async fn deadpool_postgres_adapter_returns_database_generated_serial_ids(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Serial),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

    let sql = adapter.compile_migrations(&schema).await?;
    assert!(sql.contains("GENERATED BY DEFAULT AS IDENTITY"));
    assert!(!sql.contains("SERIAL"));

    adapter.create_schema(&schema, None).await?;
    conformance::assert_returns_database_generated_serial_ids(
        &adapter,
        format!("serial-{prefix}@example.com"),
    )
    .await
}

#[tokio::test]
async fn deadpool_postgres_adapter_reports_additive_migration_plan() -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let initial = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), initial.clone()).await?;
    adapter.create_schema(&initial, None).await?;

    let updated = auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users").with_field(
            "nickname",
            DbField::new("nickname", DbFieldType::String).indexed(),
        ),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let plan = adapter.plan_migrations(&updated).await?;

    assert!(plan
        .to_be_added
        .iter()
        .any(|column| column.field_logical_name == "nickname"));
    assert!(plan
        .indexes_to_be_created
        .iter()
        .any(|index| index.field_logical_name == "nickname"));
    assert!(!plan
        .warnings
        .contains(&SchemaMigrationWarning::ColumnTypeMismatch {
            table_name: "unused".to_owned(),
            column_name: "unused".to_owned(),
            expected: "unused".to_owned(),
            actual: "unused".to_owned(),
        }));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_plan_migrations_reports_empty_database_tables_in_order(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

    let plan = adapter.plan_migrations(&schema).await?;
    let table_names = plan
        .to_be_created
        .iter()
        .map(|table| table.table_name.clone())
        .collect::<Vec<_>>();

    assert_eq!(
        table_names,
        vec![
            format!("{prefix}_users"),
            format!("{prefix}_sessions"),
            format!("{prefix}_accounts"),
            format!("{prefix}_verifications"),
            format!("{prefix}_rate_limits"),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_plan_migrations_reports_plugin_columns_indexes_and_sql(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let base_schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), base_schema.clone()).await?;
    adapter.run_migrations(&base_schema).await?;

    let mut plugin_schema = base_schema.clone();
    plugin_schema.insert_plugin_field(
        "user",
        "tenant_id".to_owned(),
        DbField::new("tenant_id", DbFieldType::String)
            .optional()
            .indexed(),
    )?;

    let plan = adapter.plan_migrations(&plugin_schema).await?;
    let sql = adapter.compile_migrations(&plugin_schema).await?;

    assert_eq!(plan.to_be_added.len(), 1);
    assert_eq!(plan.to_be_added[0].table_name, format!("{prefix}_users"));
    assert_eq!(plan.to_be_added[0].column_name, "tenant_id");
    assert_eq!(plan.indexes_to_be_created.len(), 1);
    assert!(sql.contains("ALTER TABLE"));
    assert!(sql.contains("ADD COLUMN"));
    assert!(sql.contains("CREATE INDEX"));
    assert!(!sql.contains("DROP"));
    assert!(!sql.contains("RENAME"));
    assert!(!sql.contains("ADD INDEX"));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_compile_migrations_returns_semicolon_for_noop(
) -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.run_migrations(&schema).await?;

    assert_eq!(adapter.compile_migrations(&schema).await?, ";");
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_run_migrations_adds_plugin_columns_to_existing_tables(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let base_schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), base_schema.clone()).await?;
    adapter.run_migrations(&base_schema).await?;

    let mut plugin_schema = base_schema.clone();
    plugin_schema.insert_plugin_field(
        "user",
        "tenant_id".to_owned(),
        DbField::new("tenant_id", DbFieldType::String)
            .optional()
            .indexed(),
    )?;

    adapter.run_migrations(&plugin_schema).await?;
    adapter.run_migrations(&plugin_schema).await?;

    let raw = raw_client().await?;
    let users_table = format!("{prefix}_users");
    let tenant_column_count = raw
        .query_one(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1 \
             AND column_name = 'tenant_id'",
            &[&users_table],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, i64>(0);
    let tenant_index_count = raw
        .query_one(
            "SELECT COUNT(*) FROM pg_indexes \
             WHERE schemaname = current_schema() AND tablename = $1 AND indexname = $2",
            &[&users_table, &format!("idx_{users_table}_tenant_id")],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, i64>(0);

    assert_eq!(tenant_column_count, 1);
    assert_eq!(tenant_index_count, 1);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_run_migrations_creates_plugin_tables_with_indexes_and_foreign_keys(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let users_table = format!("{prefix}_users");
    let plugin_table = format!("{prefix}_plugin_identities");
    let mut schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let mut fields = IndexMap::new();
    fields.insert("id".to_owned(), DbField::new("id", DbFieldType::String));
    fields.insert(
        "user_id".to_owned(),
        DbField::new("user_id", DbFieldType::String)
            .indexed()
            .references(ForeignKey::new(
                users_table.clone(),
                "id",
                OnDelete::Cascade,
            )),
    );
    fields.insert(
        "external_id".to_owned(),
        DbField::new("external_id", DbFieldType::String)
            .optional()
            .indexed(),
    );
    schema.insert_plugin_table(
        "plugin_identity".to_owned(),
        DbTable {
            name: plugin_table.clone(),
            fields,
            order: Some(5),
        },
    )?;
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

    adapter.run_migrations(&schema).await?;

    let raw = raw_client().await?;
    let table_count = raw
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = $1",
            &[&plugin_table],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, i64>(0);
    let external_index_count = raw
        .query_one(
            "SELECT COUNT(*) FROM pg_indexes \
             WHERE schemaname = current_schema() AND tablename = $1 AND indexname = $2",
            &[&plugin_table, &format!("idx_{plugin_table}_external_id")],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, i64>(0);
    let fk_count = raw
        .query_one(
            "SELECT COUNT(*) FROM information_schema.referential_constraints rc \
             JOIN information_schema.key_column_usage kcu \
               ON rc.constraint_schema = kcu.constraint_schema \
              AND rc.constraint_name = kcu.constraint_name \
             WHERE rc.constraint_schema = current_schema() \
               AND kcu.table_name = $1 \
               AND kcu.column_name = 'user_id' \
               AND rc.delete_rule = 'CASCADE'",
            &[&plugin_table],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, i64>(0);

    assert_eq!(table_count, 1);
    assert_eq!(external_index_count, 1);
    assert_eq!(fk_count, 1);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_uses_physical_names_from_auth_schema(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default()
            .with_name(format!("{prefix}_app_users"))
            .with_field_name("email", "primary_email"),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;

    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(false))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
        )
        .await?;
    let record = adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            "email",
            DbValue::String("ada@example.com".to_owned()),
        )))
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing physical-name user".to_owned()))?;
    let raw = raw_client().await?;
    let stored_email = raw
        .query_one(
            &format!("SELECT primary_email FROM {prefix}_app_users LIMIT 1"),
            &[],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, String>(0);

    assert_eq!(
        record.get("email"),
        Some(&DbValue::String("ada@example.com".to_owned()))
    );
    assert_eq!(stored_email, "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_uses_current_schema_for_migration_detection(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema_name = format!("{prefix}_schema");
    let raw = raw_client().await?;
    raw.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS {schema_name} CASCADE; CREATE SCHEMA {schema_name}; \
         CREATE TABLE IF NOT EXISTS public.{prefix}_users (id TEXT PRIMARY KEY)"
    ))
    .await
    .map_err(openauth_tokio_postgres::driver::postgres_error)?;

    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let mut config = Config::new();
    config.url = Some(database_url());
    config.options = Some(format!("-c search_path={schema_name}"));
    let adapter = DeadpoolPostgresAdapter::from_config_with_schema(config, schema.clone(), 2)?;

    let plan = adapter.plan_migrations(&schema).await?;
    assert!(plan
        .to_be_created
        .iter()
        .any(|table| table.table_name == format!("{prefix}_users")));

    adapter.run_migrations(&schema).await?;
    let custom_table_count = raw
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = $1 AND table_name = $2",
            &[&schema_name, &format!("{prefix}_users")],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, i64>(0);
    assert_eq!(custom_table_count, 1);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_reports_type_mismatch_and_repairs_missing_index(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users").with_field(
            "nickname",
            DbField::new("nickname", DbFieldType::String).indexed(),
        ),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let raw = raw_client().await?;
    raw.batch_execute(&format!(
        "CREATE TABLE {prefix}_users (id TEXT PRIMARY KEY, email INTEGER)"
    ))
    .await
    .map_err(openauth_tokio_postgres::driver::postgres_error)?;
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

    let initial = adapter.plan_migrations(&schema).await?;
    assert!(initial.warnings.iter().any(|warning| {
        matches!(
            warning,
            SchemaMigrationWarning::ColumnTypeMismatch {
                column_name,
                actual,
                ..
            } if column_name == "email" && actual == "integer"
        )
    }));
    assert!(initial
        .indexes_to_be_created
        .iter()
        .any(|index| index.field_logical_name == "nickname"));

    adapter.run_migrations(&schema).await?;
    assert!(!adapter
        .plan_migrations(&schema)
        .await?
        .indexes_to_be_created
        .iter()
        .any(|index| index.field_logical_name == "nickname"));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_round_trips_json_arrays_and_create_select(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users")
            .with_field("profile", DbField::new("profile", DbFieldType::Json))
            .with_field("tags", DbField::new("tags", DbFieldType::StringArray))
            .with_field("scores", DbField::new("scores", DbFieldType::NumberArray)),
        account: table_options(&prefix, "accounts"),
        session: table_options(&prefix, "sessions"),
        verification: table_options(&prefix, "verifications"),
        rate_limit: table_options(&prefix, "rate_limits"),
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;
    conformance::assert_round_trips_json_arrays_and_create_select(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_adapter_creates_native_postgres_array_columns(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let table = format!("{prefix}_users");
    let schema = auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users")
            .with_field("tags", DbField::new("tags", DbFieldType::StringArray))
            .with_field("scores", DbField::new("scores", DbFieldType::NumberArray)),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;

    let raw = raw_client().await?;
    let rows = raw
        .query(
            "SELECT column_name, data_type, udt_name FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1 \
             AND column_name IN ('tags', 'scores')",
            &[&table],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?;
    let columns = rows
        .into_iter()
        .map(|row| {
            (
                row.get::<_, String>("column_name"),
                row.get::<_, String>("data_type"),
                row.get::<_, String>("udt_name"),
            )
        })
        .collect::<Vec<_>>();

    assert!(columns.iter().any(|(name, data_type, udt_name)| {
        name == "tags" && data_type == "ARRAY" && udt_name == "_text"
    }));
    assert!(columns.iter().any(|(name, data_type, udt_name)| {
        name == "scores" && data_type == "ARRAY" && udt_name == "_int8"
    }));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_accepts_explicit_tls_connector_api() -> Result<(), OpenAuthError>
{
    let schema = test_schema();
    let mut config = Config::new();
    config.url = Some(database_url());
    let adapter =
        DeadpoolPostgresAdapter::from_config_with_schema_tls(config, schema.clone(), 16, NoTls)?;

    adapter.create_schema(&schema, None).await?;
    assert_eq!(adapter.capabilities().adapter_id, "deadpool-postgres");
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_filters_sorts_limits_counts_and_mutates(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_filters_sorts_limits_counts_and_mutates(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_adapter_applies_case_insensitive_string_operators(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    seed_user(
        &adapter,
        "user_keep",
        "keep@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_user(
        &adapter,
        "user_target",
        "Ada.Target@Example.COM",
        OffsetDateTime::now_utc(),
    )
    .await?;

    let eq = adapter
        .find_one(
            FindOne::new("user").where_clause(
                Where::new(
                    "email",
                    DbValue::String("ada.target@example.com".to_owned()),
                )
                .insensitive(),
            ),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing insensitive eq match".to_owned()))?;
    assert_eq!(
        eq.get("id"),
        Some(&DbValue::String("user_target".to_owned()))
    );

    let in_result = adapter
        .find_many(
            FindMany::new("user").where_clause(
                Where::new(
                    "email",
                    DbValue::StringArray(vec![
                        "nobody@example.com".to_owned(),
                        "ada.target@example.com".to_owned(),
                    ]),
                )
                .operator(WhereOperator::In)
                .insensitive(),
            ),
        )
        .await?;
    assert_eq!(in_result.len(), 1);

    let not_in = adapter
        .find_many(
            FindMany::new("user").where_clause(
                Where::new(
                    "email",
                    DbValue::StringArray(vec!["ada.target@example.com".to_owned()]),
                )
                .operator(WhereOperator::NotIn)
                .insensitive(),
            ),
        )
        .await?;
    assert!(not_in
        .iter()
        .all(|record| record.get("id") != Some(&DbValue::String("user_target".to_owned()))));

    let count = adapter
        .count(
            Count::new("user").where_clause(
                Where::new("email", DbValue::String("target@example.com".to_owned()))
                    .operator(WhereOperator::EndsWith)
                    .insensitive(),
            ),
        )
        .await?;
    assert_eq!(count, 1);

    let updated = adapter
        .update(
            Update::new("user")
                .where_clause(
                    Where::new(
                        "email",
                        DbValue::String("ada.target@example.com".to_owned()),
                    )
                    .operator(WhereOperator::Ne)
                    .insensitive(),
                )
                .where_clause(Where::new("id", DbValue::String("user_keep".to_owned())))
                .data(
                    "name",
                    DbValue::String("updated-by-insensitive-ne".to_owned()),
                ),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing insensitive update".to_owned()))?;
    assert_eq!(
        updated.get("name"),
        Some(&DbValue::String("updated-by-insensitive-ne".to_owned()))
    );

    let deleted = adapter
        .delete_many(
            DeleteMany::new("user").where_clause(
                Where::new(
                    "email",
                    DbValue::String("ADA.TARGET@EXAMPLE.COM".to_owned()),
                )
                .insensitive(),
            ),
        )
        .await?;
    assert_eq!(deleted, 1);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_supports_empty_mutations_and_delete_one(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_empty_mutations_delete_one_and_case_insensitive_arrays(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_adapter_handles_null_predicates_in_groups_and_updates(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    seed_user(
        &adapter,
        "null_verified",
        "null@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_user(
        &adapter,
        "image_verified",
        "image@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    adapter
        .update(
            Update::new("user")
                .where_clause(Where::new(
                    "id",
                    DbValue::String("image_verified".to_owned()),
                ))
                .data(
                    "image",
                    DbValue::String("https://example.com/avatar.png".to_owned()),
                ),
        )
        .await?;

    let null_rows = adapter
        .find_many(
            FindMany::new("user")
                .where_clause(Where::new("image", DbValue::Null).operator(WhereOperator::Eq)),
        )
        .await?;
    assert!(null_rows
        .iter()
        .any(|record| record.get("id") == Some(&DbValue::String("null_verified".to_owned()))));

    let not_null_rows = adapter
        .find_many(
            FindMany::new("user")
                .where_clause(Where::new("image", DbValue::Null).operator(WhereOperator::Ne)),
        )
        .await?;
    assert_eq!(not_null_rows.len(), 1);

    let or_rows = adapter
        .find_many(
            FindMany::new("user")
                .where_clause(
                    Where::new("image", DbValue::Null)
                        .operator(WhereOperator::Eq)
                        .or(),
                )
                .where_clause(
                    Where::new("email", DbValue::String("image@example.com".to_owned())).or(),
                ),
        )
        .await?;
    assert_eq!(or_rows.len(), 2);

    let updated = adapter
        .update(
            Update::new("user")
                .where_clause(Where::new(
                    "id",
                    DbValue::String("null_verified".to_owned()),
                ))
                .where_clause(Where::new("image", DbValue::Null).operator(WhereOperator::Eq))
                .data("name", DbValue::String("updated-null-user".to_owned())),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing null predicate update".to_owned()))?;
    assert_eq!(
        updated.get("name"),
        Some(&DbValue::String("updated-null-user".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_round_trips_json_and_array_fields() -> Result<(), OpenAuthError>
{
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users")
            .with_field("metadata", DbField::new("metadata", DbFieldType::Json))
            .with_field("tags", DbField::new("tags", DbFieldType::StringArray))
            .with_field("scores", DbField::new("scores", DbFieldType::NumberArray)),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;
    let now = OffsetDateTime::now_utc();
    let metadata = serde_json::json!({ "tier": "admin", "enabled": true });

    let created = adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_json".to_owned()))
                .data("name", DbValue::String("json user".to_owned()))
                .data("email", DbValue::String("json@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(false))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("metadata", DbValue::Json(metadata.clone()))
                .data(
                    "tags",
                    DbValue::StringArray(vec!["a".to_owned(), "b".to_owned()]),
                )
                .data("scores", DbValue::NumberArray(vec![1, 2, 3])),
        )
        .await?;

    assert_eq!(
        created.get("metadata"),
        Some(&DbValue::Json(metadata.clone()))
    );

    let updated = adapter
        .update(
            Update::new("user")
                .where_clause(Where::new("id", DbValue::String("user_json".to_owned())))
                .data("tags", DbValue::StringArray(vec!["c".to_owned()]))
                .data("scores", DbValue::NumberArray(vec![9])),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing json user update".to_owned()))?;
    assert_eq!(
        updated.get("tags"),
        Some(&DbValue::StringArray(vec!["c".to_owned()]))
    );
    assert_eq!(updated.get("scores"), Some(&DbValue::NumberArray(vec![9])));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_supports_native_and_fallback_joins() -> Result<(), OpenAuthError>
{
    let adapter = adapter().await?;
    conformance::assert_supports_native_and_fallback_joins(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_adapter_returns_empty_or_null_for_missing_join_rows(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_returns_empty_or_null_for_missing_join_rows(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_adapter_rolls_back_failed_transactions() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_rolls_back_failed_transactions(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_adapter_commits_successful_transactions() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_commits_successful_transactions(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_adapter_rolls_back_after_sql_error_in_transaction(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_rolls_back_after_sql_error_in_transaction(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_adapter_rejects_nested_transactions() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_rejects_nested_transactions(&adapter).await
}

#[tokio::test]
async fn deadpool_postgres_transaction_multi_join_uses_fallback() -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;

    conformance::assert_transaction_multi_join_uses_fallback(&adapter, schema).await
}

#[tokio::test]
async fn deadpool_postgres_rate_limit_store_is_atomic_and_uses_physical_names(
) -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;
    let store = Arc::new(DeadpoolPostgresRateLimitStore::from(&adapter));
    let rule = RateLimitRule { window: 60, max: 1 };

    let (first, second) = tokio::join!(
        store.consume(RateLimitConsumeInput {
            key: "ip:/sign-in".to_owned(),
            rule: rule.clone(),
            now_ms: 1_000,
        }),
        store.consume(RateLimitConsumeInput {
            key: "ip:/sign-in".to_owned(),
            rule,
            now_ms: 1_001,
        })
    );

    let decisions = [first?, second?];
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| decision.permitted)
            .count(),
        1
    );
    assert_eq!(adapter.count(Count::new("rate_limit")).await?, 1);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_rate_limit_store_denies_without_incrementing_denied_requests(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    let store = DeadpoolPostgresRateLimitStore::from(&adapter);
    let rule = RateLimitRule { window: 60, max: 1 };
    let key = "ip:/limited".to_owned();

    let first = store
        .consume(RateLimitConsumeInput {
            key: key.clone(),
            rule: rule.clone(),
            now_ms: 1_700_000_000_000,
        })
        .await?;
    let second = store
        .consume(RateLimitConsumeInput {
            key: key.clone(),
            rule,
            now_ms: 1_700_000_000_001,
        })
        .await?;

    assert!(first.permitted);
    assert!(!second.permitted);
    let record = adapter
        .find_one(FindOne::new("rate_limit").where_clause(Where::new("key", DbValue::String(key))))
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing rate limit row".to_owned()))?;
    assert_eq!(record.get("count"), Some(&DbValue::Number(1)));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_rate_limit_store_accepts_standalone_physical_names(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let table = format!("{prefix}_custom_rate_limits");
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit: TableOptions::default()
            .with_name(table.clone())
            .with_field_name("key", "rl_key")
            .with_field_name("count", "rl_count")
            .with_field_name("last_request", "rl_last_request"),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        DeadpoolPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;
    let store = DeadpoolPostgresRateLimitStore::with_names(
        adapter.pool().clone(),
        SqlRateLimitNames {
            table: table.clone(),
            key: "rl_key".to_owned(),
            count: "rl_count".to_owned(),
            last_request: "rl_last_request".to_owned(),
        },
    );
    let key = "ip:/standalone-names".to_owned();

    let decision = store
        .consume(RateLimitConsumeInput {
            key: key.clone(),
            rule: RateLimitRule { window: 60, max: 5 },
            now_ms: 1_700_000_000_000,
        })
        .await?;

    assert!(decision.permitted);
    let raw = raw_client().await?;
    let stored_count = raw
        .query_one(
            &format!("SELECT rl_count FROM {table} WHERE rl_key = $1"),
            &[&key],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, i64>(0);
    assert_eq!(stored_count, 1);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_allows_concurrent_pool_operations() -> Result<(), OpenAuthError>
{
    let schema = test_schema();
    let mut config = Config::new();
    config.url = Some(database_url());
    config.pool = Some(PoolConfig::new(2));
    let adapter = Arc::new(DeadpoolPostgresAdapter::from_config_with_schema(
        config,
        schema.clone(),
        16,
    )?);
    adapter.create_schema(&schema, None).await?;

    let mut tasks = Vec::new();
    for index in 0..6 {
        let adapter = Arc::clone(&adapter);
        tasks.push(tokio::spawn(async move {
            let id = format!("concurrent_user_{index}");
            let email = format!("concurrent-{index}@example.com");
            seed_user(adapter.as_ref(), &id, &email, OffsetDateTime::now_utc()).await
        }));
    }
    for task in tasks {
        task.await
            .map_err(|error| OpenAuthError::Adapter(format!("join failed: {error}")))??;
    }

    assert_eq!(adapter.count(Count::new("user")).await?, 6);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_supports_core_auth_route_flows(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(adapter().await?);
    let router = router(adapter.clone())?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);
    let cookie = cookie_header_from_response(&sign_up)?;

    let get_session = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(get_session.status(), StatusCode::OK);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let sign_in_body: Value = serde_json::from_slice(sign_in.body())?;
    assert!(sign_in_body["token"].as_str().is_some());
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_supports_password_reset_verifications(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(adapter().await?);
    let router = router(adapter.clone())?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let request_reset = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
            None,
        )?)
        .await?;
    assert_eq!(request_reset.status(), StatusCode::OK);

    let verification = adapter
        .find_many(FindMany::new("verification").limit(1))
        .await?
        .into_iter()
        .next()
        .ok_or("missing verification")?;
    let identifier = string_field(&verification, "identifier")?;
    let token = identifier
        .strip_prefix("reset-password:")
        .ok_or("bad identifier")?;

    let reset = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/reset-password",
            &format!(r#"{{"newPassword":"new-secret123","token":"{token}"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(reset.status(), StatusCode::OK);

    let account = adapter
        .find_one(FindOne::new("account").where_clause(Where::new(
            "provider_id",
            DbValue::String("credential".to_owned()),
        )))
        .await?
        .ok_or("missing credential account")?;
    let password_hash = string_field(&account, "password")?;
    assert!(verify_password(password_hash, "new-secret123")?);
    assert_eq!(adapter.count(Count::new("verification")).await?, 0);
    Ok(())
}

fn router(adapter: Arc<DeadpoolPostgresAdapter>) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

fn cookie_header_from_response(
    response: &http::Response<Vec<u8>>,
) -> Result<String, OpenAuthError> {
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split_once(';').map(|(cookie, _)| cookie.to_owned()))
        .collect::<Vec<_>>();
    if cookies.is_empty() {
        return Err(OpenAuthError::Adapter(
            "missing set-cookie header".to_owned(),
        ));
    }
    Ok(cookies.join("; "))
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing string field `{field}`"
        ))),
    }
}
