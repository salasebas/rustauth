use std::sync::Arc;

use deadpool_postgres::{Config, PoolConfig};
use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::crypto::password::verify_password;
use openauth_core::db::{
    auth_schema, AuthSchemaOptions, Count, Create, DbAdapter, DbField, DbFieldType, DbRecord,
    DbSchema, DbValue, DeleteMany, FindMany, FindOne, RateLimitStorage, TableOptions, Update,
    Where, WhereOperator,
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
    Ok(())
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
    assert!(adapter.plan_migrations(&schema).await?.is_empty());
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
async fn deadpool_postgres_adapter_reports_additive_migration_plan() -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let initial = auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users"),
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
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
        ..AuthSchemaOptions::default()
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
async fn deadpool_postgres_adapter_reports_type_mismatch_and_repairs_missing_index(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users").with_field(
            "nickname",
            DbField::new("nickname", DbFieldType::String).indexed(),
        ),
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
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
        ..AuthSchemaOptions::default()
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
        ..AuthSchemaOptions::default()
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
