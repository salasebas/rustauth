use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::crypto::password::verify_password;
use openauth_core::db::{
    auth_schema, AuthSchemaOptions, Count, Create, DbAdapter, DbField, DbFieldType, DbRecord,
    DbSchema, DbValue, FindMany, FindOne, IdGeneration, IdPolicy, JoinOption, RateLimitStorage,
    SqlRateLimitNames, TableOptions, Update, UpdateMany, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, EmailPasswordOptions, OpenAuthOptions, RateLimitConsumeInput, RateLimitRule,
    RateLimitStore,
};
use openauth_tokio_postgres::migration::{MigrationStatementKind, SchemaMigrationWarning};
use openauth_tokio_postgres::{
    TokioPostgresAdapter, TokioPostgresConnection, TokioPostgresRateLimitStore,
};
use serde_json::Value;

#[path = "../../../tests/support/postgres_adapter_conformance.rs"]
mod postgres_adapter_conformance;

#[path = "../../../tests/support/postgres_migration_atomicity.rs"]
mod postgres_migration_atomicity;

use postgres_adapter_conformance as conformance;

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

#[tokio::test]
async fn tokio_postgres_connect_error_includes_database_details() -> Result<(), OpenAuthError> {
    let error = match TokioPostgresAdapter::connect(
        "postgres://user:password@localhost:5432/openauth_missing",
    )
    .await
    {
        Ok(_) => {
            return Err(OpenAuthError::Adapter(
                "missing database should fail".to_owned(),
            ));
        }
        Err(error) => error,
    };
    let message = error.to_string();

    assert!(message.contains("3D000"), "{message}");
    assert!(message.contains("openauth_missing"), "{message}");
    Ok(())
}

async fn adapter() -> Result<TokioPostgresAdapter, OpenAuthError> {
    let schema = test_schema();
    let adapter =
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;
    Ok(adapter)
}

async fn raw_client() -> Result<tokio_postgres::Client, OpenAuthError> {
    conformance::raw_client().await
}

fn test_schema() -> DbSchema {
    conformance::test_schema("oa_tpg")
}

fn table_options(prefix: &str, table: &str) -> TableOptions {
    conformance::table_options(prefix, table)
}

fn unique_prefix() -> String {
    conformance::unique_prefix("oa_tpg")
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
async fn tokio_postgres_adapter_reports_public_capabilities() -> Result<(), OpenAuthError> {
    let capabilities = adapter().await?.capabilities();

    assert_eq!(capabilities.adapter_id, "tokio-postgres");
    assert_eq!(capabilities.adapter_name.as_deref(), Some("tokio-postgres"));
    assert!(capabilities.supports_json);
    assert!(capabilities.supports_arrays);
    assert!(capabilities.supports_joins);
    assert!(capabilities.supports_native_joins);
    assert!(capabilities.supports_transactions);
    assert!(capabilities.supports_uuid_ids);
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_returns_database_generated_uuid_ids() -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Uuid).with_database_uuid_support(true),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;

    conformance::assert_returns_database_generated_uuid_ids(
        &adapter,
        format!("ada-{prefix}@example.com"),
    )
    .await
}

#[tokio::test]
async fn tokio_postgres_adapter_supports_forced_uuid_ids() -> Result<(), OpenAuthError> {
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
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;

    conformance::assert_supports_forced_uuid_ids(
        &adapter,
        forced_id,
        format!("forced-{prefix}@example.com"),
    )
    .await
}

#[tokio::test]
async fn tokio_postgres_adapter_returns_database_generated_serial_ids() -> Result<(), OpenAuthError>
{
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
        id_policy: IdPolicy::new(IdGeneration::Serial),
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

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
async fn tokio_postgres_adapter_plans_and_runs_migrations() -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let adapter =
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

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
async fn tokio_postgres_adapter_migration_plan_rolls_back_on_statement_failure(
) -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let client = raw_client().await?;
    postgres_migration_atomicity::assert_migration_plan_rolls_back_on_statement_failure(
        &client, &schema,
    )
    .await
}

#[tokio::test]
async fn tokio_postgres_adapter_reports_additive_migration_plan() -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let initial = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..prefixed_options(&prefix)
    });
    let adapter =
        TokioPostgresAdapter::connect_with_schema(&database_url(), initial.clone()).await?;
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
async fn tokio_postgres_adapter_run_migrations_rejects_type_warnings_without_applying_statements(
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
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

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

    let result = adapter.run_migrations(&schema).await;
    assert!(
        matches!(result, Err(OpenAuthError::Adapter(message)) if message.contains("non-executable migration warnings"))
    );
    // The whole plan is rejected, so the additive index is never created.
    assert!(adapter
        .plan_migrations(&schema)
        .await?
        .indexes_to_be_created
        .iter()
        .any(|index| index.field_logical_name == "nickname"));
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_create_schema_rejects_type_warnings_without_applying_statements(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let schema = auth_schema(AuthSchemaOptions {
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
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

    let result = adapter.create_schema(&schema, None).await;
    assert!(
        matches!(result, Err(OpenAuthError::Adapter(message)) if message.contains("non-executable migration warnings"))
    );
    // No additive statements run, so dependent tables stay uncreated.
    let sessions_table_count = raw
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = $1",
            &[&format!("{prefix}_sessions")],
        )
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?
        .get::<_, i64>(0);
    assert_eq!(sessions_table_count, 0);
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_supports_postgres_schema_qualified_table_names(
) -> Result<(), OpenAuthError> {
    let prefix = unique_prefix();
    let pg_schema = format!("{prefix}_internal");
    let raw = raw_client().await?;
    raw.batch_execute(&format!(r#"CREATE SCHEMA "{pg_schema}""#))
        .await
        .map_err(openauth_tokio_postgres::driver::postgres_error)?;

    let table = |name: &str| TableOptions::default().with_name(format!("{pg_schema}.{name}"));
    let schema = auth_schema(AuthSchemaOptions {
        user: table("users"),
        account: table("accounts"),
        session: table("sessions"),
        verification: table("verifications"),
        rate_limit: table("rate_limits"),
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });
    let adapter =
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;

    adapter.create_schema(&schema, None).await?;
    conformance::seed_user(
        &adapter,
        "schema_user",
        "schema-user@example.com",
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    conformance::seed_session(&adapter, "schema_session", "schema_user").await?;

    let found = adapter
        .find_one(
            FindOne::new("session")
                .where_clause(Where::new(
                    "id",
                    DbValue::String("schema_session".to_owned()),
                ))
                .join("user", JoinOption::enabled()),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing schema-qualified session".to_owned()))?;
    assert!(matches!(
        found.get("user"),
        Some(DbValue::Record(user))
            if user.get("id") == Some(&DbValue::String("schema_user".to_owned()))
    ));
    assert!(adapter.plan_migrations(&schema).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_round_trips_json_arrays_and_create_select(
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
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;
    conformance::assert_round_trips_json_arrays_and_create_select(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_filters_sorts_limits_counts_and_mutates(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_filters_sorts_limits_counts_and_mutates(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_supports_empty_mutations_delete_one_and_case_insensitive_arrays(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_empty_mutations_delete_one_and_case_insensitive_arrays(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_supports_native_and_fallback_joins() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_supports_native_and_fallback_joins(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_returns_empty_or_null_for_missing_join_rows(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_returns_empty_or_null_for_missing_join_rows(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_rolls_back_failed_transactions() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_rolls_back_failed_transactions(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_commits_successful_transactions() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_commits_successful_transactions(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_rolls_back_after_sql_error_in_transaction(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_rolls_back_after_sql_error_in_transaction(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_rolls_back_on_cancelled_transaction() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_rolls_back_on_cancelled_transaction(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_does_not_bleed_aborted_writes_into_commit(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_no_commit_bleed_after_cancel(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_adapter_rejects_nested_transactions() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::assert_rejects_nested_transactions(&adapter).await
}

#[tokio::test]
async fn tokio_postgres_transaction_multi_join_uses_fallback() -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let adapter =
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;

    conformance::assert_transaction_multi_join_uses_fallback(&adapter, schema).await
}

#[tokio::test]
async fn tokio_postgres_transaction_adapter_reports_and_supports_joins() -> Result<(), OpenAuthError>
{
    let adapter = adapter().await?;

    adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                assert!(tx.capabilities().supports_joins);
                conformance::seed_user(
                    tx.as_ref(),
                    "user_1",
                    "ada@example.com",
                    time::OffsetDateTime::now_utc(),
                )
                .await?;
                conformance::seed_account(tx.as_ref(), "account_1", "user_1").await?;
                conformance::seed_session(tx.as_ref(), "session_1", "user_1").await?;

                let users = tx
                    .find_many(
                        FindMany::new("user")
                            .join("account", JoinOption::enabled())
                            .join("session", JoinOption::enabled()),
                    )
                    .await?;
                let user = users
                    .into_iter()
                    .next()
                    .ok_or_else(|| OpenAuthError::Adapter("missing joined user".to_owned()))?;

                assert!(matches!(
                    user.get("account"),
                    Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
                ));
                assert!(matches!(
                    user.get("session"),
                    Some(DbValue::RecordArray(sessions)) if sessions.len() == 1
                ));
                Ok(())
            })
        }))
        .await
}

#[tokio::test]
async fn tokio_postgres_adapter_handles_null_predicates_in_and_or_groups(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::seed_user(
        &adapter,
        "null_verified",
        "null-verified@example.com",
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    conformance::seed_user(
        &adapter,
        "null_unverified",
        "null-unverified@example.com",
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    conformance::seed_user(
        &adapter,
        "image_verified",
        "image-verified@example.com",
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    adapter
        .update(
            openauth_core::db::Update::new("user")
                .where_clause(Where::new(
                    "id",
                    DbValue::String("null_verified".to_owned()),
                ))
                .data("email_verified", DbValue::Boolean(true)),
        )
        .await?;
    adapter
        .update(
            openauth_core::db::Update::new("user")
                .where_clause(Where::new(
                    "id",
                    DbValue::String("image_verified".to_owned()),
                ))
                .data(
                    "image",
                    DbValue::String("https://example.com/avatar.png".to_owned()),
                )
                .data("email_verified", DbValue::Boolean(true)),
        )
        .await?;

    let null_and_verified = adapter
        .find_many(
            FindMany::new("user")
                .where_clause(Where::new("image", DbValue::Null))
                .where_clause(Where::new("email_verified", DbValue::Boolean(true))),
        )
        .await?;
    let non_null_and_verified = adapter
        .find_many(
            FindMany::new("user")
                .where_clause(Where::new("image", DbValue::Null).operator(WhereOperator::Ne))
                .where_clause(Where::new("email_verified", DbValue::Boolean(true))),
        )
        .await?;
    let null_or_target = adapter
        .find_many(
            FindMany::new("user")
                .where_clause(Where::new("image", DbValue::Null).or())
                .where_clause(
                    Where::new(
                        "email",
                        DbValue::String("image-verified@example.com".to_owned()),
                    )
                    .or(),
                ),
        )
        .await?;

    assert_eq!(ids(null_and_verified), vec!["null_verified".to_owned()]);
    assert_eq!(
        ids(non_null_and_verified),
        vec!["image_verified".to_owned()]
    );
    assert_eq!(
        ids(null_or_target),
        vec![
            "image_verified".to_owned(),
            "null_unverified".to_owned(),
            "null_verified".to_owned(),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_treats_like_wildcards_as_literals() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    let now = time::OffsetDateTime::now_utc();
    for (id, email) in [
        ("wild_percent", "literal%name@example.com"),
        ("wild_underscore", "literal_name@example.com"),
        ("wild_plain", "literalXname@example.com"),
    ] {
        conformance::seed_user(&adapter, id, email, now).await?;
    }

    let percent = adapter
        .find_many(FindMany::new("user").where_clause(
            Where::new("email", DbValue::String("%".to_owned())).operator(WhereOperator::Contains),
        ))
        .await?;
    let underscore = adapter
        .find_many(FindMany::new("user").where_clause(
            Where::new("email", DbValue::String("_".to_owned())).operator(WhereOperator::Contains),
        ))
        .await?;

    assert_eq!(ids(percent), vec!["wild_percent".to_owned()]);
    assert_eq!(ids(underscore), vec!["wild_underscore".to_owned()]);
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_updates_many_with_empty_where() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    let now = time::OffsetDateTime::now_utc();
    for id in ["bulk_1", "bulk_2", "bulk_3"] {
        conformance::seed_user(&adapter, id, &format!("{id}@example.com"), now).await?;
    }

    let count = adapter
        .update_many(
            UpdateMany::new("user").data("name", DbValue::String("bulk-updated".to_owned())),
        )
        .await?;
    let renamed = adapter
        .count(Count::new("user").where_clause(Where::new(
            "name",
            DbValue::String("bulk-updated".to_owned()),
        )))
        .await?;

    assert_eq!(count, 3);
    assert_eq!(renamed, 3);
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_returns_updated_record_when_where_field_changes(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::seed_user(
        &adapter,
        "change_where",
        "before-change@example.com",
        time::OffsetDateTime::now_utc(),
    )
    .await?;

    let updated = adapter
        .update(
            Update::new("user")
                .where_clause(Where::new(
                    "email",
                    DbValue::String("before-change@example.com".to_owned()),
                ))
                .data(
                    "email",
                    DbValue::String("after-change@example.com".to_owned()),
                )
                .data("name", DbValue::String("Changed".to_owned())),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing updated user".to_owned()))?;

    assert_eq!(
        updated.get("email"),
        Some(&DbValue::String("after-change@example.com".to_owned()))
    );
    assert!(adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            "email",
            DbValue::String("before-change@example.com".to_owned()),
        )))
        .await?
        .is_none());
    assert!(adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            "email",
            DbValue::String("after-change@example.com".to_owned()),
        )))
        .await?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_selects_base_fields_with_join() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    conformance::seed_user(
        &adapter,
        "select_join_user",
        "select-join@example.com",
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    conformance::seed_session(&adapter, "select_join_session", "select_join_user").await?;

    let found = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new(
                    "id",
                    DbValue::String("select_join_user".to_owned()),
                ))
                .select(["email"])
                .join("session", JoinOption::enabled()),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing selected joined user".to_owned()))?;

    assert_eq!(
        found.get("email"),
        Some(&DbValue::String("select-join@example.com".to_owned()))
    );
    assert!(!found.contains_key("id"));
    assert!(matches!(
        found.get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.len() == 1
    ));
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_rate_limit_store_is_atomic_and_uses_physical_names(
) -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let adapter =
        TokioPostgresAdapter::connect_with_schema(&database_url(), schema.clone()).await?;
    adapter.create_schema(&schema, None).await?;
    let store = Arc::new(TokioPostgresRateLimitStore::from(&adapter));
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
async fn tokio_postgres_rate_limit_store_denies_without_incrementing_denied_requests(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    let store = TokioPostgresRateLimitStore::from(&adapter);
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
async fn tokio_postgres_rate_limit_store_rejects_negative_persisted_counts(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    let store = TokioPostgresRateLimitStore::from(&adapter);
    let key = "ip:/corrupt-negative-count".to_owned();
    adapter
        .create(
            Create::new("rate_limit")
                .data("key", DbValue::String(key.clone()))
                .data("count", DbValue::Number(-1))
                .data("last_request", DbValue::Number(1_700_000_000_000)),
        )
        .await?;

    let result = store
        .consume(RateLimitConsumeInput {
            key,
            rule: RateLimitRule { window: 60, max: 5 },
            now_ms: 1_700_000_000_001,
        })
        .await;

    assert!(matches!(
        result,
        Err(OpenAuthError::Adapter(message)) if message.contains("negative rate limit count")
    ));
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_rate_limit_store_respects_adapter_transaction_gate(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    let store = adapter.rate_limit_store();
    let tx_started = Arc::new(tokio::sync::Notify::new());
    let release_tx = Arc::new(tokio::sync::Notify::new());
    let tx_started_for_task = Arc::clone(&tx_started);
    let release_tx_for_task = Arc::clone(&release_tx);
    let adapter_for_tx = adapter.clone();

    let tx_task = tokio::spawn(async move {
        adapter_for_tx
            .transaction(Box::new(move |_tx| {
                Box::pin(async move {
                    tx_started_for_task.notify_one();
                    release_tx_for_task.notified().await;
                    Ok(())
                })
            }))
            .await
    });

    tx_started.notified().await;

    let consume_result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        store.consume(RateLimitConsumeInput {
            key: "ip:/shared-gate".to_owned(),
            rule: RateLimitRule { window: 60, max: 1 },
            now_ms: 1_000,
        }),
    )
    .await;

    assert!(
        consume_result.is_err(),
        "rate-limit consume should wait for the adapter transaction gate"
    );

    release_tx.notify_one();
    match tx_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(join_error) => {
            return Err(OpenAuthError::Adapter(format!(
                "transaction task panicked: {join_error}"
            )));
        }
    }
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_shared_connection_serializes_adapter_and_rate_limit(
) -> Result<(), OpenAuthError> {
    let client = raw_client().await?;
    let schema = test_schema();
    let connection = TokioPostgresConnection::from_client(client);
    let adapter = TokioPostgresAdapter::with_connection(connection.clone(), schema.clone());
    adapter.create_schema(&schema, None).await?;
    let rate_limit_names = SqlRateLimitNames::from_schema(&schema);
    let store = TokioPostgresRateLimitStore::from_connection(&connection, rate_limit_names.table);

    let tx_started = Arc::new(tokio::sync::Notify::new());
    let release_tx = Arc::new(tokio::sync::Notify::new());
    let tx_started_for_task = Arc::clone(&tx_started);
    let release_tx_for_task = Arc::clone(&release_tx);
    let adapter_for_tx = adapter.clone();

    let tx_task = tokio::spawn(async move {
        adapter_for_tx
            .transaction(Box::new(move |_tx| {
                Box::pin(async move {
                    tx_started_for_task.notify_one();
                    release_tx_for_task.notified().await;
                    Ok(())
                })
            }))
            .await
    });

    tx_started.notified().await;

    let consume_result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        store.consume(RateLimitConsumeInput {
            key: "ip:/explicit-connection".to_owned(),
            rule: RateLimitRule { window: 60, max: 1 },
            now_ms: 1_000,
        }),
    )
    .await;

    assert!(
        consume_result.is_err(),
        "explicit shared connection should keep rate-limit consume behind the adapter gate"
    );

    release_tx.notify_one();
    match tx_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(join_error) => {
            return Err(OpenAuthError::Adapter(format!(
                "transaction task panicked: {join_error}"
            )));
        }
    }
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_unshared_connection_bypasses_adapter_transaction_gate(
) -> Result<(), OpenAuthError> {
    let schema = test_schema();
    let connection = TokioPostgresConnection::connect(&database_url()).await?;
    let adapter = TokioPostgresAdapter::with_connection(connection.clone(), schema.clone());
    adapter.create_schema(&schema, None).await?;
    let rate_limit_names = SqlRateLimitNames::from_schema(&schema);
    let store = TokioPostgresRateLimitStore::from_connection(
        &TokioPostgresConnection::duplicate_client_unshared_gate(&connection),
        rate_limit_names.table,
    );

    let tx_started = Arc::new(tokio::sync::Notify::new());
    let release_tx = Arc::new(tokio::sync::Notify::new());
    let tx_started_for_task = Arc::clone(&tx_started);
    let release_tx_for_task = Arc::clone(&release_tx);
    let adapter_for_tx = adapter.clone();

    let tx_task = tokio::spawn(async move {
        adapter_for_tx
            .transaction(Box::new(move |_tx| {
                Box::pin(async move {
                    tx_started_for_task.notify_one();
                    release_tx_for_task.notified().await;
                    Ok(())
                })
            }))
            .await
    });

    tx_started.notified().await;

    let consume_result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        store.consume(RateLimitConsumeInput {
            key: "ip:/unshared-gate".to_owned(),
            rule: RateLimitRule { window: 60, max: 1 },
            now_ms: 1_000,
        }),
    )
    .await;

    assert!(
        consume_result.is_ok(),
        "separate connection bundles on the same cloned client bypass the adapter gate"
    );
    match consume_result {
        Ok(Ok(decision)) => assert!(decision.permitted),
        Ok(Err(error)) => return Err(error),
        Err(_elapsed) => {
            return Err(OpenAuthError::Adapter(
                "rate-limit consume should not wait on an unshared gate".to_owned(),
            ));
        }
    }

    release_tx.notify_one();
    match tx_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(join_error) => {
            return Err(OpenAuthError::Adapter(format!(
                "transaction task panicked: {join_error}"
            )));
        }
    }
    Ok(())
}

#[tokio::test]
async fn tokio_postgres_adapter_supports_core_auth_route_flows(
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
async fn tokio_postgres_adapter_supports_password_reset_verifications(
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

fn router(adapter: Arc<TokioPostgresAdapter>) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        email_password: EmailPasswordOptions::new().enabled(true),
        development: true,
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

fn ids(records: Vec<DbRecord>) -> Vec<String> {
    let mut ids = records
        .into_iter()
        .filter_map(|record| match record.get("id") {
            Some(DbValue::String(value)) => Some(value.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    ids.sort();
    ids
}
