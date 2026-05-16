use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::crypto::password::verify_password;
use openauth_core::db::{
    auth_schema, AuthSchemaOptions, Count, Create, DbAdapter, DbField, DbFieldType, DbRecord,
    DbSchema, DbValue, DeleteMany, FindMany, FindOne, JoinOption, RateLimitStorage, Sort,
    SortDirection, TableOptions, Update, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, OpenAuthOptions, RateLimitConsumeInput, RateLimitRule, RateLimitStore,
};
use openauth_deadpool_postgres::migration::{MigrationStatementKind, SchemaMigrationWarning};
use openauth_deadpool_postgres::{DeadpoolPostgresAdapter, DeadpoolPostgresRateLimitStore};
use serde_json::Value;
use time::OffsetDateTime;

static TEST_ID: AtomicU64 = AtomicU64::new(0);
const DEFAULT_POSTGRES_URL: &str = "postgres://user:password@localhost:5432/openauth";

fn database_url() -> String {
    database_url_from_env(std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok())
}

fn database_url_from_env(value: Option<String>) -> String {
    value.unwrap_or_else(|| DEFAULT_POSTGRES_URL.to_owned())
}

#[test]
fn database_url_defaults_to_docker_compose_postgres_when_env_is_unset() {
    assert_eq!(database_url_from_env(None), DEFAULT_POSTGRES_URL);
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

fn test_schema() -> DbSchema {
    let prefix = unique_prefix();
    auth_schema(AuthSchemaOptions {
        user: table_options(&prefix, "users"),
        account: table_options(&prefix, "accounts"),
        session: table_options(&prefix, "sessions"),
        verification: table_options(&prefix, "verifications"),
        rate_limit: table_options(&prefix, "rate_limits"),
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    })
}

fn table_options(prefix: &str, table: &str) -> TableOptions {
    TableOptions::default().with_name(format!("{prefix}_{table}"))
}

fn unique_prefix() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let sequence = TEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("oa_dpg_{millis}_{sequence}")
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
async fn deadpool_postgres_adapter_filters_sorts_limits_counts_and_mutates(
) -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    let base = OffsetDateTime::UNIX_EPOCH;
    for (id, email, created_at) in [
        (
            "user_1",
            "ada@example.com",
            base + time::Duration::seconds(1),
        ),
        (
            "user_2",
            "grace@example.com",
            base + time::Duration::seconds(3),
        ),
        (
            "user_3",
            "alan@example.net",
            base + time::Duration::seconds(2),
        ),
    ] {
        seed_user(&adapter, id, email, created_at).await?;
    }

    let records = adapter
        .find_many(
            FindMany::new("user")
                .where_clause(
                    Where::new("email", DbValue::String("EXAMPLE.COM".to_owned()))
                        .operator(WhereOperator::EndsWith)
                        .insensitive(),
                )
                .sort_by(Sort::new("created_at", SortDirection::Desc))
                .limit(1)
                .offset(0),
        )
        .await?;
    let count = adapter
        .count(
            Count::new("user").where_clause(
                Where::new("email", DbValue::String("example.com".to_owned()))
                    .operator(WhereOperator::EndsWith)
                    .insensitive(),
            ),
        )
        .await?;

    assert_eq!(count, 2);
    assert_eq!(
        records[0].get("id"),
        Some(&DbValue::String("user_2".to_owned()))
    );

    seed_session(&adapter, "session_1", "user_1").await?;
    seed_session(&adapter, "session_2", "user_1").await?;
    seed_session(&adapter, "session_3", "user_2").await?;
    let updated = adapter
        .update(
            Update::new("session")
                .where_clause(Where::new("id", DbValue::String("session_1".to_owned())))
                .data("user_agent", DbValue::String("updated".to_owned())),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing updated session".to_owned()))?;
    let deleted = adapter
        .delete_many(
            DeleteMany::new("session")
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned()))),
        )
        .await?;

    assert_eq!(
        updated.get("user_agent"),
        Some(&DbValue::String("updated".to_owned()))
    );
    assert_eq!(deleted, 2);
    assert_eq!(adapter.find_many(FindMany::new("session")).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_supports_native_and_fallback_joins() -> Result<(), OpenAuthError>
{
    let adapter = adapter().await?;
    seed_user(
        &adapter,
        "user_1",
        "ada@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_user(
        &adapter,
        "user_2",
        "grace@example.com",
        OffsetDateTime::now_utc(),
    )
    .await?;
    seed_account(&adapter, "account_1", "user_1").await?;
    seed_account(&adapter, "account_2", "user_1").await?;
    seed_session(&adapter, "session_1", "user_1").await?;
    seed_session(&adapter, "session_2", "user_1").await?;

    let user = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned())))
                .join("account", JoinOption::enabled().limit(1)),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing joined user".to_owned()))?;
    assert!(matches!(
        user.get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
    ));

    let users = adapter
        .find_many(
            FindMany::new("user")
                .join("account", JoinOption::enabled().limit(1))
                .join("session", JoinOption::enabled()),
        )
        .await?;
    let joined = users
        .iter()
        .find(|record| record.get("id") == Some(&DbValue::String("user_1".to_owned())))
        .ok_or_else(|| OpenAuthError::Adapter("missing fallback joined user".to_owned()))?;
    assert!(matches!(
        joined.get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
    ));
    assert!(matches!(
        joined.get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.len() == 2
    ));

    let account = adapter
        .find_one(
            FindOne::new("account")
                .where_clause(Where::new("id", DbValue::String("account_1".to_owned())))
                .join("user", JoinOption::enabled()),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing joined account".to_owned()))?;
    assert!(matches!(
        account.get("user"),
        Some(DbValue::Record(user)) if user.get("id") == Some(&DbValue::String("user_1".to_owned()))
    ));
    Ok(())
}

#[tokio::test]
async fn deadpool_postgres_adapter_rolls_back_failed_transactions() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    let result = adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                seed_user(
                    tx.as_ref(),
                    "user_1",
                    "ada@example.com",
                    OffsetDateTime::now_utc(),
                )
                .await?;
                Err(OpenAuthError::Adapter("force rollback".to_owned()))
            })
        }))
        .await;

    assert!(result.is_err());
    assert_eq!(adapter.count(Count::new("user")).await?, 0);
    Ok(())
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

async fn seed_user<A>(
    adapter: &A,
    id: &str,
    email: &str,
    created_at: OffsetDateTime,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter + ?Sized,
{
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String(id.to_owned()))
                .data("email", DbValue::String(email.to_owned()))
                .data("email_verified", DbValue::Boolean(false))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(created_at))
                .data("updated_at", DbValue::Timestamp(created_at)),
        )
        .await?;
    Ok(())
}

async fn seed_account(
    adapter: &DeadpoolPostgresAdapter,
    id: &str,
    user_id: &str,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("account")
                .data("id", DbValue::String(id.to_owned()))
                .data("account_id", DbValue::String(id.to_owned()))
                .data("provider_id", DbValue::String("credential".to_owned()))
                .data("user_id", DbValue::String(user_id.to_owned()))
                .data("access_token", DbValue::Null)
                .data("refresh_token", DbValue::Null)
                .data("id_token", DbValue::Null)
                .data("access_token_expires_at", DbValue::Null)
                .data("refresh_token_expires_at", DbValue::Null)
                .data("scope", DbValue::Null)
                .data("password", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await?;
    Ok(())
}

async fn seed_session(
    adapter: &DeadpoolPostgresAdapter,
    id: &str,
    user_id: &str,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("session")
                .data("id", DbValue::String(id.to_owned()))
                .data(
                    "expires_at",
                    DbValue::Timestamp(now + time::Duration::hours(1)),
                )
                .data("token", DbValue::String(id.to_owned()))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("ip_address", DbValue::Null)
                .data("user_agent", DbValue::Null)
                .data("user_id", DbValue::String(user_id.to_owned())),
        )
        .await?;
    Ok(())
}
