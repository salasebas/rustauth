#![cfg(feature = "sqlite")]

use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::cookies::Cookie;
use openauth_core::crypto::password::verify_password;
use openauth_core::db::{
    auth_schema, AdapterCapabilities, AuthSchemaOptions, Count, Create, DbAdapter, DbField,
    DbFieldType, DbRecord, DbValue, DeleteMany, FindMany, FindOne, HookedAdapter, JoinOption,
    RateLimitStorage, Sort, SortDirection, TableOptions, Update, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use openauth_core::plugin::{
    PluginDatabaseBeforeAction, PluginDatabaseBeforeInput, PluginDatabaseHook,
};
use openauth_sqlx::SqliteAdapter;
use serde_json::Value;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Mutex as StdMutex;
use time::OffsetDateTime;

async fn adapter() -> Result<SqliteAdapter, OpenAuthError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(sql_error)?;
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });
    let adapter = SqliteAdapter::with_schema(pool, schema.clone());
    adapter.create_schema(&schema, None).await?;
    Ok(adapter)
}

#[tokio::test]
async fn sqlite_adapter_filters_sorts_limits_and_counts_records() -> Result<(), OpenAuthError> {
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
                .limit(1),
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
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("id"),
        Some(&DbValue::String("user_2".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_updates_and_deletes_matching_records() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    for user_id in ["user_1", "user_2"] {
        adapter
            .create(
                Create::new("user")
                    .data("id", DbValue::String(user_id.to_owned()))
                    .data("name", DbValue::String(user_id.to_owned()))
                    .data("email", DbValue::String(format!("{user_id}@example.com")))
                    .data("email_verified", DbValue::Boolean(false))
                    .data("image", DbValue::Null)
                    .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                    .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?;
    }
    for (id, user_id) in [
        ("session_1", "user_1"),
        ("session_2", "user_1"),
        ("session_3", "user_2"),
    ] {
        adapter
            .create(
                Create::new("session")
                    .data("id", DbValue::String(id.to_owned()))
                    .data("expires_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                    .data("token", DbValue::String(id.to_owned()))
                    .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                    .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                    .data("ip_address", DbValue::Null)
                    .data("user_agent", DbValue::Null)
                    .data("user_id", DbValue::String(user_id.to_owned())),
            )
            .await?;
    }

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
    let remaining = adapter.find_many(FindMany::new("session")).await?;

    assert_eq!(
        updated.get("user_agent"),
        Some(&DbValue::String("updated".to_owned()))
    );
    assert_eq!(deleted, 2);
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0].get("id"),
        Some(&DbValue::String("session_3".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_reports_public_capabilities() -> Result<(), OpenAuthError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(sql_error)?;
    let capabilities = SqliteAdapter::new(pool).capabilities();

    assert_eq!(
        capabilities,
        AdapterCapabilities::new("sqlx-sqlite")
            .named("SQLx SQLite")
            .with_json()
            .with_arrays()
            .with_joins()
            .with_transactions()
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_create_schema_is_idempotent_and_creates_rate_limit_table(
) -> Result<(), OpenAuthError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(sql_error)?;
    let adapter = SqliteAdapter::new(pool.clone());
    let schema = auth_schema(AuthSchemaOptions {
        rate_limit_storage: RateLimitStorage::Database,
        ..AuthSchemaOptions::default()
    });

    adapter.create_schema(&schema, None).await?;
    adapter.create_schema(&schema, None).await?;

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'rate_limits'",
    )
    .fetch_one(&pool)
    .await
    .map_err(sql_error)?;
    assert_eq!(table_count, 1);
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_run_migrations_applies_plugin_aware_schema() -> Result<(), OpenAuthError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(sql_error)?;
    let adapter = SqliteAdapter::new(pool.clone());
    let mut schema = auth_schema(AuthSchemaOptions::default());
    schema.insert_plugin_field(
        "user",
        "tenant_id".to_owned(),
        DbField::new("tenant_id", DbFieldType::String).optional(),
    )?;

    adapter.run_migrations(&schema).await?;

    let tenant_column_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'tenant_id'",
    )
    .fetch_one(&pool)
    .await
    .map_err(sql_error)?;
    assert_eq!(tenant_column_count, 1);
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_uses_physical_names_from_auth_schema() -> Result<(), OpenAuthError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .map_err(sql_error)?;
    let schema = auth_schema(AuthSchemaOptions {
        user: TableOptions::default()
            .with_name("app_users")
            .with_field_name("email", "primary_email"),
        ..AuthSchemaOptions::default()
    });
    let adapter = SqliteAdapter::with_schema(pool.clone(), schema.clone());
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
        .ok_or_else(|| OpenAuthError::Adapter("missing user".to_owned()))?;
    let stored_email: String = sqlx::query_scalar("SELECT primary_email FROM app_users LIMIT 1")
        .fetch_one(&pool)
        .await
        .map_err(sql_error)?;

    assert_eq!(
        record.get("email"),
        Some(&DbValue::String("ada@example.com".to_owned()))
    );
    assert_eq!(stored_email, "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_rolls_back_failed_transactions() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;

    let result = adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                tx.create(
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
                Err(OpenAuthError::Adapter("force rollback".to_owned()))
            })
        }))
        .await;

    assert!(result.is_err());
    assert_eq!(adapter.count(Count::new("user")).await?, 0);
    Ok(())
}

#[tokio::test]
async fn sqlite_hooked_adapter_preserves_native_transaction_rollback() -> Result<(), OpenAuthError>
{
    let raw = adapter().await?;
    let events = Arc::new(StdMutex::new(Vec::<String>::new()));
    let adapter = HookedAdapter::new(
        Arc::new(raw.clone()) as Arc<dyn DbAdapter>,
        vec![
            PluginDatabaseHook::before_create("rewrite-name", |_context, mut query| {
                if query.model == "user" {
                    query
                        .data
                        .insert("name".to_owned(), DbValue::String("Hooked".to_owned()));
                }
                Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Create(query),
                ))
            }),
            PluginDatabaseHook::after_create("after-create", {
                let events = Arc::clone(&events);
                move |_context, _query, _result| {
                    events
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                        .push("after".to_owned());
                    Ok(())
                }
            }),
        ],
    );

    let result = adapter
        .transaction(Box::new(|tx| {
            Box::pin(async move {
                tx.create(
                    Create::new("user")
                        .data("id", DbValue::String("user_hooked_rollback".to_owned()))
                        .data("name", DbValue::String("Ada".to_owned()))
                        .data("email", DbValue::String("rollback@example.com".to_owned()))
                        .data("email_verified", DbValue::Boolean(false))
                        .data("image", DbValue::Null)
                        .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                        .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
                )
                .await?;
                Err(OpenAuthError::Adapter("force rollback".to_owned()))
            })
        }))
        .await;

    assert!(result.is_err());
    assert_eq!(raw.count(Count::new("user")).await?, 0);
    assert!(events
        .lock()
        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn sqlite_hooked_adapter_runs_after_hooks_after_native_transaction_commit(
) -> Result<(), OpenAuthError> {
    let raw = adapter().await?;
    let events = Arc::new(StdMutex::new(Vec::<String>::new()));
    let adapter = HookedAdapter::new(
        Arc::new(raw.clone()) as Arc<dyn DbAdapter>,
        vec![PluginDatabaseHook::after_create("after-create", {
            let events = Arc::clone(&events);
            move |_context, _query, _result| {
                events
                    .lock()
                    .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                    .push("after".to_owned());
                Ok(())
            }
        })],
    );

    adapter
        .transaction(Box::new({
            let events = Arc::clone(&events);
            move |tx| {
                Box::pin(async move {
                    tx.create(
                        Create::new("user")
                            .data("id", DbValue::String("user_hooked_commit".to_owned()))
                            .data("name", DbValue::String("Ada".to_owned()))
                            .data("email", DbValue::String("commit@example.com".to_owned()))
                            .data("email_verified", DbValue::Boolean(false))
                            .data("image", DbValue::Null)
                            .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                            .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
                    )
                    .await?;
                    assert!(events
                        .lock()
                        .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
                        .is_empty());
                    Ok(())
                })
            }
        }))
        .await?;

    assert_eq!(raw.count(Count::new("user")).await?, 1);
    assert_eq!(
        events
            .lock()
            .map_err(|_| OpenAuthError::Adapter("events lock poisoned".to_owned()))?
            .as_slice(),
        ["after"]
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_supports_where_operators() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    for (key, count, last_request) in [("alpha", 1, 10), ("beta", 2, 20), ("omega", 3, 30)] {
        adapter
            .create(
                Create::new("rate_limit")
                    .data("key", DbValue::String(key.to_owned()))
                    .data("count", DbValue::Number(count))
                    .data("last_request", DbValue::Number(last_request)),
            )
            .await?;
    }

    assert_eq!(
        adapter
            .count(
                Count::new("rate_limit").where_clause(
                    Where::new("count", DbValue::Number(2)).operator(WhereOperator::Gte),
                )
            )
            .await?,
        2
    );
    assert_eq!(
        adapter
            .count(
                Count::new("rate_limit").where_clause(
                    Where::new(
                        "key",
                        DbValue::StringArray(vec!["alpha".to_owned(), "omega".to_owned()])
                    )
                    .operator(WhereOperator::In),
                )
            )
            .await?,
        2
    );
    assert_eq!(
        adapter
            .count(
                Count::new("rate_limit").where_clause(
                    Where::new("key", DbValue::String("TA".to_owned()))
                        .operator(WhereOperator::Contains)
                        .insensitive(),
                )
            )
            .await?,
        1
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_supports_forward_reverse_and_limited_joins() -> Result<(), OpenAuthError> {
    let adapter = adapter().await?;
    seed_join_user(&adapter, "user_1", "ada@example.com").await?;
    seed_join_user(&adapter, "user_2", "grace@example.com").await?;
    seed_join_account(&adapter, "account_1", "user_1").await?;
    seed_join_account(&adapter, "account_2", "user_1").await?;
    seed_join_session(&adapter, "session_1", "user_1").await?;
    seed_join_session(&adapter, "session_2", "user_1").await?;
    seed_join_session(&adapter, "session_3", "user_2").await?;

    let users = adapter
        .find_many(
            FindMany::new("user")
                .sort_by(Sort::new("id", SortDirection::Asc))
                .select(["email"])
                .join("account", JoinOption::enabled().limit(1))
                .join("session", JoinOption::enabled()),
        )
        .await?;

    assert_eq!(users.len(), 2);
    assert_eq!(
        users[0].get("email"),
        Some(&DbValue::String("ada@example.com".to_owned()))
    );
    assert!(!users[0].contains_key("id"));
    assert!(matches!(
        users[0].get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
    ));
    assert!(matches!(
        users[0].get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.len() == 2
    ));
    assert!(matches!(
        users[1].get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.is_empty()
    ));

    let users_with_sessions = adapter
        .find_many(
            FindMany::new("user")
                .sort_by(Sort::new("id", SortDirection::Asc))
                .join("session", JoinOption::enabled().limit(1)),
        )
        .await?;

    assert_eq!(users_with_sessions.len(), 2);
    assert!(matches!(
        users_with_sessions[0].get("session"),
        Some(DbValue::RecordArray(sessions)) if sessions.len() == 1
    ));

    let user = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String("user_1".to_owned())))
                .join("account", JoinOption::enabled().limit(1))
                .join("session", JoinOption::enabled()),
        )
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("missing joined user".to_owned()))?;

    assert!(matches!(
        user.get("account"),
        Some(DbValue::RecordArray(accounts)) if accounts.len() == 1
    ));
    assert!(matches!(
        user.get("session"),
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
async fn sqlite_adapter_supports_core_auth_route_flows() -> Result<(), Box<dyn std::error::Error>> {
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
    let sign_up_body: Value = serde_json::from_slice(sign_up.body())?;
    let sign_up_cookie = cookie_header_from_response(&sign_up)?;

    let get_session = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&sign_up_cookie),
        )?)
        .await?;
    assert_eq!(get_session.status(), StatusCode::OK);

    let sign_out = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-out",
            "",
            Some(&sign_up_cookie),
        )?)
        .await?;
    assert_eq!(sign_out.status(), StatusCode::OK);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let sign_in_cookie = cookie_header_from_response(&sign_in)?;
    let sign_in_body: Value = serde_json::from_slice(sign_in.body())?;

    let update_session = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-session",
            r#"{}"#,
            Some(&sign_in_cookie),
        )?)
        .await?;
    assert_eq!(update_session.status(), StatusCode::BAD_REQUEST);

    let list_sessions = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/list-sessions",
            "",
            Some(&sign_in_cookie),
        )?)
        .await?;
    assert_eq!(list_sessions.status(), StatusCode::OK);

    let revoke_other = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/revoke-other-sessions",
            "",
            Some(&sign_in_cookie),
        )?)
        .await?;
    assert_eq!(revoke_other.status(), StatusCode::OK);

    let token = sign_in_body["token"]
        .as_str()
        .ok_or("missing sign-in token")?
        .to_owned();
    let revoke_session = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/revoke-session",
            &format!(r#"{{"token":"{token}"}}"#),
            Some(&sign_in_cookie),
        )?)
        .await?;
    assert_eq!(revoke_session.status(), StatusCode::OK);

    let _ = sign_up_body;
    Ok(())
}

#[tokio::test]
async fn sqlite_adapter_supports_password_reset_verifications(
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

fn router(adapter: Arc<SqliteAdapter>) -> Result<AuthRouter, OpenAuthError> {
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

#[allow(dead_code)]
fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some(secret().to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let cookies = openauth_core::cookies::set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        openauth_core::cookies::SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing string field `{field}`"
        ))),
    }
}

async fn seed_join_user(
    adapter: &SqliteAdapter,
    id: &str,
    email: &str,
) -> Result<(), OpenAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String(id.to_owned()))
                .data("name", DbValue::String(id.to_owned()))
                .data("email", DbValue::String(email.to_owned()))
                .data("email_verified", DbValue::Boolean(false))
                .data("image", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await?;
    Ok(())
}

async fn seed_join_account(
    adapter: &SqliteAdapter,
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

async fn seed_join_session(
    adapter: &SqliteAdapter,
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

fn sql_error(error: sqlx::Error) -> OpenAuthError {
    OpenAuthError::Adapter(error.to_string())
}
