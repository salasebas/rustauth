use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::db::DbAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, EmailPasswordOptions, OpenAuthOptions, RateLimitConsumeInput, RateLimitRule,
    RateLimitStore,
};
use openauth_core::plugin::AuthPlugin;
use openauth_plugins::admin::{admin, AdminOptions};
use openauth_plugins::api_key::api_key;
use openauth_plugins::jwt::jwt;
use openauth_plugins::multi_session::multi_session;
use openauth_plugins::one_time_token::one_time_token;
use openauth_plugins::organization::organization;
use openauth_plugins::two_factor::{two_factor, TwoFactorOptions};
use openauth_redis::RedisRateLimitStore;
use openauth_sqlx::{MySqlAdapter, PostgresAdapter};
use serde_json::{json, Value};
use sqlx::mysql::MySqlPoolOptions;
use sqlx::postgres::PgPoolOptions;

const DEFAULT_POSTGRES_URL: &str = "postgres://user:password@localhost:5432/openauth";
const DEFAULT_MYSQL_URL: &str = "mysql://user:password@localhost:3306/openauth";
const DEFAULT_REDIS_URL: &str = "redis://localhost:6379";
const DEFAULT_VALKEY_URL: &str = "redis://localhost:6380";
const TEST_BASE_URL: &str = "http://localhost:3000";
const TEST_SECRET: &str = "secret-a-at-least-32-chars-long!!";

#[ignore = "requires `docker compose up -d postgres`"]
#[tokio::test]
async fn docker_postgres_plugins_end_to_end_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(matrix_options()?)?;
    let url = env_or("OPENAUTH_TEST_POSTGRES_URL", DEFAULT_POSTGRES_URL);
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .map_err(|error| preflight_error("postgres", &url, error))?;
    let adapter = Arc::new(PostgresAdapter::with_schema(
        pool,
        context.db_schema.clone(),
    ));

    adapter.create_schema(&context.db_schema, None).await?;
    plugin_smoke(adapter).await
}

#[ignore = "requires `docker compose up -d mysql`"]
#[tokio::test]
async fn docker_mysql_plugins_end_to_end_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(matrix_options()?)?;
    let url = env_or("OPENAUTH_TEST_MYSQL_URL", DEFAULT_MYSQL_URL);
    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .map_err(|error| preflight_error("mysql", &url, error))?;
    let adapter = Arc::new(MySqlAdapter::with_schema(pool, context.db_schema.clone()));

    adapter.create_schema(&context.db_schema, None).await?;
    plugin_smoke(adapter).await
}

#[ignore = "requires `docker compose up -d redis valkey`"]
#[tokio::test]
async fn docker_redis_and_valkey_rate_limit_store_are_atomic(
) -> Result<(), Box<dyn std::error::Error>> {
    for (name, env, default_url) in [
        ("redis", "OPENAUTH_TEST_REDIS_URL", DEFAULT_REDIS_URL),
        ("valkey", "OPENAUTH_TEST_VALKEY_URL", DEFAULT_VALKEY_URL),
    ] {
        let url = env_or(env, default_url);
        let store = RedisRateLimitStore::connect(&url).await.map_err(|error| {
            OpenAuthError::Adapter(format!(
                "{name} rate-limit preflight failed for `{url}`: {error}"
            ))
        })?;
        let key = format!("plugins-matrix:{}:{}", name, unique_suffix());
        let rule = RateLimitRule::new(60, 1);
        let first = store
            .consume(RateLimitConsumeInput {
                key: key.clone(),
                rule: rule.clone(),
                now_ms: now_ms(),
            })
            .await?;
        let second = store
            .consume(RateLimitConsumeInput {
                key,
                rule,
                now_ms: now_ms(),
            })
            .await?;

        assert!(first.permitted, "{name} should allow the first consume");
        assert!(!second.permitted, "{name} should reject the second consume");
    }
    Ok(())
}

async fn plugin_smoke(adapter: Arc<dyn DbAdapter>) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(matrix_options()?, adapter.clone())?;
    let router =
        AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))?;
    let suffix = unique_suffix();
    let user = request_json(
        &router,
        Method::POST,
        "/api/auth/sign-up/email",
        json!({
            "name": "Matrix User",
            "email": format!("matrix-{suffix}@example.com"),
            "password": "secret123"
        }),
        None,
    )
    .await?;
    assert_eq!(user.status, StatusCode::OK);
    let cookie = user.set_cookie.ok_or("missing sign-up cookie")?;
    let user_id = user.body["user"]["id"].as_str().ok_or("missing user id")?;

    let organization = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name": "Matrix Org", "slug": format!("matrix-{suffix}")}),
        Some(&cookie),
    )
    .await?;
    assert_eq!(organization.status, StatusCode::OK);
    assert_eq!(organization.body["members"][0]["role"], "owner");

    let key = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name": "matrix-key", "userId": user_id, "remaining": 1}),
        None,
    )
    .await?;
    assert_eq!(key.status, StatusCode::OK);
    let raw_key = key.body["key"].as_str().ok_or("missing api key")?;
    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": raw_key}),
        None,
    )
    .await?;
    assert_eq!(verified.body["valid"], true);

    let token = request_json(
        &router,
        Method::GET,
        "/api/auth/token",
        Value::Null,
        Some(&cookie),
    )
    .await?;
    assert_eq!(token.status, StatusCode::OK);
    assert!(token.body["token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    let jwks = request_json(&router, Method::GET, "/api/auth/jwks", Value::Null, None).await?;
    assert_eq!(jwks.status, StatusCode::OK);
    assert!(jwks.body["keys"]
        .as_array()
        .is_some_and(|keys| !keys.is_empty()));

    let one_time = request_json(
        &router,
        Method::GET,
        "/api/auth/one-time-token/generate",
        Value::Null,
        Some(&cookie),
    )
    .await?;
    assert_eq!(one_time.status, StatusCode::OK);
    let one_time_token = one_time.body["token"]
        .as_str()
        .ok_or("missing one-time token")?;
    let one_time_verified = request_json(
        &router,
        Method::POST,
        "/api/auth/one-time-token/verify",
        json!({"token": one_time_token}),
        None,
    )
    .await?;
    assert_eq!(one_time_verified.status, StatusCode::OK);

    let sessions = request_json(
        &router,
        Method::GET,
        "/api/auth/multi-session/list-device-sessions",
        Value::Null,
        Some(&cookie),
    )
    .await?;
    assert_eq!(sessions.status, StatusCode::OK);
    assert!(sessions
        .body
        .as_array()
        .is_some_and(|sessions| !sessions.is_empty()));

    Ok(())
}

fn matrix_options() -> Result<OpenAuthOptions, OpenAuthError> {
    Ok(OpenAuthOptions {
        base_url: Some(TEST_BASE_URL.to_owned()),
        secret: Some(TEST_SECRET.to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        plugins: matrix_plugins()?,
        email_password: EmailPasswordOptions::new().enabled(true),
        development: true,
        ..OpenAuthOptions::default()
    })
}

fn matrix_plugins() -> Result<Vec<AuthPlugin>, OpenAuthError> {
    Ok(vec![
        admin(AdminOptions::default()),
        organization(),
        api_key(),
        jwt()?,
        one_time_token(),
        multi_session(),
        two_factor(TwoFactorOptions::default()),
    ])
}

struct TestResponse {
    status: StatusCode,
    body: Value,
    set_cookie: Option<String>,
}

async fn request_json(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
) -> Result<TestResponse, Box<dyn std::error::Error>> {
    let payload = if matches!(body, Value::Null) {
        Vec::new()
    } else {
        serde_json::to_vec(&body)?
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("{TEST_BASE_URL}{path}"));
    if !payload.is_empty() {
        builder = builder
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, TEST_BASE_URL);
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }

    let response = router.handle_async(builder.body(payload)?).await?;
    let status = response.status();
    let set_cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("open-auth.session_token="))
        .and_then(|value| value.split(';').next().map(str::to_owned));
    let body = if response.body().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.body())?
    };
    Ok(TestResponse {
        status,
        body,
        set_cookie,
    })
}

fn env_or(name: &str, default_url: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default_url.to_owned())
}

fn preflight_error(adapter: &str, database_url: &str, error: sqlx::Error) -> OpenAuthError {
    OpenAuthError::Adapter(format!(
        "{adapter} plugin matrix preflight failed for `{database_url}`: {error}. Start Docker Compose or override the test URL with the matching OPENAUTH_TEST_*_URL variable."
    ))
}

fn unique_suffix() -> String {
    format!("{}-{}", now_ms(), std::process::id())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .ok()
        .and_then(|millis| i64::try_from(millis).ok())
        .unwrap_or_default()
}
