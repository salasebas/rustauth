use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{Create, DbAdapter, DbValue, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, IpAddressOptions, OpenAuthOptions, SessionOptions};
use openauth_plugins::api_key::{
    api_key_with, default_key_hasher, ApiKeyConfiguration, ApiKeyOptions, ApiKeyReference,
    API_KEY_MODEL, INVALID_API_KEY, INVALID_REFERENCE_ID_FROM_API_KEY,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::helpers::{
    request_json, request_json_with_headers, sign_up, test_router, with_test_defaults,
};

#[tokio::test]
async fn api_key_can_mock_get_session_when_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_session_for_api_keys: true,
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Bea", "bea-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"session-key"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let session = request_json(
        &router,
        Method::GET,
        "/api/auth/get-session",
        Value::Null,
        None,
        Some(("x-api-key", key)),
    )
    .await?;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(session.body["user"]["id"], user.user_id);
    assert_eq!(session.body["session"]["token"], key);
    Ok(())
}

#[tokio::test]
async fn custom_api_key_getter_can_mock_session() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_session_for_api_keys: true,
                    custom_api_key_getter: Some(Arc::new(|_context, request| {
                        let key = request
                            .headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .and_then(|value| value.strip_prefix("Bearer "))
                            .map(str::to_owned);
                        Box::pin(async move { Ok(key) })
                    })),
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Bev", "bev-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"session-key"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;
    let bearer = format!("Bearer {key}");

    let session = request_json(
        &router,
        Method::GET,
        "/api/auth/get-session",
        Value::Null,
        None,
        Some(("authorization", &bearer)),
    )
    .await?;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(session.body["user"]["id"], user.user_id);
    assert_eq!(session.body["session"]["token"], key);
    Ok(())
}

#[tokio::test]
async fn short_api_key_header_is_rejected_when_session_hook_matches(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_session_for_api_keys: true,
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;

    let session = request_json(
        &router,
        Method::GET,
        "/api/auth/get-session",
        Value::Null,
        None,
        Some(("x-api-key", "short")),
    )
    .await?;
    assert_eq!(session.status, StatusCode::FORBIDDEN);
    assert_eq!(session.body["code"], INVALID_API_KEY);
    Ok(())
}

#[tokio::test]
async fn custom_validator_rejection_fails_api_key_session_mocking(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_session_for_api_keys: true,
                    custom_api_key_validator: Some(Arc::new(|_context, _key| {
                        Box::pin(async move { Ok(false) })
                    })),
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Val", "val-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"blocked"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let session = request_json(
        &router,
        Method::GET,
        "/api/auth/get-session",
        Value::Null,
        None,
        Some(("x-api-key", key)),
    )
    .await?;

    assert_eq!(session.status, StatusCode::FORBIDDEN);
    assert_eq!(session.body["code"], INVALID_API_KEY);
    Ok(())
}

#[tokio::test]
async fn org_owned_key_cannot_mock_user_session() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let raw_key = "A".repeat(64);
    let hashed_key = default_key_hasher(&raw_key);
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new(API_KEY_MODEL)
                .force_allow_id()
                .data("id", DbValue::String("org_key_1".to_owned()))
                .data("config_id", DbValue::String("default".to_owned()))
                .data("name", DbValue::String("org".to_owned()))
                .data("start", DbValue::String("AAAAAA".to_owned()))
                .data("prefix", DbValue::Null)
                .data("key", DbValue::String(hashed_key))
                .data("reference_id", DbValue::String("org_1".to_owned()))
                .data("refill_interval", DbValue::Null)
                .data("refill_amount", DbValue::Null)
                .data("last_refill_at", DbValue::Null)
                .data("enabled", DbValue::Boolean(true))
                .data("rate_limit_enabled", DbValue::Boolean(true))
                .data("rate_limit_time_window", DbValue::Number(86_400_000))
                .data("rate_limit_max", DbValue::Number(10))
                .data("request_count", DbValue::Number(0))
                .data("remaining", DbValue::Null)
                .data("last_request", DbValue::Null)
                .data("expires_at", DbValue::Null)
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .data("metadata", DbValue::Null)
                .data("permissions", DbValue::Null),
        )
        .await?;
    let router = test_router(
        adapter,
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_session_for_api_keys: true,
                    reference: ApiKeyReference::Organization,
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;

    let session = request_json(
        &router,
        Method::GET,
        "/api/auth/get-session",
        Value::Null,
        None,
        Some(("x-api-key", &raw_key)),
    )
    .await?;

    assert_eq!(session.status, StatusCode::UNAUTHORIZED);
    assert_eq!(session.body["code"], INVALID_REFERENCE_ID_FROM_API_KEY);
    Ok(())
}

#[tokio::test]
async fn api_key_session_hook_records_trusted_request_ip() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            plugins: vec![api_key_with(
                ApiKeyOptions::builder()
                    .configuration(ApiKeyConfiguration {
                        enable_session_for_api_keys: true,
                        ..ApiKeyConfiguration::default()
                    })
                    .build()?,
            )?],
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("test-secret-at-least-32-chars-long!".to_owned()),
            advanced: AdvancedOptions::default()
                .ip_address(IpAddressOptions::new().headers(["x-forwarded-for"])),
            ..OpenAuthOptions::default()
        },
    )?;
    let user = sign_up(&router, "Ip", "ip-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"ip-key"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let session = request_json_with_headers(
        &router,
        Method::GET,
        "/api/auth/get-session",
        Value::Null,
        None,
        &[("x-api-key", key), ("x-forwarded-for", "127.0.0.1")],
    )
    .await?;

    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(session.body["session"]["ip_address"], "127.0.0.1");
    Ok(())
}

#[tokio::test]
async fn api_key_session_hook_rejects_out_of_range_session_expiry(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let setup_router = test_router(
        adapter.clone(),
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_session_for_api_keys: true,
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;
    let user = sign_up(&setup_router, "Bo", "bo-api@example.com").await?;
    let created = request_json(
        &setup_router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"session-key"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created
        .body
        .get("key")
        .and_then(Value::as_str)
        .ok_or("missing api key")?;

    let router = test_router_with_options(
        adapter,
        OpenAuthOptions {
            plugins: vec![api_key_with(
                ApiKeyOptions::builder()
                    .configuration(ApiKeyConfiguration {
                        enable_session_for_api_keys: true,
                        ..ApiKeyConfiguration::default()
                    })
                    .build()?,
            )?],
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("test-secret-at-least-32-chars-long!".to_owned()),
            session: SessionOptions::default().expires_in(u64::MAX),
            on_api_error: openauth_core::options::OnApiErrorOptions::default().throw(true),
            ..OpenAuthOptions::default()
        },
    )?;

    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/get-session")
        .header("x-api-key", key)
        .body(Vec::new())?;
    let error = router
        .handle_async_server(request)
        .await
        .err()
        .ok_or("expected session expiry range error")?;

    assert!(matches!(
        error,
        OpenAuthError::NumericOutOfRange {
            context: "session.expires_in"
        }
    ));
    Ok(())
}

fn test_router_with_options(
    adapter: Arc<MemoryAdapter>,
    options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
    let adapter: Arc<dyn DbAdapter> = adapter;
    let context = create_auth_context_with_adapter(with_test_defaults(options), adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}
