use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{OpenAuthOptions, SessionOptions};
use openauth_plugins::api_key::INVALID_API_KEY;
use openauth_plugins::api_key::{api_key_with_options, ApiKeyConfiguration, ApiKeyOptions};
use serde_json::{json, Value};

use super::helpers::{request_json, sign_up, test_router};

#[tokio::test]
async fn api_key_can_mock_get_session_when_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                enable_session_for_api_keys: true,
                ..ApiKeyConfiguration::default()
            },
        }),
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
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
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
            },
        }),
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
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                enable_session_for_api_keys: true,
                ..ApiKeyConfiguration::default()
            },
        }),
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
async fn api_key_session_hook_rejects_out_of_range_session_expiry(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let setup_router = test_router(
        adapter.clone(),
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                enable_session_for_api_keys: true,
                ..ApiKeyConfiguration::default()
            },
        }),
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
            plugins: vec![api_key_with_options(ApiKeyOptions {
                configuration: ApiKeyConfiguration {
                    enable_session_for_api_keys: true,
                    ..ApiKeyConfiguration::default()
                },
            })],
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("test-secret-at-least-32-chars-long!".to_owned()),
            session: SessionOptions::default().expires_in(u64::MAX),
            ..OpenAuthOptions::default()
        },
    )?;

    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/get-session")
        .header("x-api-key", key)
        .body(Vec::new())?;
    let error = router
        .handle_async(request)
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
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}
