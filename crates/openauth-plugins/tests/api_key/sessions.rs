use std::sync::Arc;

use http::{header, Method, StatusCode};
use openauth_core::db::MemoryAdapter;
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
