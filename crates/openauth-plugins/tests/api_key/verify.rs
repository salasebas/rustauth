use std::collections::BTreeMap;
use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::{DbAdapter, MemoryAdapter};
use openauth_core::options::{AdvancedOptions, BackgroundTaskRunner, OpenAuthOptions};
use openauth_plugins::api_key::{
    api_key, api_key_with_options, ApiKeyConfiguration, ApiKeyGeneratorInput, ApiKeyOptions,
    INVALID_API_KEY, KEY_NOT_FOUND, RATE_LIMIT_EXCEEDED,
};
use serde_json::json;

use super::helpers::{
    request_json, server_request_json, sign_up, CountingBackgroundRunner, DelayedUpdateAdapter,
};

#[tokio::test]
async fn verification_decrements_remaining_and_blocks_exhausted_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = super::helpers::test_router(adapter, api_key())?;
    let user = sign_up(&router, "Dee", "dee-api@example.com").await?;

    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"limited","userId": user.user_id, "remaining":1}),
        None,
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key = created.body["key"].as_str().ok_or("missing key")?;

    let first = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(first.body["valid"], true);
    assert_eq!(first.body["key"]["remaining"], 0);

    let second = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(second.body["valid"], false);
    assert_eq!(second.body["error"]["code"], "USAGE_EXCEEDED");
    Ok(())
}

#[tokio::test]
async fn concurrent_verification_consumes_remaining_only_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let memory = Arc::new(MemoryAdapter::new());
    let adapter: Arc<dyn DbAdapter> = Arc::new(DelayedUpdateAdapter::new(
        memory,
        std::time::Duration::from_millis(50),
    ));
    let router = super::helpers::test_router_with_adapter(adapter, vec![api_key()])?;
    let user = sign_up(&router, "Race", "race-api@example.com").await?;

    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"single-use","userId": user.user_id, "remaining":1}),
        None,
        None,
    )
    .await?;
    let key = created.body["key"]
        .as_str()
        .ok_or("missing api key")?
        .to_owned();

    let (first, second) = tokio::join!(
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/verify",
            json!({"key": key}),
            None,
            None,
        ),
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/verify",
            json!({"key": key}),
            None,
            None,
        ),
    );
    let responses = [first?, second?];
    let valid = responses
        .iter()
        .filter(|response| response.body["valid"] == true)
        .count();
    let usage_exceeded = responses
        .iter()
        .filter(|response| response.body["error"]["code"] == "USAGE_EXCEEDED")
        .count();

    assert_eq!(valid, 1, "only one concurrent verification should succeed");
    assert_eq!(
        usage_exceeded, 1,
        "the second concurrent verification should observe exhausted usage"
    );
    Ok(())
}

#[tokio::test]
async fn verification_enforces_rate_limit_window() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = super::helpers::test_router(adapter, api_key())?;
    let user = sign_up(&router, "Eon", "eon-api@example.com").await?;
    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({
            "name": "burst",
            "userId": user.user_id,
            "rateLimitMax": 1,
            "rateLimitTimeWindow": 60_000
        }),
        None,
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let first = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(first.body["valid"], true);

    let second = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(second.body["valid"], false);
    assert_eq!(second.body["error"]["code"], RATE_LIMIT_EXCEEDED);
    assert!(second.body["error"]["tryAgainIn"]
        .as_i64()
        .is_some_and(|value| value > 0));
    Ok(())
}

#[tokio::test]
async fn concurrent_verification_enforces_rate_limit_max_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let memory = Arc::new(MemoryAdapter::new());
    let adapter: Arc<dyn DbAdapter> = Arc::new(DelayedUpdateAdapter::new(
        memory,
        std::time::Duration::from_millis(50),
    ));
    let router = super::helpers::test_router_with_adapter(adapter, vec![api_key()])?;
    let user = sign_up(&router, "Rate Race", "rate-race-api@example.com").await?;
    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({
            "name": "single-request-window",
            "userId": user.user_id,
            "rateLimitMax": 1,
            "rateLimitTimeWindow": 60_000
        }),
        None,
        None,
    )
    .await?;
    let key = created.body["key"]
        .as_str()
        .ok_or("missing api key")?
        .to_owned();

    let (first, second) = tokio::join!(
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/verify",
            json!({"key": key}),
            None,
            None,
        ),
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/verify",
            json!({"key": key}),
            None,
            None,
        ),
    );
    let responses = [first?, second?];
    let valid = responses
        .iter()
        .filter(|response| response.body["valid"] == true)
        .count();
    let rate_limited = responses
        .iter()
        .filter(|response| response.body["error"]["code"] == RATE_LIMIT_EXCEEDED)
        .count();

    assert_eq!(valid, 1, "only one request should fit in the window");
    assert_eq!(rate_limited, 1, "the competing request should be limited");
    Ok(())
}

#[tokio::test]
async fn verification_refills_remaining_after_interval() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = super::helpers::test_router(adapter, api_key())?;
    let user = sign_up(&router, "Fin", "fin-api@example.com").await?;
    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({
            "name": "refill",
            "userId": user.user_id,
            "remaining": 1,
            "refillAmount": 2,
            "refillInterval": 1
        }),
        None,
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let first = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(first.body["valid"], true);

    tokio::time::sleep(std::time::Duration::from_millis(2)).await;

    let second = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(second.body["valid"], true);
    assert_eq!(second.body["key"]["remaining"], 1);
    Ok(())
}

#[tokio::test]
async fn deferred_updates_use_background_runner_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let runner = Arc::new(CountingBackgroundRunner::default());
    let runner_for_options: Arc<dyn BackgroundTaskRunner> = runner.clone();
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            plugins: vec![api_key_with_options(ApiKeyOptions {
                configuration: ApiKeyConfiguration {
                    defer_updates: true,
                    ..ApiKeyConfiguration::default()
                },
            })],
            advanced: AdvancedOptions::default().background_tasks(runner_for_options),
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    let adapter_dyn: Arc<dyn DbAdapter> = adapter;
    let router = AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter_dyn),
    )?;
    let user = sign_up(&router, "Gen", "gen-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"deferred"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(verified.body["valid"], true);
    assert_eq!(runner.calls(), 1);
    Ok(())
}

#[tokio::test]
async fn verification_enforces_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = super::helpers::test_router(adapter, api_key())?;
    let user = sign_up(&router, "Han", "han-api@example.com").await?;
    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({
            "name":"scoped",
            "userId": user.user_id,
            "permissions": {"post": ["read"]}
        }),
        None,
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let allowed = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key, "permissions": {"post": ["read"]}}),
        None,
        None,
    )
    .await?;
    assert_eq!(allowed.body["valid"], true);

    let denied = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key, "permissions": {"post": ["delete"]}}),
        None,
        None,
    )
    .await?;
    assert_eq!(denied.body["valid"], false);
    assert_eq!(denied.body["error"]["code"], KEY_NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn default_permissions_are_applied_on_create() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = super::helpers::test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                default_permissions: Some(BTreeMap::from([(
                    "post".to_owned(),
                    vec!["read".to_owned()],
                )])),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Ian", "ian-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"default-scope"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["permissions"]["post"][0], "read");
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key, "permissions": {"post": ["read"]}}),
        None,
        None,
    )
    .await?;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.body["valid"], true);
    Ok(())
}

#[tokio::test]
async fn custom_key_generator_and_validator_are_used() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = super::helpers::test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                custom_key_generator: Some(Arc::new(|input: ApiKeyGeneratorInput| {
                    Box::pin(
                        async move { Ok(format!("{}blocked", input.prefix.unwrap_or_default())) },
                    )
                })),
                custom_api_key_validator: Some(Arc::new(|_context, key| {
                    let key = key.to_owned();
                    Box::pin(async move { Ok(key != "blocked") })
                })),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Ivy", "ivy-api@example.com").await?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"custom"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["key"], "blocked");

    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": "blocked"}),
        None,
        None,
    )
    .await?;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.body["valid"], false);
    assert_eq!(verified.body["error"]["code"], INVALID_API_KEY);
    Ok(())
}
