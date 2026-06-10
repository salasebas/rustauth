use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::api_key::{
    api_key_with, ApiKeyConfiguration, ApiKeyOptions, ApiKeyRateLimitOptions,
};
use serde_json::json;

use super::helpers::{request_json, server_request_json, sign_up, test_router};

#[tokio::test]
async fn create_applies_explicit_rate_limit_enabled_false() -> Result<(), Box<dyn std::error::Error>>
{
    let router = test_router(
        Arc::new(MemoryAdapter::new()),
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration::default())
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Rae", "rae-rate-limit@example.com").await?;

    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"userId": user.user_id, "rateLimitEnabled": false}),
        None,
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["rateLimitEnabled"], false);
    Ok(())
}

#[tokio::test]
async fn create_defaults_rate_limit_enabled_true_when_omitted(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = test_router(
        Arc::new(MemoryAdapter::new()),
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration::default())
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Rem", "rem-rate-limit@example.com").await?;

    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"userId": user.user_id}),
        None,
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["rateLimitEnabled"], true);
    Ok(())
}

#[tokio::test]
async fn create_respects_disabled_rate_limit_from_plugin_options(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = test_router(
        Arc::new(MemoryAdapter::new()),
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_metadata: true,
                    rate_limit: ApiKeyRateLimitOptions {
                        enabled: false,
                        time_window: 1_000,
                        max_requests: 10,
                    },
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Rio", "rio-rate-limit@example.com").await?;

    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"userId": user.user_id}),
        None,
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["rateLimitEnabled"], false);
    assert_eq!(created.body["rateLimitTimeWindow"], 1_000);
    assert_eq!(created.body["rateLimitMax"], 10);
    Ok(())
}

#[tokio::test]
async fn verify_skips_rate_limit_when_rate_limit_enabled_is_false(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = test_router(
        Arc::new(MemoryAdapter::new()),
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration::default())
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Ryn", "ryn-rate-limit@example.com").await?;

    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({
            "userId": user.user_id,
            "rateLimitEnabled": false,
            "rateLimitMax": 1,
            "rateLimitTimeWindow": 60_000
        }),
        None,
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    for _ in 0..3 {
        let verified = request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/verify",
            json!({"key": key}),
            None,
            None,
        )
        .await?;
        assert_eq!(verified.status, StatusCode::OK);
        assert_eq!(verified.body["valid"], true);
    }
    Ok(())
}
