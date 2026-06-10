use std::sync::Arc;

use http::{Method, StatusCode};
use serde_json::Value;

use super::common::{bearer_request, router, seed_user_and_session, TestAdapter};

#[tokio::test]
async fn raw_session_token_is_accepted_when_signature_is_not_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    seed_user_and_session(&adapter).await;
    let router = router(adapter, openauth_plugins::bearer::bearer())?;

    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/get-session",
            "token_1",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["session"]["token"], "token_1");
    Ok(())
}

#[tokio::test]
async fn raw_session_token_is_rejected_when_signature_is_required(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    seed_user_and_session(&adapter).await;
    let router = router(
        adapter,
        openauth_plugins::bearer::bearer_with(openauth_plugins::bearer::BearerOptions {
            require_signature: true,
        }),
    )?;

    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/get-session",
            "token_1",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body.is_null());
    Ok(())
}

#[test]
fn bearer_options_serialize_with_upstream_camel_case() {
    let plugin = openauth_plugins::bearer::bearer_with(openauth_plugins::bearer::BearerOptions {
        require_signature: true,
    });

    assert_eq!(
        plugin.options,
        Some(serde_json::json!({ "requireSignature": true }))
    );
}
