use std::sync::Arc;

use http::{HeaderMap, Method, StatusCode};
use serde_json::Value;

use super::common::{
    assert_exposes_header, auth_token_header, bearer_request, json_request, router,
    sign_up_and_tokens, TestAdapter,
};

#[tokio::test]
async fn sign_up_response_exposes_auth_token_header() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, openauth_plugins::bearer::bearer())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
            HeaderMap::new(),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(auth_token_header(&response).is_some_and(|token| token.contains('.')));
    assert_exposes_header(&response, "set-auth-token")?;
    Ok(())
}

#[tokio::test]
async fn get_session_accepts_signed_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, openauth_plugins::bearer::bearer())?;
    let tokens = sign_up_and_tokens(&router).await?;

    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/get-session",
            &tokens.signed,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["session"]["token"], tokens.raw);
    assert_eq!(body["user"]["email"], "ada@example.com");
    Ok(())
}

#[tokio::test]
async fn list_sessions_accepts_signed_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, openauth_plugins::bearer::bearer())?;
    let tokens = sign_up_and_tokens(&router).await?;

    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/list-sessions",
            &tokens.signed,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body.as_array().map(Vec::len), Some(1));
    Ok(())
}

#[tokio::test]
async fn sign_up_body_token_can_be_used_as_raw_bearer() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, openauth_plugins::bearer::bearer())?;
    let tokens = sign_up_and_tokens(&router).await?;

    let response = router
        .handle_async(bearer_request(
            Method::GET,
            "/api/auth/get-session",
            &tokens.raw,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["session"]["token"], tokens.raw);
    Ok(())
}

#[tokio::test]
async fn sign_out_expired_cookie_does_not_emit_auth_token_header(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(TestAdapter::default());
    let router = router(adapter, openauth_plugins::bearer::bearer())?;
    let tokens = sign_up_and_tokens(&router).await?;

    let response = router
        .handle_async(bearer_request(
            Method::POST,
            "/api/auth/sign-out",
            &tokens.signed,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(auth_token_header(&response).is_none());
    Ok(())
}
