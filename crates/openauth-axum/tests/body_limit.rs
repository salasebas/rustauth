mod common;

use axum::http::{Method, StatusCode};
use common::*;
use openauth::OpenAuthOptions;
use openauth_axum::{router_with_options, OpenAuthAxumOptions};
use tower::ServiceExt;

#[tokio::test]
async fn configurable_body_limit_rejects_oversized_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = router_with_options(
        auth_with_options(OpenAuthOptions::default())?,
        OpenAuthAxumOptions::default().body_limit(8),
    )?;

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "PAYLOAD_TOO_LARGE");
    Ok(())
}

#[tokio::test]
async fn configurable_body_limit_allows_requests_within_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = router_with_options(
        auth_with_options(OpenAuthOptions::default())?,
        OpenAuthAxumOptions::default().body_limit(1024),
    )?;

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com"}"#,
            None,
        )?)
        .await?;

    assert_ne!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}
