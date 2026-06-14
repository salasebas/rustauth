mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, Response, StatusCode};
use axum::middleware::{self, Next};
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::RustAuthOptions;
use rustauth_axum::{RustAuthAxumExt, RustAuthAxumOptions};
use tower::ServiceExt;

#[tokio::test]
async fn configurable_body_limit_rejects_oversized_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_options(RustAuthOptions::default())
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default().body_limit(8))?;

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body = body_json(response).await?;
    assert_eq!(body["code"], "PAYLOAD_TOO_LARGE");
    Ok(())
}

#[tokio::test]
async fn configurable_body_limit_allows_requests_within_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_options(RustAuthOptions::default())
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default().body_limit(1024))?;

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

#[tokio::test]
async fn body_consuming_middleware_before_auth_routes_returns_stable_json_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(MemoryAdapter::new(), RustAuthOptions::default())
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default())?
        .layer(middleware::from_fn(drain_body_before_auth));

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    Ok(())
}

async fn drain_body_before_auth(request: Request<Body>, next: Next) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let _ = to_bytes(body, BODY_LIMIT).await;
    next.run(Request::from_parts(parts, Body::empty())).await
}
