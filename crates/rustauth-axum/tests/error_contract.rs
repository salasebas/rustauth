mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::options::RustAuthOptions;
use rustauth::RustAuth;
use rustauth_axum::{RustAuthAxumExt, RustAuthAxumOptions};
use tower::ServiceExt;

#[tokio::test]
async fn invalid_json_body_returns_stable_json_error() -> Result<(), Box<dyn std::error::Error>> {
    let app = auth_with_adapter(MemoryAdapter::new(), RustAuthOptions::default())
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com""#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "INVALID_REQUEST_BODY");
    assert!(body["message"]
        .as_str()
        .unwrap_or("")
        .contains("invalid JSON"));
    Ok(())
}

#[tokio::test]
async fn unsupported_content_type_returns_415_json_error() -> Result<(), Box<dyn std::error::Error>>
{
    let app = auth_with_adapter(MemoryAdapter::new(), RustAuthOptions::default())
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(
            request(
                Method::POST,
                "/api/auth/sign-in/email",
                "email=ada@example.com",
                None,
            )?
            .with_header(header::CONTENT_TYPE, "text/plain")?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "UNSUPPORTED_MEDIA_TYPE");
    Ok(())
}

#[tokio::test]
async fn internal_endpoint_errors_are_sanitized() -> Result<(), Box<dyn std::error::Error>> {
    let app = RustAuth::builder()
        .secret(SECRET)
        .production(true)
        .rate_limit(rustauth::options::RateLimitOptions::new().enabled(false))
        .async_endpoint(failing_endpoint("/fail"))
        .build()
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default())?;

    let response = app
        .oneshot(request(Method::GET, "/api/auth/fail", "", None)?)
        .await?;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(response).await?;
    assert_eq!(body["code"], "INTERNAL_SERVER_ERROR");
    assert_eq!(body["message"], "Internal Server Error");
    assert!(!body.to_string().contains("simulated internal failure"));
    Ok(())
}
