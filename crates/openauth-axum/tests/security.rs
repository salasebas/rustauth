mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use openauth::{MemoryAdapter, OpenAuthOptions, RateLimitRule};
use openauth_axum::router;
use tower::ServiceExt;

#[tokio::test]
async fn csrf_origin_checks_are_preserved_over_axum() -> Result<(), Box<dyn std::error::Error>> {
    let app = router(auth_with_adapter(
        MemoryAdapter::new(),
        OpenAuthOptions::default().base_url("https://app.example.com/api/auth"),
    )?)?;

    let rejected = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/email",
                r#"{"email":"ada@example.com","password":"secret123"}"#,
                Some("better-auth.session_token=signed"),
            )?
            .with_header(header::ORIGIN, "https://evil.example.com")?,
        )
        .await?;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let rejected_body = body_json(rejected).await?;
    assert_eq!(rejected_body["code"], "INVALID_ORIGIN");

    let allowed = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-in/email",
                r#"{"email":"ada@example.com","password":"secret123"}"#,
                Some("better-auth.session_token=signed"),
            )?
            .with_header(header::ORIGIN, "https://app.example.com")?,
        )
        .await?;
    assert_ne!(allowed.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn core_rate_limit_runs_without_axum_middleware() -> Result<(), Box<dyn std::error::Error>> {
    let app = router(auth_with_adapter(
        MemoryAdapter::new(),
        OpenAuthOptions::default().rate_limit(
            openauth::RateLimitOptions::new()
                .enabled(true)
                .custom_rule("/ok", RateLimitRule { window: 60, max: 1 }),
        ),
    )?)?;

    for attempt in 0..2 {
        let response = app
            .clone()
            .oneshot(request(Method::GET, "/api/auth/ok", "", None)?)
            .await?;
        if attempt == 0 {
            assert_eq!(response.status(), StatusCode::OK);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(response.headers().contains_key("X-Retry-After"));
        }
    }
    Ok(())
}
