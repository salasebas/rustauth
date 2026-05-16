mod common;

use axum::http::{Method, StatusCode};
use common::*;
use openauth::{MemoryAdapter, OpenAuthOptions};
use openauth_axum::router;
use tower::ServiceExt;

#[tokio::test]
async fn password_reset_flow_works_over_axum() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let app = router(auth_with_adapter(
        adapter.clone(),
        OpenAuthOptions::default(),
    )?)?;

    let sign_up = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let request_reset = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com"}"#,
            None,
        )?)
        .await?;
    assert_eq!(request_reset.status(), StatusCode::OK);

    let token = reset_token(&adapter).await?;
    let reset = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/reset-password",
            &format!(r#"{{"token":"{token}","newPassword":"changed123"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(reset.status(), StatusCode::OK);

    let callback = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/api/auth/reset-password/{token}?callbackURL=/reset"),
            "",
            None,
        )?)
        .await?;
    assert_eq!(callback.status(), StatusCode::FOUND);

    let sign_in = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"changed123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    Ok(())
}
