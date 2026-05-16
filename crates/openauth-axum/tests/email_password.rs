mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use openauth::{MemoryAdapter, OpenAuthOptions};
use openauth_axum::router;
use tower::ServiceExt;

#[tokio::test]
async fn email_password_session_lifecycle_works_over_axum() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = MemoryAdapter::new();
    let app = router(auth_with_adapter(
        adapter.clone(),
        OpenAuthOptions::default().base_url("http://localhost:3000/api/auth"),
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
    let cookie = cookie_header(&sign_up).ok_or("missing sign-up cookie")?;
    let sign_up_body = body_json(sign_up).await?;
    assert!(sign_up_body["token"].is_string());
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);

    let get_session = app
        .clone()
        .oneshot(request(
            Method::GET,
            "/api/auth/get-session",
            "",
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(get_session.status(), StatusCode::OK);
    let session_body = body_json(get_session).await?;
    assert_eq!(session_body["user"]["email"], "ada@example.com");

    let sign_out = app
        .clone()
        .oneshot(
            json_request(Method::POST, "/api/auth/sign-out", "{}", Some(&cookie))?
                .with_header(header::ORIGIN, "http://localhost:3000")?,
        )
        .await?;
    assert_eq!(sign_out.status(), StatusCode::OK);
    assert!(cookie_header(&sign_out).is_some());

    let sign_in = app
        .oneshot(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"secret123"}"#,
            None,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let sign_in_body = body_json(sign_in).await?;
    assert_eq!(sign_in_body["user"]["email"], "ada@example.com");
    Ok(())
}
