mod common;

use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::*;
use openauth::options::PasswordResetEmail;
use openauth::{ApiRequest, MemoryAdapter, OpenAuthError, OpenAuthOptions, PasswordOptions};
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

#[tokio::test]
async fn password_reset_url_uses_inferred_base_url() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let captured_url = Arc::new(Mutex::new(None::<String>));
    let url_sink = Arc::clone(&captured_url);
    let app = router(auth_with_adapter(
        adapter,
        OpenAuthOptions::default().password(PasswordOptions::default().send_reset_password(
            move |email: PasswordResetEmail, _request: Option<&ApiRequest>| {
                let mut url = url_sink
                    .lock()
                    .map_err(|_| OpenAuthError::Api("url capture lock poisoned".to_owned()))?;
                *url = Some(email.url);
                Ok(())
            },
        )),
    )?)?;

    let sign_up = app
        .clone()
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/sign-up/email",
                r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
                None,
            )?
            .with_header(axum::http::header::HOST, "app.example.com")?,
        )
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let request_reset = app
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/request-password-reset",
                r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
                None,
            )?
            .with_header(axum::http::header::HOST, "app.example.com")?,
        )
        .await?;
    assert_eq!(request_reset.status(), StatusCode::OK);

    let url = captured_url
        .lock()
        .map_err(|_| "url capture lock poisoned")?
        .clone()
        .ok_or("missing reset url")?;
    assert!(url.starts_with("https://app.example.com/api/auth/reset-password/"));
    assert!(url.contains("callbackURL=%2Freset"));
    Ok(())
}
