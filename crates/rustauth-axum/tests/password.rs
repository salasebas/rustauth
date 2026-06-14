mod common;

use std::sync::{Arc, Mutex};

use axum::http::{header, Method, Request, StatusCode};
use common::*;
use rustauth::db::MemoryAdapter;
use rustauth::error::RustAuthError;
use rustauth::options::PasswordResetEmail;
use rustauth::options::{PasswordOptions, RustAuthOptions, TrustedOriginOptions};
use rustauth_axum::{RustAuthAxumExt, RustAuthAxumOptions};
use rustauth_core::OutboundSendFuture;
use tower::ServiceExt;

#[tokio::test]
async fn password_reset_flow_works_over_axum() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let app = auth_with_adapter(adapter.clone(), RustAuthOptions::default())
        .await?
        .mount_at_base_path(RustAuthAxumOptions::default())?;

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
    let app = auth_with_adapter(
        adapter,
        RustAuthOptions::default()
            .trusted_origins(TrustedOriginOptions::Static(vec![
                "https://app.example.com".to_owned(),
            ]))
            .password(PasswordOptions::default().send_reset_password(
                move |email: PasswordResetEmail,
                      _request: Option<&Request<Vec<u8>>>|
                      -> OutboundSendFuture {
                    let url_sink = Arc::clone(&url_sink);
                    Box::pin(async move {
                        let mut url = url_sink.lock().map_err(|_| {
                            RustAuthError::Api("url capture lock poisoned".to_owned())
                        })?;
                        *url = Some(email.url);
                        Ok(())
                    })
                },
            )),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::new().infer_base_url_from_request(true))?;

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

    let url = wait_for_mutex_option(&captured_url).await?;
    assert!(url.starts_with("https://app.example.com/api/auth/reset-password/"));
    assert!(url.contains("callbackURL=%2Freset"));
    Ok(())
}

#[tokio::test]
async fn password_reset_url_does_not_infer_host_by_default(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let captured_url = Arc::new(Mutex::new(None::<String>));
    let url_sink = Arc::clone(&captured_url);
    let app = auth_with_adapter(
        adapter,
        RustAuthOptions::default()
            .base_url("https://app.example.com/api/auth")
            .password(PasswordOptions::default().send_reset_password(
                move |email: PasswordResetEmail,
                      _request: Option<&Request<Vec<u8>>>|
                      -> OutboundSendFuture {
                    let url_sink = Arc::clone(&url_sink);
                    Box::pin(async move {
                        let mut url = url_sink.lock().map_err(|_| {
                            RustAuthError::Api("url capture lock poisoned".to_owned())
                        })?;
                        *url = Some(email.url);
                        Ok(())
                    })
                },
            )),
    )
    .await?
    .mount_at_base_path(RustAuthAxumOptions::default())?;

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
        .oneshot(
            json_request(
                Method::POST,
                "/api/auth/request-password-reset",
                r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
                None,
            )?
            .with_header(header::HOST, "evil.example.com")?,
        )
        .await?;
    assert_eq!(request_reset.status(), StatusCode::OK);

    let url = wait_for_mutex_option(&captured_url).await?;
    assert!(url.starts_with("https://app.example.com/api/auth/reset-password/"));
    assert!(!url.contains("evil.example.com"));
    Ok(())
}
