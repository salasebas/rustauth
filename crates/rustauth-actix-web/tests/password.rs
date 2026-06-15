mod common;

use std::sync::{Arc, Mutex};

use actix_web::http::{header, Method, StatusCode};
use actix_web::test;
use common::*;
use http::Request;
use rustauth::db::MemoryAdapter;
use rustauth::error::RustAuthError;
use rustauth::options::PasswordResetEmail;
use rustauth::options::{PasswordOptions, RustAuthOptions, TrustedOriginOptions};
use rustauth_actix_web::RustAuthActixWebOptions;
use rustauth_core::OutboundSendFuture;

#[tokio::test]
async fn password_reset_flow_works_over_actix_web() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let auth = Arc::new(auth_with_adapter(adapter.clone(), RustAuthOptions::default()).await?);
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let sign_up = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let request_reset = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(request_reset.status(), StatusCode::OK);

    let token = reset_token(&adapter).await?;
    let reset = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/reset-password",
            &format!(r#"{{"token":"{token}","newPassword":"changed123"}}"#),
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(reset.status(), StatusCode::OK);

    let callback = test::call_service(
        &app,
        test_request(
            Method::GET,
            &format!("/api/auth/reset-password/{token}?callbackURL=/reset"),
            "",
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::FOUND);

    let sign_in = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"changed123"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(sign_in.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn password_reset_url_uses_inferred_base_url() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let captured_url = Arc::new(Mutex::new(None::<String>));
    let url_sink = Arc::clone(&captured_url);
    let auth = Arc::new(
        auth_with_adapter(
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
        .await?,
    );
    let app = mounted_app!(
        auth,
        RustAuthActixWebOptions::new().infer_base_url_from_request(true),
    );

    let sign_up = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .insert_header((header::HOST, "app.example.com"))
        .to_request(),
    )
    .await;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let request_reset = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
            None,
        )
        .insert_header((header::HOST, "app.example.com"))
        .to_request(),
    )
    .await;
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
    let auth = Arc::new(
        auth_with_adapter(
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
        .await?,
    );
    let app = mounted_app!(auth, RustAuthActixWebOptions::default());

    let sign_up = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let request_reset = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/request-password-reset",
            r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
            None,
        )
        .insert_header((header::HOST, "evil.example.com"))
        .to_request(),
    )
    .await;
    assert_eq!(request_reset.status(), StatusCode::OK);

    let url = wait_for_mutex_option(&captured_url).await?;
    assert!(url.starts_with("https://app.example.com/api/auth/reset-password/"));
    assert!(!url.contains("evil.example.com"));
    Ok(())
}
