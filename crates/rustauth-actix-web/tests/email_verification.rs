mod common;

use std::sync::{Arc, Mutex};

use actix_web::http::{Method, StatusCode};
use actix_web::test;
use common::*;
use http::Request;
use rustauth::db::DbValue;
use rustauth::db::MemoryAdapter;
use rustauth::error::RustAuthError;
use rustauth::options::{
    EmailVerificationOptions, RustAuthOptions, TrustedOriginOptions, VerificationEmail,
};
use rustauth_actix_web::RustAuthActixWebOptions;
use rustauth_core::OutboundSendFuture;

#[tokio::test]
async fn email_verification_routes_work_over_actix_web() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let captured_token = Arc::new(Mutex::new(None::<String>));
    let token_sink = Arc::clone(&captured_token);
    let auth = Arc::new(
        auth_with_adapter(
            adapter.clone(),
            RustAuthOptions::default()
                .base_url("http://localhost:3000/api/auth")
                .email_verification(EmailVerificationOptions::default().send_verification_email(
                    move |email: VerificationEmail,
                          _request: Option<&Request<Vec<u8>>>|
                          -> OutboundSendFuture {
                        let token_sink = Arc::clone(&token_sink);
                        Box::pin(async move {
                            let mut token = token_sink.lock().map_err(|_| {
                                RustAuthError::Api("token capture lock poisoned".to_owned())
                            })?;
                            *token = Some(email.token);
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

    let send = test::call_service(
        &app,
        json_test_request(
            Method::POST,
            "/api/auth/send-verification-email",
            r#"{"email":"ada@example.com","callbackURL":"/verified"}"#,
            None,
        )
        .to_request(),
    )
    .await;
    assert_eq!(send.status(), StatusCode::OK);
    let token = wait_for_mutex_option(&captured_token).await?;

    let verify = test::call_service(
        &app,
        test_request(
            Method::GET,
            &format!("/api/auth/verify-email?token={token}"),
            "",
            None,
        )
        .to_request(),
    )
    .await;

    assert_eq!(verify.status(), StatusCode::OK);
    let body = body_json(verify).await?;
    assert_eq!(body["status"], true);
    assert!(body["user"].is_null());
    let user = adapter
        .records("user")
        .await
        .into_iter()
        .find(|record| record.get("email") == Some(&DbValue::String("ada@example.com".to_owned())))
        .ok_or("missing verified user")?;
    assert_eq!(user.get("email_verified"), Some(&DbValue::Boolean(true)));
    Ok(())
}

#[tokio::test]
async fn email_verification_url_uses_inferred_base_url() -> Result<(), Box<dyn std::error::Error>> {
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
                .email_verification(
                    EmailVerificationOptions::default()
                        .send_verification_email(
                            move |email: VerificationEmail,
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
                        )
                        .send_on_sign_up(true),
                ),
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
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","callbackURL":"/verified"}"#,
            None,
        )
        .insert_header((actix_web::http::header::HOST, "app.example.com"))
        .to_request(),
    )
    .await;

    assert_eq!(sign_up.status(), StatusCode::OK);
    let url = wait_for_mutex_option(&captured_url).await?;
    assert!(url.starts_with("https://app.example.com/api/auth/verify-email?token="));
    assert!(url.contains("callbackURL=%2Fverified"));
    Ok(())
}
