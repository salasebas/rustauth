mod common;

use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use common::*;
use openauth::db::DbValue;
use openauth::{
    ApiRequest, EmailVerificationOptions, MemoryAdapter, OpenAuthError, OpenAuthOptions,
    VerificationEmail,
};
use openauth_axum::router;
use tower::ServiceExt;

#[tokio::test]
async fn email_verification_routes_work_over_axum() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = MemoryAdapter::new();
    let captured_token = Arc::new(Mutex::new(None::<String>));
    let token_sink = Arc::clone(&captured_token);
    let app = router(auth_with_adapter(
        adapter.clone(),
        OpenAuthOptions::default()
            .base_url("http://localhost:3000/api/auth")
            .email_verification(EmailVerificationOptions::default().send_verification_email(
                move |email: VerificationEmail, _request: Option<&ApiRequest>| {
                    let mut token = token_sink.lock().map_err(|_| {
                        OpenAuthError::Api("token capture lock poisoned".to_owned())
                    })?;
                    *token = Some(email.token);
                    Ok(())
                },
            )),
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

    let send = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/send-verification-email",
            r#"{"email":"ada@example.com","callbackURL":"/verified"}"#,
            None,
        )?)
        .await?;
    assert_eq!(send.status(), StatusCode::OK);
    let token = captured_token
        .lock()
        .map_err(|_| "token capture lock poisoned")?
        .clone()
        .ok_or("missing verification token")?;

    let verify = app
        .oneshot(request(
            Method::GET,
            &format!("/api/auth/verify-email?token={token}"),
            "",
            None,
        )?)
        .await?;

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
