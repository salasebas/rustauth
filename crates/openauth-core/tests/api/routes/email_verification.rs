use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use openauth_core::crypto::jwt::sign_jwt;
use openauth_core::options::{
    AfterEmailVerification, BeforeEmailVerification, EmailVerificationCallbackPayload,
    EmailVerificationOptions, SendVerificationEmail, VerificationEmail,
};
use serde_json::json;

use super::*;

#[derive(Default)]
struct CapturingVerificationSender {
    sent: StdMutex<Vec<VerificationEmail>>,
}

struct CountBefore(Arc<AtomicUsize>);

impl BeforeEmailVerification for CountBefore {
    fn before_email_verification(
        &self,
        _payload: EmailVerificationCallbackPayload,
        _request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct CountAfter(Arc<AtomicUsize>);

impl AfterEmailVerification for CountAfter {
    fn after_email_verification(
        &self,
        _payload: EmailVerificationCallbackPayload,
        _request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn verify_email_route_invokes_before_and_after_callbacks(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let sender = Arc::new(CapturingVerificationSender::default());
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            email_verification: EmailVerificationOptions {
                send_verification_email: Some(sender.clone()),
                before_email_verification: Some(Arc::new(CountBefore(Arc::clone(&before)))),
                after_email_verification: Some(Arc::new(CountAfter(Arc::clone(&after)))),
                ..EmailVerificationOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/send-verification-email",
            r#"{"email":"ada@example.com"}"#,
            None,
        )?)
        .await?;
    let token = sender
        .sent
        .lock()
        .map_err(|_| OpenAuthError::Api("sender lock poisoned".to_owned()))?
        .last()
        .ok_or("missing verification email")?
        .token
        .clone();
    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/verify-email?token={token}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(before.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 1);
    Ok(())
}

impl SendVerificationEmail for CapturingVerificationSender {
    fn send_verification_email(
        &self,
        email: VerificationEmail,
        _request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self.sent
            .lock()
            .map_err(|_| OpenAuthError::Api("sender lock poisoned".to_owned()))?
            .push(email);
        Ok(())
    }
}

#[tokio::test]
async fn send_verification_email_route_sends_for_current_unverified_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let sender = Arc::new(CapturingVerificationSender::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    adapter
        .insert_session(session(now, now + Duration::hours(1)))
        .await;
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            email_verification: EmailVerificationOptions {
                send_verification_email: Some(sender.clone()),
                ..EmailVerificationOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/send-verification-email",
            r#"{"email":"ada@example.com","callbackURL":"/welcome"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    let sent = sender
        .sent
        .lock()
        .map_err(|_| OpenAuthError::Api("sender lock poisoned".to_owned()))?;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].user.email, "ada@example.com");
    assert!(sent[0].url.contains("/verify-email?token="));
    assert!(sent[0].url.contains("callbackURL=%2Fwelcome"));
    assert!(!sent[0].token.is_empty());
    Ok(())
}

#[tokio::test]
async fn send_verification_email_route_does_not_reveal_missing_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let sender = Arc::new(CapturingVerificationSender::default());
    let router = router_with_options(
        adapter,
        OpenAuthOptions {
            email_verification: EmailVerificationOptions {
                send_verification_email: Some(sender.clone()),
                ..EmailVerificationOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/send-verification-email",
            r#"{"email":"missing@example.com"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    assert!(sender
        .sent
        .lock()
        .map_err(|_| OpenAuthError::Api("sender lock poisoned".to_owned()))?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn verify_email_route_marks_user_verified() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    let token = sign_jwt(&json!({ "email": "ada@example.com" }), secret(), 3600)?;
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/verify-email?token={token}"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    assert!(body["user"].is_null());
    let user = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(user.get("email_verified"), Some(&DbValue::Boolean(true)));
    Ok(())
}

#[tokio::test]
async fn verify_email_route_rejects_invalid_token() -> Result<(), Box<dyn std::error::Error>> {
    let router = router(Arc::new(RouteAdapter::default()))?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/verify-email?token=bad-token",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_TOKEN");
    Ok(())
}
