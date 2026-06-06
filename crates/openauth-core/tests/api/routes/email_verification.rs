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
async fn verify_email_auto_sign_in_creates_session_without_current_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    let token = sign_jwt(&json!({ "email": "ada@example.com" }), secret(), 3600)?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            email_verification: EmailVerificationOptions::default()
                .auto_sign_in_after_verification(true),
            ..OpenAuthOptions::default()
        },
    )?;

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
    assert_eq!(adapter.len("session").await, 1);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn verify_email_auto_sign_in_reuses_matching_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
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
    let token = sign_jwt(&json!({ "email": "ada@example.com" }), secret(), 3600)?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            email_verification: EmailVerificationOptions::default()
                .auto_sign_in_after_verification(true),
            ..OpenAuthOptions::default()
        },
    )?;
    let cookie = signed_session_cookie("token_1")?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/verify-email?token={token}"),
            "",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["status"], true);
    assert!(body["user"].is_null());
    assert_eq!(adapter.len("session").await, 1);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
    Ok(())
}

#[tokio::test]
async fn verify_email_change_email_does_not_auto_sign_in() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: true,
            ..user(now)
        })
        .await;
    let token = sign_jwt(
        &json!({
            "email": "ada@example.com",
            "updateTo": "new@example.com",
            "requestType": "change-email-verification"
        }),
        secret(),
        3600,
    )?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            email_verification: EmailVerificationOptions::default()
                .auto_sign_in_after_verification(true),
            ..OpenAuthOptions::default()
        },
    )?;

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
    assert_eq!(body["user"]["email"], "new@example.com");
    assert!(adapter.is_empty("session").await);
    assert!(set_cookie_values(&response).is_empty());
    Ok(())
}

#[tokio::test]
async fn verify_email_auto_sign_in_sets_cookie_on_callback_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    let token = sign_jwt(&json!({ "email": "ada@example.com" }), secret(), 3600)?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
            email_verification: EmailVerificationOptions::default()
                .auto_sign_in_after_verification(true),
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/verify-email?token={token}&callbackURL=/callback"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/callback")
    );
    assert_eq!(adapter.len("session").await, 1);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.contains("session_token=")));
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
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
            ..OpenAuthOptions::default()
        },
    )?;

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

#[tokio::test]
async fn verify_email_route_redirects_to_trusted_callback() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    let token = sign_jwt(&json!({ "email": "ada@example.com" }), secret(), 3600)?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/verify-email?token={token}&callbackURL=/callback"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/callback")
    );
    let user = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(user.get("email_verified"), Some(&DbValue::Boolean(true)));
    Ok(())
}

#[tokio::test]
async fn verify_email_change_email_redirects_to_trusted_callback(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: true,
            ..user(now)
        })
        .await;
    let token = sign_jwt(
        &json!({
            "email": "ada@example.com",
            "updateTo": "new@example.com",
            "requestType": "change-email-verification"
        }),
        secret(),
        3600,
    )?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            &format!("/api/auth/verify-email?token={token}&callbackURL=/callback"),
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/callback")
    );
    assert!(!contains_record_string(&adapter, "user", "email", "ada@example.com").await?);
    let updated = record_by_string(&adapter, "user", "email", "new@example.com")
        .await?
        .ok_or("missing updated user")?;
    assert_eq!(
        updated.get("email"),
        Some(&DbValue::String("new@example.com".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn verify_email_route_rejects_untrusted_callback_urls(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(RouteAdapter::default());
    let now = OffsetDateTime::now_utc();
    adapter
        .insert_user(User {
            email_verified: false,
            ..user(now)
        })
        .await;
    let token = sign_jwt(&json!({ "email": "ada@example.com" }), secret(), 3600)?;
    let router = router_with_options(
        adapter.clone(),
        OpenAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
            ..OpenAuthOptions::default()
        },
    )?;

    let location = |response: &http::Response<Vec<u8>>| {
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };

    for unsafe_url in [
        "https://malicious.example",
        "//malicious.example",
        "/\\malicious.example",
    ] {
        let response = router
            .handle_async(json_request(
                Method::GET,
                &format!("/api/auth/verify-email?token={token}&callbackURL={unsafe_url}"),
                "",
                None,
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            location(&response).as_deref(),
            Some("/error?error=INVALID_TOKEN"),
            "callback {unsafe_url} must fall back to /error"
        );
    }

    let user = record_by_string(&adapter, "user", "email", "ada@example.com")
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("email_verified"),
        Some(&DbValue::Boolean(false)),
        "untrusted callback must not verify the user"
    );
    Ok(())
}

#[tokio::test]
async fn verify_email_route_redirects_invalid_token_to_trusted_callback(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = router_with_options(
        Arc::new(RouteAdapter::default()),
        OpenAuthOptions {
            base_url: Some("https://app.example.com/api/auth".to_owned()),
            ..OpenAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::GET,
            "/api/auth/verify-email?token=bad-token&callbackURL=/callback",
            "",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/callback?error=INVALID_TOKEN")
    );
    Ok(())
}
