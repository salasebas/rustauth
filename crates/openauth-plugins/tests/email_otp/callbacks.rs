use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use openauth_core::db::MemoryAdapter;
use openauth_core::options::{
    AfterEmailVerification, BeforeEmailVerification, EmailVerificationCallbackPayload,
    EmailVerificationOptions, OnPasswordReset, OpenAuthOptions, PasswordOptions,
    PasswordResetPayload,
};
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_plugins::email_otp::{ChangeEmailOptions, EmailOtpOptions};
use time::{Duration, OffsetDateTime};

use super::common::*;

struct CountBefore(Arc<AtomicUsize>);

impl BeforeEmailVerification for CountBefore {
    fn before_email_verification(
        &self,
        _payload: EmailVerificationCallbackPayload,
        _request: Option<&http::Request<Vec<u8>>>,
    ) -> Result<(), openauth_core::error::OpenAuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct CountAfter(Arc<AtomicUsize>);

impl AfterEmailVerification for CountAfter {
    fn after_email_verification(
        &self,
        _payload: EmailVerificationCallbackPayload,
        _request: Option<&http::Request<Vec<u8>>>,
    ) -> Result<(), openauth_core::error::OpenAuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct CountReset(Arc<AtomicUsize>);

impl OnPasswordReset for CountReset {
    fn on_password_reset(
        &self,
        _payload: PasswordResetPayload,
        _request: Option<&http::Request<Vec<u8>>>,
    ) -> Result<(), openauth_core::error::OpenAuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn verify_email_invokes_before_and_after_callbacks() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let router = router_with_auth_options(
        adapter,
        sender.clone(),
        EmailOtpOptions::default(),
        OpenAuthOptions {
            email_verification: EmailVerificationOptions {
                before_email_verification: Some(Arc::new(CountBefore(Arc::clone(&before)))),
                after_email_verification: Some(Arc::new(CountAfter(Arc::clone(&after)))),
                ..EmailVerificationOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )
    .unwrap();

    router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"ada@example.com","type":"email-verification"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let otp = sender.last_otp();
    let response = router
        .handle_async(
            json_request(
                "/email-otp/verify-email",
                &format!(r#"{{"email":"ada@example.com","otp":"{otp}"}}"#),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(before.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reset_password_invokes_callback_and_revokes_sessions() {
    let adapter = Arc::new(MemoryAdapter::new());
    let user = create_user(&adapter, "ada@example.com", true).await;
    create_credential(&adapter, &user.id, "old-password").await;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            &user.id,
            OffsetDateTime::now_utc() + Duration::days(7),
        ))
        .await
        .unwrap();
    let sender = CaptureSender::default();
    let resets = Arc::new(AtomicUsize::new(0));
    let router = router_with_auth_options(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions::default(),
        OpenAuthOptions {
            password: PasswordOptions {
                on_password_reset: Some(Arc::new(CountReset(Arc::clone(&resets)))),
                revoke_sessions_on_password_reset: true,
                ..PasswordOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )
    .unwrap();

    router
        .handle_async(
            json_request(
                "/email-otp/request-password-reset",
                r#"{"email":"ada@example.com"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let otp = sender.last_otp();
    let response = router
        .handle_async(
            json_request(
                "/email-otp/reset-password",
                &format!(
                    r#"{{"email":"ada@example.com","otp":"{otp}","password":"new-password"}}"#
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(resets.load(Ordering::SeqCst), 1);
    assert!(DbSessionStore::new(adapter.as_ref())
        .find_session(&session.token)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn change_email_revalidates_target_after_valid_otp() {
    let adapter = Arc::new(MemoryAdapter::new());
    let user = create_user(&adapter, "ada@example.com", true).await;
    let cookie = session_cookie(&adapter, &user.id).await;
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            change_email: ChangeEmailOptions {
                enabled: true,
                verify_current_email: false,
            },
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    router
        .handle_async(
            json_request(
                "/email-otp/request-email-change",
                r#"{"newEmail":"grace@example.com"}"#,
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let otp = sender.last_otp();
    create_user(&adapter, "grace@example.com", true).await;

    let response = router
        .handle_async(
            json_request(
                "/email-otp/change-email",
                &format!(r#"{{"newEmail":"grace@example.com","otp":"{otp}"}}"#),
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "EMAIL_ALREADY_IN_USE");
}

#[tokio::test]
async fn change_email_invokes_before_and_after_callbacks() {
    let adapter = Arc::new(MemoryAdapter::new());
    let user = create_user(&adapter, "ada@example.com", true).await;
    let cookie = session_cookie(&adapter, &user.id).await;
    let sender = CaptureSender::default();
    let before = Arc::new(AtomicUsize::new(0));
    let after = Arc::new(AtomicUsize::new(0));
    let router = router_with_auth_options(
        adapter,
        sender.clone(),
        EmailOtpOptions {
            change_email: ChangeEmailOptions {
                enabled: true,
                verify_current_email: false,
            },
            ..EmailOtpOptions::default()
        },
        OpenAuthOptions {
            email_verification: EmailVerificationOptions {
                before_email_verification: Some(Arc::new(CountBefore(Arc::clone(&before)))),
                after_email_verification: Some(Arc::new(CountAfter(Arc::clone(&after)))),
                ..EmailVerificationOptions::default()
            },
            ..OpenAuthOptions::default()
        },
    )
    .unwrap();

    router
        .handle_async(
            json_request(
                "/email-otp/request-email-change",
                r#"{"newEmail":"grace@example.com"}"#,
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let otp = sender.last_otp();
    let response = router
        .handle_async(
            json_request(
                "/email-otp/change-email",
                &format!(r#"{{"newEmail":"grace@example.com","otp":"{otp}"}}"#),
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(before.load(Ordering::SeqCst), 1);
    assert_eq!(after.load(Ordering::SeqCst), 1);
}
