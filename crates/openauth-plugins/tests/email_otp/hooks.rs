use std::sync::Arc;

use openauth_core::db::MemoryAdapter;
use openauth_plugins::email_otp::EmailOtpOptions;

use super::common::*;

#[tokio::test]
async fn send_verification_on_sign_up_hook_sends_otp() {
    let adapter = Arc::new(MemoryAdapter::new());
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            send_verification_on_sign_up: true,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/sign-up/email",
                r#"{"name":"Ada","email":"ada@example.com","password":"valid-password"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(sender.count(), 1);
    assert!(
        verification_value(&adapter, "email-verification-otp-ada@example.com")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn override_default_send_verification_email_sends_otp() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            override_default_email_verification: true,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/send-verification-email",
                r#"{"email":"ada@example.com"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(sender.count(), 1);
    assert!(
        verification_value(&adapter, "email-verification-otp-ada@example.com")
            .await
            .is_some()
    );
}
