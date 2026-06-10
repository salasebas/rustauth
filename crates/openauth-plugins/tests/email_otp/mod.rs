#![allow(clippy::unwrap_used)]

mod additional_fields;
mod callbacks;
mod common;
mod concurrency;
mod hooks;
mod server;
mod storage;

use std::sync::Arc;

use common::*;
use openauth_core::db::MemoryAdapter;
use openauth_core::options::{EmailVerificationOptions, OpenAuthOptions};
use openauth_core::user::DbUserStore;
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use openauth_plugins::email_otp::{
    email_otp_with, ChangeEmailOptions, EmailOtpOptions, OtpStorage,
};
use time::{Duration, OffsetDateTime};

#[test]
fn exposes_email_otp_plugin_builder() {
    let plugin = email_otp_with(EmailOtpOptions::default());

    assert_eq!(openauth_plugins::email_otp::UPSTREAM_PLUGIN_ID, "email-otp");
    assert_eq!(plugin.id, "email-otp");
    assert!(plugin
        .endpoints
        .iter()
        .any(|endpoint| endpoint.path == "/email-otp/send-verification-otp"));
    assert!(plugin
        .endpoints
        .iter()
        .any(|endpoint| endpoint.path == "/email-otp/create-verification-otp"));
    assert!(plugin
        .error_codes
        .iter()
        .any(|error| error.code == "INVALID_OTP"));
}

#[tokio::test]
async fn send_verification_otp_creates_verification_and_calls_sender() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender.clone(), EmailOtpOptions::default()).unwrap();

    let response = router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"Ada@Example.com","type":"email-verification"}"#,
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
async fn disable_sign_up_silently_skips_sender_for_missing_sign_in_user() {
    let adapter = Arc::new(MemoryAdapter::new());
    let sender = CaptureSender::default();
    let router = router(
        adapter,
        sender.clone(),
        EmailOtpOptions {
            disable_sign_up: true,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"missing@example.com","type":"sign-in"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(sender.count(), 0);
}

#[tokio::test]
async fn disable_sign_up_silently_skips_sender_for_missing_email_verification_user() {
    let adapter = Arc::new(MemoryAdapter::new());
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            disable_sign_up: true,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"missing@example.com","type":"email-verification"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(sender.count(), 0);
    assert!(
        verification_value(&adapter, "email-verification-otp-missing@example.com")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn invalid_email_and_change_email_type_are_rejected() {
    let adapter = Arc::new(MemoryAdapter::new());
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender, EmailOtpOptions::default()).unwrap();

    let invalid_email = router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"invalid","type":"email-verification"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let change_email = router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"ada@example.com","type":"change-email"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(invalid_email.status(), StatusCode::BAD_REQUEST);
    assert_eq!(change_email.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn check_otp_tracks_failed_attempts_and_rejects_too_many() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender.clone(), EmailOtpOptions::default()).unwrap();
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

    let ok = router
        .handle_async(
            json_request(
                "/email-otp/check-verification-otp",
                &format!(
                    r#"{{"email":"ada@example.com","type":"email-verification","otp":"{otp}"}}"#
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let bad = router
        .handle_async(
            json_request(
                "/email-otp/check-verification-otp",
                r#"{"email":"ada@example.com","type":"email-verification","otp":"000000"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert!(
        verification_value(&adapter, "email-verification-otp-ada@example.com")
            .await
            .is_some_and(|value| value.ends_with(":1"))
    );
}

#[tokio::test]
async fn check_otp_returns_too_many_attempts_on_limit_attempt() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(
        adapter,
        sender,
        EmailOtpOptions {
            allowed_attempts: 2,
            ..EmailOtpOptions::default()
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

    let first = router
        .handle_async(
            json_request(
                "/email-otp/check-verification-otp",
                r#"{"email":"ada@example.com","type":"email-verification","otp":"000000"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let second = router
        .handle_async(
            json_request(
                "/email-otp/check-verification-otp",
                r#"{"email":"ada@example.com","type":"email-verification","otp":"000000"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(second.body()).unwrap();

    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "TOO_MANY_ATTEMPTS");
}

#[tokio::test]
async fn check_otp_returns_otp_expired_for_expired_verification() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    DbVerificationStore::new(adapter.as_ref())
        .create_verification(CreateVerificationInput::new(
            "email-verification-otp-ada@example.com",
            "123456:0",
            OffsetDateTime::now_utc() - Duration::seconds(1),
        ))
        .await
        .unwrap();
    let sender = CaptureSender::default();
    let router = router(adapter, sender, EmailOtpOptions::default()).unwrap();

    let response = router
        .handle_async(
            json_request(
                "/email-otp/check-verification-otp",
                r#"{"email":"ada@example.com","type":"email-verification","otp":"123456"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "OTP_EXPIRED");
}

#[tokio::test]
async fn sign_in_email_otp_existing_user_sets_cookie() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender.clone(), EmailOtpOptions::default()).unwrap();
    router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"ada@example.com","type":"sign-in"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/sign-in/email-otp",
                &format!(
                    r#"{{"email":"ada@example.com","otp":"{}"}}"#,
                    sender.last_otp()
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
}

#[tokio::test]
async fn sign_in_email_otp_can_create_verified_user() {
    let adapter = Arc::new(MemoryAdapter::new());
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender.clone(), EmailOtpOptions::default()).unwrap();
    router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"new@example.com","type":"sign-in"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/sign-in/email-otp",
                &format!(
                    r#"{{"email":"NEW@example.com","otp":"{}","name":"New User","image":"https://example.com/a.png"}}"#,
                    sender.last_otp()
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["email"], "new@example.com");
    assert_eq!(body["user"]["email_verified"], true);
}

#[tokio::test]
async fn reset_password_updates_credentials_and_verifies_email() {
    let adapter = Arc::new(MemoryAdapter::new());
    let user = create_user(&adapter, "ada@example.com", false).await;
    create_credential(&adapter, &user.id, "old-password").await;
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender.clone(), EmailOtpOptions::default()).unwrap();
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

    let response = router
        .handle_async(
            json_request(
                "/email-otp/reset-password",
                &format!(
                    r#"{{"email":"ada@example.com","otp":"{}","password":"new-password"}}"#,
                    sender.last_otp()
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let account = DbUserStore::new(adapter.as_ref())
        .find_credential_account(&user.id)
        .await
        .unwrap()
        .unwrap();
    let updated = DbUserStore::new(adapter.as_ref())
        .find_user_by_email("ada@example.com")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(fast_verify_password(account.password.as_deref().unwrap(), "new-password").unwrap());
    assert!(updated.email_verified);
}

#[tokio::test]
async fn verify_email_auto_signs_in_when_enabled() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router_with_auth_options(
        adapter,
        sender.clone(),
        EmailOtpOptions::default(),
        OpenAuthOptions {
            email_verification: EmailVerificationOptions {
                auto_sign_in_after_verification: true,
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

    let response = router
        .handle_async(
            json_request(
                "/email-otp/verify-email",
                &format!(
                    r#"{{"email":"ada@example.com","otp":"{}"}}"#,
                    sender.last_otp()
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert!(set_cookie_values(&response)
        .iter()
        .any(|cookie| cookie.starts_with("open-auth.session_token=")));
}

#[tokio::test]
async fn verify_email_accepts_only_latest_otp_after_resend() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender.clone(), EmailOtpOptions::default()).unwrap();

    for _ in 0..3 {
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
    }
    let otps = sender.otps();
    let first_otp = otps.first().unwrap();

    let stale = router
        .handle_async(
            json_request(
                "/email-otp/verify-email",
                &format!(r#"{{"email":"ada@example.com","otp":"{first_otp}"}}"#),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let stale_body: Value = serde_json::from_slice(stale.body()).unwrap();
    assert_eq!(stale.status(), StatusCode::BAD_REQUEST);
    assert_eq!(stale_body["code"], "INVALID_OTP");

    let response = router
        .handle_async(
            json_request(
                "/email-otp/verify-email",
                &format!(
                    r#"{{"email":"ada@example.com","otp":"{}"}}"#,
                    sender.last_otp()
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = DbUserStore::new(adapter.as_ref())
        .find_user_by_email("ada@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(updated.email_verified);
}

#[tokio::test]
async fn request_email_change_rejects_same_email_and_skips_sender_for_taken_email() {
    let adapter = Arc::new(MemoryAdapter::new());
    let user = create_user(&adapter, "ada@example.com", true).await;
    create_user(&adapter, "taken@example.com", true).await;
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

    let same_email = router
        .handle_async(
            json_request(
                "/email-otp/request-email-change",
                r#"{"newEmail":"ada@example.com"}"#,
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let same_body: Value = serde_json::from_slice(same_email.body()).unwrap();
    assert_eq!(same_email.status(), StatusCode::BAD_REQUEST);
    assert_eq!(same_body["code"], "EMAIL_IS_THE_SAME");
    assert_eq!(sender.count(), 0);

    let before_taken = sender.count();
    let taken = router
        .handle_async(
            json_request(
                "/email-otp/request-email-change",
                r#"{"newEmail":"taken@example.com"}"#,
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(taken.status(), StatusCode::OK);
    assert_eq!(sender.count(), before_taken);
    assert!(verification_value(
        &adapter,
        "change-email-otp-ada@example.com:taken@example.com"
    )
    .await
    .is_none());
}

#[tokio::test]
async fn change_email_requires_session_and_updates_email_with_otp() {
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

    let unauthorized = router
        .handle_async(
            json_request(
                "/email-otp/request-email-change",
                r#"{"newEmail":"new@example.com"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    router
        .handle_async(
            json_request(
                "/email-otp/request-email-change",
                r#"{"newEmail":"new@example.com"}"#,
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let response = router
        .handle_async(
            json_request(
                "/email-otp/change-email",
                &format!(
                    r#"{{"newEmail":"new@example.com","otp":"{}"}}"#,
                    sender.last_otp()
                ),
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let updated = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&user.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body, serde_json::json!({ "success": true }));
    assert_eq!(updated.email, "new@example.com");
    assert!(updated.email_verified);
}

#[tokio::test]
async fn request_email_change_requires_current_email_otp_when_configured() {
    let adapter = Arc::new(MemoryAdapter::new());
    let user = create_user(&adapter, "ada@example.com", true).await;
    let cookie = session_cookie(&adapter, &user.id).await;
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender,
        EmailOtpOptions {
            change_email: ChangeEmailOptions {
                enabled: true,
                verify_current_email: true,
            },
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/email-otp/request-email-change",
                r#"{"newEmail":"new@example.com"}"#,
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "OTP_REQUIRED");
    assert!(
        verification_value(&adapter, "change-email-otp-ada@example.com:new@example.com")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn request_email_change_rejects_invalid_current_email_otp_when_configured() {
    let adapter = Arc::new(MemoryAdapter::new());
    let user = create_user(&adapter, "ada@example.com", true).await;
    let cookie = session_cookie(&adapter, &user.id).await;
    DbVerificationStore::new(adapter.as_ref())
        .create_verification(CreateVerificationInput::new(
            "email-verification-otp-ada@example.com",
            "123456:0",
            OffsetDateTime::now_utc() + Duration::minutes(5),
        ))
        .await
        .unwrap();
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender,
        EmailOtpOptions {
            change_email: ChangeEmailOptions {
                enabled: true,
                verify_current_email: true,
            },
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/email-otp/request-email-change",
                r#"{"newEmail":"new@example.com","otp":"000000"}"#,
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_OTP");
    assert!(
        verification_value(&adapter, "change-email-otp-ada@example.com:new@example.com")
            .await
            .is_none()
    );
}

#[tokio::test]
async fn deprecated_forget_password_email_otp_alias_requests_reset_otp() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender.clone(), EmailOtpOptions::default()).unwrap();

    let response = router
        .handle_async(
            json_request(
                "/forget-password/email-otp",
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
        verification_value(&adapter, "forget-password-otp-ada@example.com")
            .await
            .is_some()
    );
}

#[tokio::test]
async fn sign_in_email_otp_stores_session_in_secondary_storage_when_configured() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = router_with_auth_options(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions::default(),
        OpenAuthOptions::default().secondary_storage(storage.clone()),
    )
    .unwrap();
    router
        .handle_async(
            json_request(
                "/email-otp/send-verification-otp",
                r#"{"email":"ada@example.com","type":"sign-in"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/sign-in/email-otp",
                &format!(
                    r#"{{"email":"ada@example.com","otp":"{}"}}"#,
                    sender.last_otp()
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let token = body["token"].as_str().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(storage
        .value(&format!("session:{token}"))
        .unwrap()
        .is_some());
    assert_eq!(adapter.len("session").await, 0);
}

#[tokio::test]
async fn verify_email_auto_sign_in_stores_session_in_secondary_storage_when_configured() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = router_with_auth_options(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions::default(),
        OpenAuthOptions {
            email_verification: EmailVerificationOptions {
                auto_sign_in_after_verification: true,
                ..EmailVerificationOptions::default()
            },
            ..OpenAuthOptions::default().secondary_storage(storage.clone())
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

    let response = router
        .handle_async(
            json_request(
                "/email-otp/verify-email",
                &format!(
                    r#"{{"email":"ada@example.com","otp":"{}"}}"#,
                    sender.last_otp()
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(response.body()).unwrap();
    let token = body["token"].as_str().unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(storage
        .value(&format!("session:{token}"))
        .unwrap()
        .is_some());
    assert_eq!(adapter.len("session").await, 0);
}

#[tokio::test]
async fn hashed_storage_does_not_store_plain_otp_but_verifies() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            store_otp: OtpStorage::Hashed,
            ..EmailOtpOptions::default()
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
    let stored = verification_value(&adapter, "email-verification-otp-ada@example.com")
        .await
        .unwrap();

    let response = router
        .handle_async(
            json_request(
                "/email-otp/check-verification-otp",
                &format!(
                    r#"{{"email":"ada@example.com","type":"email-verification","otp":"{otp}"}}"#
                ),
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    assert!(!stored.starts_with(&otp));
    assert_eq!(response.status(), StatusCode::OK);
}
