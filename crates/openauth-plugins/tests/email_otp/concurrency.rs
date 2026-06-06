use std::sync::Arc;

use openauth_core::crypto::password::verify_password;
use openauth_core::db::MemoryAdapter;
use openauth_core::user::DbUserStore;
use openauth_plugins::email_otp::{ChangeEmailOptions, EmailOtpOptions};

use super::common::*;

#[tokio::test]
async fn sign_in_email_otp_allows_only_one_concurrent_redeem() {
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
    let otp = sender.last_otp();
    let body = format!(r#"{{"email":"ada@example.com","otp":"{otp}"}}"#);
    let first_request = json_request("/sign-in/email-otp", &body, None).unwrap();
    let second_request = json_request("/sign-in/email-otp", &body, None).unwrap();

    let (first, second) = tokio::join!(
        router.handle_async(first_request),
        router.handle_async(second_request),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    let successes = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();

    assert_eq!(
        successes,
        1,
        "exactly one concurrent sign-in may succeed: {:?} {:?}",
        first.status(),
        second.status()
    );
    let failures = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::BAD_REQUEST)
        .count();
    assert_eq!(failures, 1);
    let failed_body: Value = if first.status() == StatusCode::BAD_REQUEST {
        serde_json::from_slice(first.body()).unwrap()
    } else {
        serde_json::from_slice(second.body()).unwrap()
    };
    assert_eq!(failed_body["code"], "INVALID_OTP");
    assert_eq!(adapter.len("session").await, 1);
}

#[tokio::test]
async fn reset_password_email_otp_allows_only_one_concurrent_redeem() {
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
    let otp = sender.last_otp();
    let body = format!(r#"{{"email":"ada@example.com","otp":"{otp}","password":"new-password"}}"#);
    let first_request = json_request("/email-otp/reset-password", &body, None).unwrap();
    let second_request = json_request("/email-otp/reset-password", &body, None).unwrap();

    let (first, second) = tokio::join!(
        router.handle_async(first_request),
        router.handle_async(second_request),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    let successes = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();

    assert_eq!(
        successes,
        1,
        "exactly one concurrent reset may succeed: {:?} {:?}",
        first.status(),
        second.status()
    );
    let failures = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::BAD_REQUEST)
        .count();
    assert_eq!(failures, 1);
    let failed_body: Value = if first.status() == StatusCode::BAD_REQUEST {
        serde_json::from_slice(first.body()).unwrap()
    } else {
        serde_json::from_slice(second.body()).unwrap()
    };
    assert_eq!(failed_body["code"], "INVALID_OTP");

    let account = DbUserStore::new(adapter.as_ref())
        .find_credential_account(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(verify_password(account.password.as_deref().unwrap(), "new-password").unwrap());
}

#[tokio::test]
async fn change_email_otp_allows_only_one_concurrent_redeem() {
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
                r#"{"newEmail":"new@example.com"}"#,
                Some(&cookie),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let otp = sender.last_otp();
    let body = format!(r#"{{"newEmail":"new@example.com","otp":"{otp}"}}"#);
    let first_request = json_request("/email-otp/change-email", &body, Some(&cookie)).unwrap();
    let second_request = json_request("/email-otp/change-email", &body, Some(&cookie)).unwrap();

    let (first, second) = tokio::join!(
        router.handle_async(first_request),
        router.handle_async(second_request),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    let successes = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();

    assert_eq!(
        successes,
        1,
        "exactly one concurrent change-email may succeed: {:?} {:?}",
        first.status(),
        second.status()
    );
    let failures = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::BAD_REQUEST)
        .count();
    assert_eq!(failures, 1);
    let failed_body: Value = if first.status() == StatusCode::BAD_REQUEST {
        serde_json::from_slice(first.body()).unwrap()
    } else {
        serde_json::from_slice(second.body()).unwrap()
    };
    assert_eq!(failed_body["code"], "INVALID_OTP");

    let updated = DbUserStore::new(adapter.as_ref())
        .find_user_by_id(&user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.email, "new@example.com");
}
