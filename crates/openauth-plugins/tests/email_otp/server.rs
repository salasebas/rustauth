use std::sync::Arc;

use openauth_core::crypto::SecretEntry;
use openauth_core::db::MemoryAdapter;
use openauth_core::options::OpenAuthOptions;
use openauth_plugins::email_otp::{EmailOtpOptions, OtpStorage};

use super::common::*;

#[tokio::test]
async fn server_create_and_get_otp_returns_recoverable_plain_value() {
    let adapter = Arc::new(MemoryAdapter::new());
    let sender = CaptureSender::default();
    let router = router(adapter.clone(), sender, EmailOtpOptions::default()).unwrap();

    let create = router
        .handle_async(
            json_request(
                "/email-otp/create-verification-otp",
                r#"{"email":"ada@example.com","type":"email-verification"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let create_body: Value = serde_json::from_slice(create.body()).unwrap();
    let otp = create_body["otp"].as_str().unwrap();
    assert!(
        verification_value(&adapter, "email-verification-otp-ada@example.com")
            .await
            .is_some()
    );

    let get = router
        .handle_async(
            get_json_request(
                "/email-otp/get-verification-otp?email=ada%40example.com&type=email-verification",
                "",
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let get_body: Value = serde_json::from_slice(get.body()).unwrap();

    assert_eq!(create.status(), StatusCode::OK);
    assert_eq!(get_body["otp"], otp);
}

#[tokio::test]
async fn server_get_otp_uses_query_and_handles_percent_encoded_email() {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(
        adapter,
        CaptureSender::default(),
        EmailOtpOptions::default(),
    )
    .unwrap();

    let create = router
        .handle_async(
            json_request(
                "/email-otp/create-verification-otp",
                r#"{"email":"ada+tag@example.com","type":"email-verification"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let create_body: Value = serde_json::from_slice(create.body()).unwrap();

    let get = router
        .handle_async(
            get_json_request(
                "/email-otp/get-verification-otp?email=ada%2Btag%40example.com&type=email-verification",
                "",
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let get_body: Value = serde_json::from_slice(get.body()).unwrap();

    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get_body["otp"], create_body["otp"]);
}

#[tokio::test]
async fn server_get_otp_rejects_non_recoverable_hashed_storage() {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(
        adapter,
        CaptureSender::default(),
        EmailOtpOptions {
            store_otp: OtpStorage::Hashed,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    router
        .handle_async(
            json_request(
                "/email-otp/create-verification-otp",
                r#"{"email":"ada@example.com","type":"email-verification"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let get = router
        .handle_async(
            get_json_request(
                "/email-otp/get-verification-otp?email=ada%40example.com&type=email-verification",
                "",
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(get.body()).unwrap();

    assert_eq!(get.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_OTP");
}

#[tokio::test]
async fn server_get_otp_returns_encrypted_value_with_secret_rotation() {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_auth_options(
        adapter,
        CaptureSender::default(),
        EmailOtpOptions {
            store_otp: OtpStorage::Encrypted,
            ..EmailOtpOptions::default()
        },
        OpenAuthOptions {
            secrets: vec![
                SecretEntry::new(2, "current-secret-for-email-otp-tests-2"),
                SecretEntry::new(1, "previous-secret-for-email-otp-tests-1"),
            ],
            ..OpenAuthOptions::default()
        },
    )
    .unwrap();

    let create = router
        .handle_async(
            json_request(
                "/email-otp/create-verification-otp",
                r#"{"email":"ada@example.com","type":"email-verification"}"#,
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let create_body: Value = serde_json::from_slice(create.body()).unwrap();
    let get = router
        .handle_async(
            get_json_request(
                "/email-otp/get-verification-otp?email=ada%40example.com&type=email-verification",
                "",
                None,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let get_body: Value = serde_json::from_slice(get.body()).unwrap();

    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(get_body["otp"], create_body["otp"]);
}
