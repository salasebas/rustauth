use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use openauth_core::db::MemoryAdapter;
use openauth_core::error::OpenAuthError;
use openauth_plugins::email_otp::{
    EmailOtpEncryptor, EmailOtpGenerator, EmailOtpHasher, EmailOtpOptions, EmailOtpType,
    OtpStorage, ResendStrategy,
};

use super::common::*;

#[tokio::test]
async fn encrypted_storage_is_not_plain_and_can_be_reused() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            store_otp: OtpStorage::Encrypted,
            resend_strategy: ResendStrategy::Reuse,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    for _ in 0..2 {
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

    assert_eq!(sender.count(), 2);
    assert!(!stored.starts_with(&otp));
    assert_eq!(response.status(), StatusCode::OK);
}

struct PrefixEncryptor;

impl EmailOtpEncryptor for PrefixEncryptor {
    fn encrypt_otp(&self, otp: &str) -> Result<String, OpenAuthError> {
        Ok(format!("enc:{otp}"))
    }

    fn decrypt_otp(&self, stored: &str) -> Result<String, OpenAuthError> {
        stored
            .strip_prefix("enc:")
            .map(str::to_owned)
            .ok_or_else(|| OpenAuthError::Crypto("invalid custom encrypted OTP".to_owned()))
    }
}

struct PrefixHasher;

impl EmailOtpHasher for PrefixHasher {
    fn hash_otp(&self, otp: &str) -> Result<String, OpenAuthError> {
        Ok(format!("hashed:{otp}"))
    }
}

struct CountingGenerator(Arc<AtomicUsize>);

impl EmailOtpGenerator for CountingGenerator {
    fn generate_otp(&self, _email: &str, _otp_type: EmailOtpType, _length: usize) -> String {
        format!("otp-{}", self.0.fetch_add(1, Ordering::SeqCst))
    }
}

#[tokio::test]
async fn custom_hash_storage_verifies_and_is_not_reused() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let router = router(
        adapter.clone(),
        sender.clone(),
        EmailOtpOptions {
            store_otp: OtpStorage::CustomHash(Arc::new(PrefixHasher)),
            resend_strategy: ResendStrategy::Reuse,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    for _ in 0..2 {
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

    assert_eq!(sender.count(), 2);
    assert!(stored.starts_with("hashed:"));
    assert!(!stored.contains(&format!("{}:0", otp)));
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn custom_encrypt_storage_verifies_and_can_be_retrieved() {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(
        adapter,
        CaptureSender::default(),
        EmailOtpOptions {
            store_otp: OtpStorage::CustomEncrypt(Arc::new(PrefixEncryptor)),
            ..EmailOtpOptions::default()
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
    let otp = create_body["otp"].as_str().unwrap();
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
    assert_eq!(get_body["otp"], otp);
}

#[tokio::test]
async fn rotate_strategy_always_generates_new_otp() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let counter = Arc::new(AtomicUsize::new(0));
    let router = router(
        adapter,
        sender.clone(),
        EmailOtpOptions {
            generator: Some(Arc::new(CountingGenerator(Arc::clone(&counter)))),
            resend_strategy: ResendStrategy::Rotate,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    for _ in 0..2 {
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

    assert_eq!(sender.count(), 2);
    assert_eq!(sender.otps(), vec!["otp-0", "otp-1"]);
}

#[tokio::test]
async fn reuse_strategy_generates_fresh_otp_after_expiry() {
    let adapter = Arc::new(MemoryAdapter::new());
    create_user(&adapter, "ada@example.com", false).await;
    let sender = CaptureSender::default();
    let counter = Arc::new(AtomicUsize::new(0));
    let router = router(
        adapter,
        sender.clone(),
        EmailOtpOptions {
            expires_in: 0,
            generator: Some(Arc::new(CountingGenerator(Arc::clone(&counter)))),
            resend_strategy: ResendStrategy::Reuse,
            ..EmailOtpOptions::default()
        },
    )
    .unwrap();

    for _ in 0..2 {
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

    assert_eq!(sender.otps(), vec!["otp-0", "otp-1"]);
}
