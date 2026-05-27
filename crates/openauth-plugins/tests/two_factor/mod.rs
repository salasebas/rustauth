mod helpers;

use std::sync::Arc;

use helpers::*;
use http::{Method, StatusCode};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::crypto::symmetric_decrypt;
use openauth_core::db::{DbAdapter, DbValue, FindOne, MemoryAdapter, Where};
use openauth_plugins::two_factor::{
    totp_code, BackupCodeOptions, OtpStorage, SendOtp, TwoFactorOptions,
};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::Mutex;

#[tokio::test]
async fn plugin_registers_schema_and_error_codes() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let context = create_auth_context_with_adapter(options(), adapter)?;

    assert_eq!(
        context.db_schema.field("user", "two_factor_enabled")?.name,
        "two_factor_enabled"
    );
    assert!(context.db_schema.table("twoFactor").is_some());
    assert!(context
        .plugin_error_codes
        .contains_key("INVALID_TWO_FACTOR_COOKIE"));
    Ok(())
}

#[tokio::test]
async fn enable_returns_totp_uri_and_backup_codes_without_enabling_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let cookie = sign_in_cookie(&router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            r#"{"password":"password123"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["backupCodes"].as_array().map(Vec::len), Some(10));
    assert!(body["totpURI"]
        .as_str()
        .is_some_and(|uri| uri.starts_with("otpauth://totp/OpenAuth:")));
    assert!(!user_enabled(adapter.as_ref()).await?);
    assert_eq!(
        two_factor_record(adapter.as_ref()).await?.get("verified"),
        Some(&DbValue::Boolean(false))
    );
    Ok(())
}

#[tokio::test]
async fn enable_uses_request_issuer_and_encodes_issuer_parameter(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_adapter, router) = seeded_router().await?;
    let cookie = sign_in_cookie(&router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            r#"{"password":"password123","issuer":"Custom App Name"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let uri = body["totpURI"].as_str().ok_or("missing totpURI")?;
    assert!(uri.starts_with("otpauth://totp/Custom%20App%20Name:"));
    assert!(uri.contains("issuer=Custom+App+Name"));
    Ok(())
}

#[tokio::test]
async fn invalid_totp_code_returns_upstream_error_code() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let _cookie = enable_totp(&adapter, &router).await?;
    let (challenge_cookie, _body) = two_factor_challenge_cookie(&router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-totp",
            r#"{"code":"invalid-code"}"#,
            Some(&challenge_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_CODE");
    Ok(())
}

#[tokio::test]
async fn verify_totp_enables_user_and_marks_row_verified() -> Result<(), Box<dyn std::error::Error>>
{
    let (adapter, router) = seeded_router().await?;
    let cookie = sign_in_cookie(&router).await?;
    let _ = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            r#"{"password":"password123"}"#,
            Some(&cookie),
        )?)
        .await?;
    let record = two_factor_record(adapter.as_ref()).await?;
    let secret = symmetric_decrypt(secret(), string_field(&record, "secret")?)?;
    let code = totp_code(&secret, 6, 30, OffsetDateTime::now_utc().unix_timestamp());

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-totp",
            &format!(r#"{{"code":"{code}"}}"#),
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(user_enabled(adapter.as_ref()).await?);
    assert_eq!(
        two_factor_record(adapter.as_ref()).await?.get("verified"),
        Some(&DbValue::Boolean(true))
    );
    Ok(())
}

#[tokio::test]
async fn sign_in_requires_second_factor_after_totp_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let cookie = sign_in_cookie(&router).await?;
    let _ = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            r#"{"password":"password123"}"#,
            Some(&cookie),
        )?)
        .await?;
    let record = two_factor_record(adapter.as_ref()).await?;
    let secret = symmetric_decrypt(secret(), string_field(&record, "secret")?)?;
    let code = totp_code(&secret, 6, 30, OffsetDateTime::now_utc().unix_timestamp());
    let _ = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-totp",
            &format!(r#"{{"code":"{code}"}}"#),
            Some(&cookie),
        )?)
        .await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"password123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["twoFactorRedirect"], true);
    assert_eq!(body["twoFactorMethods"], serde_json::json!(["totp"]));
    let set_cookie = set_cookie_values(&response).join(", ");
    assert!(set_cookie.contains("two_factor="));
    assert!(set_cookie.contains("session_token=;"));
    Ok(())
}

#[tokio::test]
async fn username_sign_in_requires_second_factor_after_totp_is_enabled(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = options_with_two_factor(TwoFactorOptions::default());
    options.plugins.push(openauth_plugins::username::username());
    let (adapter, router) = seeded_router_with_auth_options(options).await?;
    let _cookie = enable_totp(&adapter, &router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/username",
            r#"{"username":"ada_user","password":"password123"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["twoFactorRedirect"], true);
    assert_eq!(body["twoFactorMethods"], serde_json::json!(["totp"]));
    let set_cookie = set_cookie_values(&response).join(", ");
    assert!(set_cookie.contains("two_factor="));
    assert!(set_cookie.contains("session_token=;"));
    Ok(())
}

#[tokio::test]
async fn second_factor_verification_preserves_dont_remember_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let _cookie = enable_totp(&adapter, &router).await?;
    let record = two_factor_record(adapter.as_ref()).await?;
    let secret = symmetric_decrypt(secret(), string_field(&record, "secret")?)?;
    let code = totp_code(&secret, 6, 30, OffsetDateTime::now_utc().unix_timestamp());

    let challenge = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"password123","rememberMe":false}"#,
            None,
        )?)
        .await?;
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge_cookie = cookie_header_from_response(&challenge);

    let verified = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-totp",
            &format!(r#"{{"code":"{code}"}}"#),
            Some(&challenge_cookie),
        )?)
        .await?;

    assert_eq!(verified.status(), StatusCode::OK);
    let set_cookies = set_cookie_values(&verified);
    let session_cookie = set_cookies
        .iter()
        .find(|value| value.starts_with("open-auth.session_token="))
        .ok_or("missing session cookie")?;
    assert!(!session_cookie.contains("Max-Age="));
    assert!(set_cookies
        .iter()
        .any(|value| value.starts_with("open-auth.dont_remember=")));
    Ok(())
}

#[tokio::test]
async fn reenabling_two_factor_preserves_verified_totp_method(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let cookie = enable_totp(&adapter, &router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            r#"{"password":"password123"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        two_factor_record(adapter.as_ref()).await?.get("verified"),
        Some(&DbValue::Boolean(true))
    );

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"password123"}"#,
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["twoFactorMethods"], serde_json::json!(["totp"]));
    Ok(())
}

#[tokio::test]
async fn backup_code_verification_consumes_the_code() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let cookie = enable_totp(&adapter, &router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/generate-backup-codes",
            r#"{"password":"password123"}"#,
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    let code = body["backupCodes"][0]
        .as_str()
        .ok_or("missing backup code")?
        .to_owned();

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-backup-code",
            &format!(r#"{{"code":"{code}"}}"#),
            Some(&cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/view-backup-codes",
            r#"{"userId":"user_1"}"#,
            None,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(!body["backupCodes"]
        .as_array()
        .ok_or("backupCodes")?
        .iter()
        .any(|candidate| candidate.as_str() == Some(&code)));
    Ok(())
}

#[tokio::test]
async fn disable_two_factor_clears_user_flag_and_row() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let cookie = enable_totp(&adapter, &router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/disable",
            r#"{"password":"password123"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!user_enabled(adapter.as_ref()).await?);
    assert!(adapter
        .find_one(
            FindOne::new("twoFactor")
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned()),))
        )
        .await?
        .is_none());
    Ok(())
}

#[tokio::test]
async fn verify_totp_without_two_factor_cookie_returns_plugin_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let _cookie = enable_totp(&adapter, &router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-totp",
            r#"{"code":"000000"}"#,
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_TWO_FACTOR_COOKIE");
    Ok(())
}

#[tokio::test]
async fn otp_send_and_verify_supports_hashed_storage() -> Result<(), Box<dyn std::error::Error>> {
    assert_otp_send_and_verify(OtpStorage::Hashed).await
}

#[tokio::test]
async fn otp_send_and_verify_supports_encrypted_storage() -> Result<(), Box<dyn std::error::Error>>
{
    assert_otp_send_and_verify(OtpStorage::Encrypted).await
}

async fn assert_otp_send_and_verify(storage: OtpStorage) -> Result<(), Box<dyn std::error::Error>> {
    let (options, sent) = otp_options(storage, 5, 180);
    let (adapter, router) = seeded_router_with_options(options).await?;
    let _cookie = enable_totp(&adapter, &router).await?;
    let (challenge_cookie, body) = two_factor_challenge_cookie(&router).await?;
    assert_eq!(body["twoFactorMethods"], serde_json::json!(["totp", "otp"]));

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/send-otp",
            "{}",
            Some(&challenge_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let code = sent.lock().await.clone().ok_or("missing OTP")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-otp",
            &format!(r#"{{"code":"{code}"}}"#),
            Some(&challenge_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    Ok(())
}

#[tokio::test]
async fn otp_attempt_limit_requires_new_code() -> Result<(), Box<dyn std::error::Error>> {
    let (options, _sent) = otp_options(OtpStorage::Plain, 1, 180);
    let (adapter, router) = seeded_router_with_options(options).await?;
    let _cookie = enable_totp(&adapter, &router).await?;
    let (challenge_cookie, _body) = two_factor_challenge_cookie(&router).await?;
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/send-otp",
            "{}",
            Some(&challenge_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-otp",
            r#"{"code":"000000"}"#,
            Some(&challenge_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-otp",
            r#"{"code":"000000"}"#,
            Some(&challenge_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE");
    Ok(())
}

#[tokio::test]
async fn otp_expiry_rejects_stale_codes() -> Result<(), Box<dyn std::error::Error>> {
    let (options, sent) = otp_options(OtpStorage::Encrypted, 5, 0);
    let (adapter, router) = seeded_router_with_options(options).await?;
    let _cookie = enable_totp(&adapter, &router).await?;
    let (challenge_cookie, _body) = two_factor_challenge_cookie(&router).await?;
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/send-otp",
            "{}",
            Some(&challenge_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let code = sent.lock().await.clone().ok_or("missing OTP")?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-otp",
            &format!(r#"{{"code":"{code}"}}"#),
            Some(&challenge_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "OTP_HAS_EXPIRED");
    Ok(())
}

#[tokio::test]
async fn custom_table_name_is_used_for_two_factor_records() -> Result<(), Box<dyn std::error::Error>>
{
    let options = TwoFactorOptions {
        two_factor_table: "customTwoFactor".to_owned(),
        ..TwoFactorOptions::default()
    };
    let (adapter, router) = seeded_router_with_options(options).await?;
    let cookie = sign_in_cookie(&router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            r#"{"password":"password123"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(two_factor_record_in(adapter.as_ref(), "customTwoFactor")
        .await
        .is_ok());
    assert!(adapter
        .find_one(
            FindOne::new("twoFactor")
                .where_clause(Where::new("user_id", DbValue::String("user_1".to_owned())))
        )
        .await?
        .is_none());
    Ok(())
}

#[test]
fn backup_codes_with_custom_length_split_after_first_five_characters() {
    let options = BackupCodeOptions {
        length: 8,
        ..BackupCodeOptions::default()
    };

    let codes = openauth_plugins::two_factor::generate_backup_codes(&options);

    assert!(codes
        .iter()
        .all(|code| code.len() == 9 && code.as_bytes().get(5) == Some(&b'-')));
}

#[tokio::test]
async fn passwordless_enable_requires_explicit_option() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router) = seeded_router().await?;
    let cookie = passwordless_session_cookie(adapter.as_ref()).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            "{}",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_PASSWORD");

    let options = TwoFactorOptions {
        allow_passwordless: true,
        ..TwoFactorOptions::default()
    };
    let (adapter, router) = seeded_router_with_options(options).await?;
    let cookie = passwordless_session_cookie(adapter.as_ref()).await?;
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/enable",
            "{}",
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn trusted_device_bypasses_second_factor_and_rotates_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = TwoFactorOptions {
        trust_device_max_age: 60,
        ..TwoFactorOptions::default()
    };
    let (adapter, router) = seeded_router_with_options(options).await?;
    let _cookie = enable_totp(&adapter, &router).await?;
    let record = two_factor_record(adapter.as_ref()).await?;
    let secret = symmetric_decrypt(secret(), string_field(&record, "secret")?)?;
    let code = totp_code(&secret, 6, 30, OffsetDateTime::now_utc().unix_timestamp());
    let (challenge_cookie, _body) = two_factor_challenge_cookie(&router).await?;

    let trusted_response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/two-factor/verify-totp",
            &format!(r#"{{"code":"{code}","trustDevice":true}}"#),
            Some(&challenge_cookie),
        )?)
        .await?;
    assert_eq!(trusted_response.status(), StatusCode::OK);
    let trusted_cookie = cookie_value_from_response(&trusted_response, "trust_device")
        .ok_or("missing trust device cookie")?;
    assert!(set_cookie_values(&trusted_response)
        .iter()
        .any(|value| value.contains("trust_device=") && value.contains("Max-Age=60")));
    let trusted_cookie_header = cookie_header_from_response(&trusted_response);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"password123"}"#,
            Some(&trusted_cookie_header),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert!(body["twoFactorRedirect"].is_null());
    let rotated_cookie =
        cookie_value_from_response(&response, "trust_device").ok_or("missing rotated cookie")?;
    assert_ne!(trusted_cookie, rotated_cookie);
    Ok(())
}

#[tokio::test]
async fn invalid_trusted_device_cookie_is_expired_on_second_factor_challenge(
) -> Result<(), Box<dyn std::error::Error>> {
    let options = TwoFactorOptions {
        trust_device_max_age: 60,
        ..TwoFactorOptions::default()
    };
    let (adapter, router) = seeded_router_with_options(options).await?;
    let _cookie = enable_totp(&adapter, &router).await?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/email",
            r#"{"email":"ada@example.com","password":"password123"}"#,
            Some("open-auth.trust_device=invalid"),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["twoFactorRedirect"], true);
    assert!(set_cookie_values(&response)
        .iter()
        .any(|value| value.starts_with("open-auth.trust_device=;") && value.contains("Max-Age=0")));
    Ok(())
}

fn otp_options(
    storage: OtpStorage,
    allowed_attempts: u32,
    period_seconds: u64,
) -> (TwoFactorOptions, Arc<Mutex<Option<String>>>) {
    let sent = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&sent);
    let send_otp: SendOtp = Arc::new(move |message| {
        let capture = Arc::clone(&capture);
        Box::pin(async move {
            *capture.lock().await = Some(message.otp);
            Ok(())
        })
    });
    let mut options = TwoFactorOptions::default();
    options.otp.storage = storage;
    options.otp.allowed_attempts = allowed_attempts;
    options.otp.period_seconds = period_seconds;
    options.otp.send_otp = Some(send_otp);
    (options, sent)
}
