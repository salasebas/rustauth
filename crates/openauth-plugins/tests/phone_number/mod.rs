use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::cookies::{set_session_cookie, Cookie, SessionCookieOptions};
use openauth_core::db::{
    DbAdapter, DbRecord, DbValue, FindOne, HookedAdapter, JoinAdapter, MemoryAdapter, Update, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, OnPasswordReset, OpenAuthOptions, PasswordOptions, PasswordResetPayload,
    UserAdditionalField, UserOptions,
};
use openauth_core::session::{CreateSessionInput, DbSessionStore};
use openauth_core::test_utils::fast_hash_password;
use openauth_core::user::{CreateCredentialAccountInput, CreateUserInput, DbUserStore};
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use openauth_plugins::phone_number::{
    phone_number_with, PhoneNumberOptions, SignUpOnVerification, UPSTREAM_PLUGIN_ID,
};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

mod edge_cases;

const PHONE: &str = "+1234567890";
const NEW_PHONE: &str = "+19876543210";

#[tokio::test]
async fn plugin_metadata_registers_expected_contracts() -> Result<(), Box<dyn std::error::Error>> {
    let _adapter = Arc::new(MemoryAdapter::new());
    let plugin = phone_number_with(PhoneNumberOptions::default());

    assert_eq!(UPSTREAM_PLUGIN_ID, "phone-number");
    assert_eq!(plugin.id, "phone-number");
    assert_eq!(plugin.endpoints.len(), 5);
    assert!(plugin
        .endpoints
        .iter()
        .any(|endpoint| endpoint.path == "/phone-number/verify"));
    assert!(plugin
        .error_codes
        .iter()
        .any(|error| error.code == "INVALID_OTP"));
    assert_eq!(plugin.schema.len(), 2);
    assert_eq!(plugin.rate_limit.len(), 1);
    Ok(())
}

#[tokio::test]
async fn send_otp_stores_code_and_invokes_sender() -> Result<(), Box<dyn std::error::Error>> {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let router = router_with_options(
        PhoneNumberOptions::default().send_otp({
            let sent = Arc::clone(&sent);
            move |phone_number, code| {
                sent.lock()
                    .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))?
                    .push((phone_number.to_owned(), code.to_owned()));
                Ok(())
            }
        }),
        Arc::new(MemoryAdapter::new()),
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/send-otp",
            &format!(r#"{{"phoneNumber":"{PHONE}"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(sent.lock().map_err(|_| "lock poisoned")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn verify_allows_only_one_concurrent_session() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, false).await?;
    seed_otp(&adapter, PHONE, "123456", 0, 300).await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter.clone())?;

    let body = format!(r#"{{"phoneNumber":"{PHONE}","code":"123456"}}"#);
    let first_request = json_request(Method::POST, "/api/auth/phone-number/verify", &body, None)?;
    let second_request = json_request(Method::POST, "/api/auth/phone-number/verify", &body, None)?;

    let (first, second) = tokio::join!(
        router.handle_async(first_request),
        router.handle_async(second_request),
    );
    let first = first?;
    let second = second?;
    let successes = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();
    assert_eq!(
        successes,
        1,
        "exactly one concurrent verify may mint a session: {:?} {:?}",
        first.status(),
        second.status()
    );
    assert_eq!(adapter.len("session").await, 1);
    assert!(find_verification(&adapter, PHONE).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn verify_allows_only_one_concurrent_redeem() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, false).await?;
    seed_otp(&adapter, PHONE, "123456", 0, 300).await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter.clone())?;

    let body = format!(r#"{{"phoneNumber":"{PHONE}","code":"123456","disableSession":true}}"#);
    let first_request = json_request(Method::POST, "/api/auth/phone-number/verify", &body, None)?;
    let second_request = json_request(Method::POST, "/api/auth/phone-number/verify", &body, None)?;

    let (first, second) = tokio::join!(
        router.handle_async(first_request),
        router.handle_async(second_request),
    );
    let first = first?;
    let second = second?;
    let successes = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();
    assert_eq!(
        successes,
        1,
        "exactly one concurrent verify may succeed: {:?} {:?}",
        first.status(),
        second.status()
    );
    let failures = [first.status(), second.status()]
        .into_iter()
        .filter(|status| *status == StatusCode::BAD_REQUEST)
        .count();
    assert_eq!(failures, 1);
    let failed_body: Value = if first.status() == StatusCode::BAD_REQUEST {
        serde_json::from_slice(first.body())?
    } else {
        serde_json::from_slice(second.body())?
    };
    assert_eq!(failed_body["code"], "INVALID_OTP");
    assert!(find_verification(&adapter, PHONE).await?.is_none());
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn verify_marks_existing_user_and_deletes_otp() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, false).await?;
    seed_otp(&adapter, PHONE, "123456", 0, 300).await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{PHONE}","code":"123456","disableSession":true}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let user = find_user_by_phone(&adapter, PHONE)
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("phone_number_verified"),
        Some(&DbValue::Boolean(true))
    );
    assert!(find_verification(&adapter, PHONE).await?.is_none());
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn wrong_otp_increments_attempts_and_then_blocks() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_otp(&adapter, PHONE, "123456", 1, 300).await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{PHONE}","code":"000000"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_OTP");

    let blocked = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{PHONE}","code":"000000"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    assert!(find_verification(&adapter, PHONE).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn update_phone_number_requires_session_and_rejects_duplicates(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    seed_user_with_phone_id(&adapter, "user_2", NEW_PHONE, true).await?;
    seed_otp(&adapter, NEW_PHONE, "123456", 0, 300).await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{NEW_PHONE}","code":"123456","updatePhoneNumber":true}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn update_phone_number_returns_current_session_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    seed_otp(&adapter, NEW_PHONE, "123456", 0, 300).await?;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            "user_1",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let cookie = signed_session_cookie(&session.token)?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{NEW_PHONE}","code":"123456","updatePhoneNumber":true}}"#),
            Some(&cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["token"], session.token);
    Ok(())
}

#[tokio::test]
async fn sign_up_on_verification_creates_user() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_otp(&adapter, PHONE, "123456", 0, 300).await?;
    let options = PhoneNumberOptions::default().sign_up_on_verification(SignUpOnVerification {
        get_temp_email: Arc::new(|phone| format!("{}@temp.example", phone.trim_start_matches('+'))),
        get_temp_name: Some(Arc::new(|phone| format!("Phone {phone}"))),
    });
    let router = router_with_options(options, adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{PHONE}","code":"123456","disableSession":true}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let user = find_user_by_phone(&adapter, PHONE)
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("email"),
        Some(&DbValue::String("1234567890@temp.example".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_up_on_verification_persists_user_additional_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_otp(&adapter, PHONE, "123456", 0, 300).await?;
    let options = PhoneNumberOptions::default().sign_up_on_verification(SignUpOnVerification {
        get_temp_email: Arc::new(|phone| format!("{}@temp.example", phone.trim_start_matches('+'))),
        get_temp_name: None,
    });
    let openauth_options = OpenAuthOptions {
        user: UserOptions::new().additional_field(
            "role",
            UserAdditionalField::new(openauth_core::db::DbFieldType::String),
        ),
        ..OpenAuthOptions::default()
    };
    let router = router_with_options_and_openauth(options, adapter.clone(), openauth_options)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(
                r#"{{"phoneNumber":"{PHONE}","code":"123456","disableSession":true,"role":"phone-user"}}"#
            ),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let user = find_user_by_phone(&adapter, PHONE)
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("role"),
        Some(&DbValue::String("phone-user".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn sign_in_with_phone_and_password_creates_session() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    DbUserStore::new(adapter.as_ref())
        .create_credential_account(CreateCredentialAccountInput::new(
            "user_1",
            fast_hash_password("secret123")?,
        ))
        .await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/phone-number",
            &format!(r#"{{"phoneNumber":"{PHONE}","password":"secret123"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(adapter.len("session").await, 1);
    Ok(())
}

#[tokio::test]
async fn request_and_reset_password_by_phone() -> Result<(), Box<dyn std::error::Error>> {
    let sent = Arc::new(Mutex::new(String::new()));
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    let options = PhoneNumberOptions::default().send_password_reset_otp({
        let sent = Arc::clone(&sent);
        move |_phone_number, code| {
            *sent
                .lock()
                .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))? = code.to_owned();
            Ok(())
        }
    });
    let router = router_with_options(options, adapter.clone())?;

    let requested = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/request-password-reset",
            &format!(r#"{{"phoneNumber":"{PHONE}"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(requested.status(), StatusCode::OK);
    let code = sent.lock().map_err(|_| "lock poisoned")?.clone();

    let reset = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/reset-password",
            &format!(r#"{{"phoneNumber":"{PHONE}","otp":"{code}","newPassword":"newsecret123"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(reset.status(), StatusCode::OK);
    assert!(DbUserStore::new(adapter.as_ref())
        .find_credential_account("user_1")
        .await?
        .is_some());
    Ok(())
}

#[tokio::test]
async fn reset_password_allows_only_one_concurrent_redeem() -> Result<(), Box<dyn std::error::Error>>
{
    let reset_users = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    seed_reset_otp(&adapter, PHONE, "123456", 0, 300).await?;
    let openauth_options = OpenAuthOptions {
        password: PasswordOptions::default()
            .on_password_reset(RecordPasswordReset {
                user_ids: Arc::clone(&reset_users),
            })
            .revoke_sessions_on_password_reset(true),
        ..OpenAuthOptions::default()
    };
    let router = router_with_options_and_openauth(
        PhoneNumberOptions::default(),
        adapter.clone(),
        openauth_options,
    )?;

    let body =
        format!(r#"{{"phoneNumber":"{PHONE}","otp":"123456","newPassword":"newsecret123"}}"#);
    let first_request = json_request(
        Method::POST,
        "/api/auth/phone-number/reset-password",
        &body,
        None,
    )?;
    let second_request = json_request(
        Method::POST,
        "/api/auth/phone-number/reset-password",
        &body,
        None,
    )?;

    let (first, second) = tokio::join!(
        router.handle_async(first_request),
        router.handle_async(second_request),
    );
    let first = first?;
    let second = second?;
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
        serde_json::from_slice(first.body())?
    } else {
        serde_json::from_slice(second.body())?
    };
    assert_eq!(failed_body["code"], "OTP_NOT_FOUND");
    assert_eq!(reset_users.lock().map_err(|_| "lock poisoned")?.len(), 1);
    assert!(find_reset_verification(&adapter, PHONE).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn reset_password_runs_callback_and_revokes_sessions_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let sent = Arc::new(Mutex::new(String::new()));
    let reset_users = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            "user_1",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let options = PhoneNumberOptions::default().send_password_reset_otp({
        let sent = Arc::clone(&sent);
        move |_phone_number, code| {
            *sent
                .lock()
                .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))? = code.to_owned();
            Ok(())
        }
    });
    let openauth_options = OpenAuthOptions {
        password: PasswordOptions::default()
            .on_password_reset(RecordPasswordReset {
                user_ids: Arc::clone(&reset_users),
            })
            .revoke_sessions_on_password_reset(true),
        ..OpenAuthOptions::default()
    };
    let router = router_with_options_and_openauth(options, adapter.clone(), openauth_options)?;

    let requested = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/request-password-reset",
            &format!(r#"{{"phoneNumber":"{PHONE}"}}"#),
            None,
        )?)
        .await?;
    assert_eq!(requested.status(), StatusCode::OK);
    let code = sent.lock().map_err(|_| "lock poisoned")?.clone();

    let reset = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/reset-password",
            &format!(r#"{{"phoneNumber":"{PHONE}","otp":"{code}","newPassword":"newsecret123"}}"#),
            None,
        )?)
        .await?;

    assert_eq!(reset.status(), StatusCode::OK);
    assert_eq!(
        reset_users.lock().map_err(|_| "lock poisoned")?.as_slice(),
        ["user_1"]
    );
    assert_eq!(adapter.len("session").await, 0);
    Ok(())
}

#[tokio::test]
async fn update_user_can_clear_phone_and_resets_verified() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, true).await?;
    let session = DbSessionStore::new(adapter.as_ref())
        .create_session(CreateSessionInput::new(
            "user_1",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;
    let router = router_with_options(PhoneNumberOptions::default(), adapter.clone())?;
    let cookie = signed_session_cookie(&session.token)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/update-user",
            r#"{"phoneNumber":null}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let user = record_by_id(&adapter, "user", "user_1")
        .await?
        .ok_or("missing user")?;
    assert_eq!(user.get("phone_number"), Some(&DbValue::Null));
    assert_eq!(
        user.get("phone_number_verified"),
        Some(&DbValue::Boolean(false))
    );
    Ok(())
}

#[tokio::test]
async fn custom_verify_otp_bypasses_internal_otp_store() -> Result<(), Box<dyn std::error::Error>> {
    let called = Arc::new(Mutex::new(false));
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, false).await?;
    let options = PhoneNumberOptions::default().verify_otp({
        let called = Arc::clone(&called);
        move |_phone_number, code| {
            *called
                .lock()
                .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))? = true;
            Ok(code == "external")
        }
    });
    let router = router_with_options(options, adapter)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{PHONE}","code":"external","disableSession":true}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(*called.lock().map_err(|_| "lock poisoned")?);
    Ok(())
}

#[tokio::test]
async fn custom_verify_otp_deletes_existing_internal_otp() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    seed_user_with_phone(&adapter, PHONE, false).await?;
    seed_otp(&adapter, PHONE, "123456", 0, 300).await?;
    let options =
        PhoneNumberOptions::default().verify_otp(|_phone_number, code| Ok(code == "external"));
    let router = router_with_options(options, adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/phone-number/verify",
            &format!(r#"{{"phoneNumber":"{PHONE}","code":"external","disableSession":true}}"#),
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(find_verification(&adapter, PHONE).await?.is_none());
    Ok(())
}

fn router_with_options(
    options: PhoneNumberOptions,
    inner: Arc<MemoryAdapter>,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_options_and_openauth(options, inner, OpenAuthOptions::default())
}

fn router_with_options_and_openauth(
    options: PhoneNumberOptions,
    inner: Arc<MemoryAdapter>,
    openauth_options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
    let base_adapter: Arc<dyn DbAdapter> = inner;
    let plugin = phone_number_with(options.clone());
    let mut initial_options = openauth_options.clone();
    initial_options.secret = Some(secret().to_owned());
    initial_options.plugins = vec![plugin.clone()];
    initial_options.advanced = advanced_options();
    let initial_options =
        openauth_core::test_utils::with_integration_test_defaults(initial_options);
    let initial_context =
        create_auth_context_with_adapter(initial_options, Arc::clone(&base_adapter))?;
    let hooked: Arc<dyn DbAdapter> = Arc::new(HookedAdapter::new(
        Arc::clone(&base_adapter),
        initial_context.plugin_database_hooks.clone(),
    ));
    let adapter: Arc<dyn DbAdapter> =
        Arc::new(JoinAdapter::new(initial_context.db_schema, hooked, false));
    let mut final_options = openauth_options;
    final_options.secret = Some(secret().to_owned());
    final_options.plugins = vec![phone_number_with(options)];
    final_options.advanced = advanced_options();
    let final_options = openauth_core::test_utils::with_integration_test_defaults(final_options);
    let context = create_auth_context_with_adapter(final_options, Arc::clone(&adapter))?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn advanced_options() -> AdvancedOptions {
    AdvancedOptions {
        disable_csrf_check: true,
        disable_origin_check: true,
        ..AdvancedOptions::default()
    }
}

fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

fn secret() -> &'static str {
    "test-secret-123456789012345678901234"
}

fn signed_session_cookie(token: &str) -> Result<String, OpenAuthError> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            secret: Some(secret().to_owned()),
            ..OpenAuthOptions::default()
        },
        Arc::new(MemoryAdapter::new()),
    )?;
    let cookies = set_session_cookie(
        &context.auth_cookies,
        &context.secret,
        token,
        SessionCookieOptions::default(),
    )?;
    Ok(cookie_header(&cookies))
}

fn cookie_header(cookies: &[Cookie]) -> String {
    cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

async fn seed_user_with_phone(
    adapter: &MemoryAdapter,
    phone: &str,
    verified: bool,
) -> Result<(), OpenAuthError> {
    seed_user_with_phone_id(adapter, "user_1", phone, verified).await
}

async fn seed_user_with_phone_id(
    adapter: &MemoryAdapter,
    id: &str,
    phone: &str,
    verified: bool,
) -> Result<(), OpenAuthError> {
    let user = DbUserStore::new(adapter)
        .create_user(
            CreateUserInput::new(format!("User {id}"), format!("{id}@example.com"))
                .id(id.to_owned())
                .email_verified(true),
        )
        .await?;
    adapter
        .update(
            Update::new("user")
                .where_clause(Where::new("id", DbValue::String(user.id)))
                .data("phone_number", DbValue::String(phone.to_owned()))
                .data("phone_number_verified", DbValue::Boolean(verified)),
        )
        .await?;
    Ok(())
}

async fn seed_otp(
    adapter: &MemoryAdapter,
    identifier: &str,
    code: &str,
    attempts: u32,
    expires_in_seconds: i64,
) -> Result<(), OpenAuthError> {
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            identifier.to_owned(),
            format!("{code}:{attempts}"),
            OffsetDateTime::now_utc() + Duration::seconds(expires_in_seconds),
        ))
        .await?;
    Ok(())
}

async fn seed_reset_otp(
    adapter: &MemoryAdapter,
    phone: &str,
    code: &str,
    attempts: u32,
    expires_in_seconds: i64,
) -> Result<(), OpenAuthError> {
    seed_otp(
        adapter,
        &reset_identifier(phone),
        code,
        attempts,
        expires_in_seconds,
    )
    .await
}

fn reset_identifier(phone_number: &str) -> String {
    format!("{phone_number}-request-password-reset")
}

async fn find_reset_verification(
    adapter: &MemoryAdapter,
    phone: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    find_verification(adapter, &reset_identifier(phone)).await
}

async fn find_user_by_phone(
    adapter: &MemoryAdapter,
    phone: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            "phone_number",
            DbValue::String(phone.to_owned()),
        )))
        .await
}

async fn record_by_id(
    adapter: &MemoryAdapter,
    model: &str,
    id: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(
            FindOne::new(model).where_clause(Where::new("id", DbValue::String(id.to_owned()))),
        )
        .await
}

async fn find_verification(
    adapter: &MemoryAdapter,
    identifier: &str,
) -> Result<Option<DbRecord>, OpenAuthError> {
    adapter
        .find_one(FindOne::new("verification").where_clause(Where::new(
            "identifier",
            DbValue::String(identifier.to_owned()),
        )))
        .await
}

struct RecordPasswordReset {
    user_ids: Arc<Mutex<Vec<String>>>,
}

impl OnPasswordReset for RecordPasswordReset {
    fn on_password_reset(
        &self,
        payload: PasswordResetPayload,
        _request: Option<&Request<Vec<u8>>>,
    ) -> Result<(), OpenAuthError> {
        self.user_ids
            .lock()
            .map_err(|_| OpenAuthError::Api("lock poisoned".to_owned()))?
            .push(payload.user.id);
        Ok(())
    }
}
