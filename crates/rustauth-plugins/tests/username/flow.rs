use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use rustauth_core::api::{core_auth_async_endpoints, AuthRouter};
use rustauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use rustauth_core::db::{
    Create, DbAdapter, DbValue, FindOne, HookedAdapter, JoinAdapter, MemoryAdapter, Where,
};
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{
    AdvancedOptions, EmailPasswordOptions, EmailVerificationOptions, RustAuthOptions,
    VerificationEmail,
};
use rustauth_core::test_utils::fast_hash_password;
use rustauth_core::OutboundSendFuture;
use rustauth_plugins::username::{UsernameOptions, ValidationOrder, ValidationPhase};
use serde_json::{json, Value};
use time::OffsetDateTime;

#[tokio::test]
async fn sign_up_normalizes_username_and_preserves_display_username(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone())?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"Ada_User"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["username"], "ada_user");
    assert_eq!(body["user"]["displayUsername"], "Ada_User");
    Ok(())
}

#[tokio::test]
async fn username_availability_and_sign_in_use_normalized_username(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter)?;
    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"Ada_User"}"#,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let unavailable = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/is-username-available",
            r#"{"username":"ADA_USER"}"#,
        )?)
        .await?;
    assert_eq!(unavailable.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(unavailable.body())?;
    assert_eq!(body["available"], false);

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/username",
            r#"{"username":"ADA_USER","password":"secret123"}"#,
        )?)
        .await?;
    assert_eq!(sign_in.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(sign_in.body())?;
    assert!(body["token"]
        .as_str()
        .is_some_and(|token| !token.is_empty()));
    assert_eq!(body["user"]["username"], "ada_user");
    Ok(())
}

#[tokio::test]
async fn custom_username_validator_rejects_sign_up_and_sign_in(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_username_options(
        adapter,
        UsernameOptions {
            username_validator: Arc::new(|username| username.starts_with("crew_")),
            ..UsernameOptions::default()
        },
    )?;

    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"bad_user"}"#,
        )?)
        .await?;
    let sign_up_body: Value = serde_json::from_slice(sign_up.body())?;
    assert_eq!(sign_up.status(), StatusCode::BAD_REQUEST);
    assert_eq!(sign_up_body["code"], "INVALID_USERNAME");

    router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"crew_ada"}"#,
        )?)
        .await?;

    let sign_in = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/username",
            r#"{"username":"bad_user","password":"secret123"}"#,
        )?)
        .await?;
    let sign_in_body: Value = serde_json::from_slice(sign_in.body())?;
    assert_eq!(sign_in.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(sign_in_body["code"], "INVALID_USERNAME");
    Ok(())
}

#[tokio::test]
async fn is_username_available_rejects_too_long_username() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_username_options(
        adapter,
        UsernameOptions {
            max_username_length: 12,
            ..UsernameOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/is-username-available",
            r#"{"username":"abcdefghijklm"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "USERNAME_TOO_LONG");
    Ok(())
}

#[tokio::test]
async fn username_availability_rejects_invalid_username_422(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/is-username-available",
            r#"{"username":"ab"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "USERNAME_TOO_SHORT");
    Ok(())
}

#[tokio::test]
async fn sign_up_rejects_empty_username() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter)?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":""}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "USERNAME_TOO_SHORT");
    Ok(())
}

#[tokio::test]
async fn sign_in_username_rejects_wrong_password_before_other_user_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter)?;
    let sign_up = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"ada_user"}"#,
        )?)
        .await?;
    assert_eq!(sign_up.status(), StatusCode::OK);

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/username",
            r#"{"username":"ada_user","password":"wrong-password"}"#,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_USERNAME_OR_PASSWORD");
    Ok(())
}

#[tokio::test]
async fn sign_in_username_rejects_wrong_password_before_unverified_email_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_unverified_username(adapter.as_ref()).await?;
    let router = router_with_options(
        adapter,
        RustAuthOptions {
            plugins: vec![rustauth_plugins::username::username(
                UsernameOptions::default(),
            )],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            email_password: EmailPasswordOptions::new()
                .enabled(true)
                .require_email_verification(true),
            advanced: test_advanced_options(),
            ..RustAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/username",
            r#"{"username":"ada_user","password":"wrong-password"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "INVALID_USERNAME_OR_PASSWORD");
    Ok(())
}

#[tokio::test]
async fn sign_in_username_requires_verified_email_after_password_is_valid(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_unverified_username(adapter.as_ref()).await?;
    let router = router_with_options(
        adapter,
        RustAuthOptions {
            plugins: vec![rustauth_plugins::username::username(
                UsernameOptions::default(),
            )],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            email_password: EmailPasswordOptions::new()
                .enabled(true)
                .require_email_verification(true),
            advanced: test_advanced_options(),
            ..RustAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/username",
            r#"{"username":"ada_user","password":"secret123"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "EMAIL_NOT_VERIFIED");
    Ok(())
}

#[tokio::test]
async fn sign_in_username_sends_verification_email_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    seed_unverified_username(adapter.as_ref()).await?;
    let sent = Arc::new(Mutex::new(Vec::<VerificationEmail>::new()));
    let capture = Arc::clone(&sent);
    let router = router_with_options(
        adapter,
        RustAuthOptions {
            plugins: vec![rustauth_plugins::username::username(
                UsernameOptions::default(),
            )],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            email_password: EmailPasswordOptions::new()
                .enabled(true)
                .require_email_verification(true),
            email_verification: EmailVerificationOptions::new()
                .send_on_sign_in(true)
                .send_verification_email(
                    move |email: VerificationEmail,
                          _request: Option<&Request<Vec<u8>>>|
                          -> OutboundSendFuture {
                        let capture = Arc::clone(&capture);
                        Box::pin(async move {
                            capture
                                .lock()
                                .map_err(|_| {
                                    RustAuthError::Api(
                                        "verification email mutex poisoned".to_owned(),
                                    )
                                })?
                                .push(email);
                            Ok(())
                        })
                    },
                ),
            advanced: test_advanced_options(),
            ..RustAuthOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-in/username",
            r#"{"username":"ada_user","password":"secret123","callbackURL":"/settings"}"#,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    for _ in 0..200 {
        if sent.lock().map(|emails| emails.len()).unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    let sent = sent
        .lock()
        .map_err(|_| RustAuthError::Api("verification email mutex poisoned".to_owned()))?;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].user.email, "ada@example.com");
    assert!(sent[0].url.contains("callbackURL=%2Fsettings"));
    Ok(())
}

#[tokio::test]
async fn sign_up_rejects_duplicate_normalized_username() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter)?;
    let first = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"Ada_User"}"#,
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let duplicate = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Grace","email":"grace@example.com","password":"secret123","username":"ADA_USER"}"#,
        )?)
        .await?;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(duplicate.body())?;
    assert_eq!(body["code"], "USERNAME_IS_ALREADY_TAKEN");
    Ok(())
}

#[tokio::test]
async fn update_user_rejects_duplicate_username_different_casing(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter)?;
    let _ada = sign_up_username(&router, "Ada", "ada@example.com", "Ada_User").await?;
    let (_grace, grace_cookie) =
        sign_up_username(&router, "Grace", "grace@example.com", "grace_user").await?;

    let response = router
        .handle_async(json_request_with_cookie(
            Method::POST,
            "/api/auth/update-user",
            r#"{"username":"ADA_USER"}"#,
            Some(&grace_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["code"], "USERNAME_IS_ALREADY_TAKEN");
    Ok(())
}

#[tokio::test]
async fn update_user_rejects_duplicate_username_owned_by_different_user(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter)?;
    let _ada = sign_up_username(&router, "Ada", "ada@example.com", "ada_user").await?;
    let (_grace, grace_cookie) =
        sign_up_username(&router, "Grace", "grace@example.com", "grace_user").await?;

    let response = router
        .handle_async(json_request_with_cookie(
            Method::POST,
            "/api/auth/update-user",
            r#"{"username":"ada_user"}"#,
            Some(&grace_cookie),
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "USERNAME_IS_ALREADY_TAKEN");
    Ok(())
}

#[tokio::test]
async fn sign_up_rejects_invalid_display_username() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_username_options(
        adapter,
        UsernameOptions {
            display_username_validator: Some(Arc::new(|display| !display.contains('!'))),
            ..UsernameOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","username":"ada_user","displayUsername":"Ada!"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "INVALID_DISPLAY_USERNAME");
    Ok(())
}

#[tokio::test]
async fn post_normalization_validation_allows_sign_up_display_username_fallback(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router_with_username_options(
        adapter,
        UsernameOptions {
            validation_order: ValidationOrder {
                username: ValidationPhase::PostNormalization,
                display_username: ValidationPhase::PreNormalization,
            },
            username_normalization: Some(Arc::new(|username| username.to_lowercase())),
            ..UsernameOptions::default()
        },
    )?;

    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            r#"{"name":"Ada","email":"ada@example.com","password":"secret123","displayUsername":"Ada_User"}"#,
        )?)
        .await?;
    let body: Value = serde_json::from_slice(response.body())?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body["user"]["username"], "ada_user");
    assert_eq!(body["user"]["displayUsername"], "Ada_User");
    Ok(())
}

#[tokio::test]
async fn update_user_normalizes_username_and_preserves_display_username(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone())?;
    let (body, cookie) = sign_up_username(&router, "Ada", "ada@example.com", "ada_user").await?;
    let user_id = body["user"]["id"].as_str().ok_or("missing user id")?;

    let response = router
        .handle_async(json_request_with_cookie(
            Method::POST,
            "/api/auth/update-user",
            r#"{"username":"New_User","displayUsername":"New User"}"#,
            Some(&cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let user = adapter
        .find_one(
            FindOne::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned()))),
        )
        .await?
        .ok_or("missing user")?;
    assert_eq!(
        user.get("username"),
        Some(&DbValue::String("new_user".to_owned()))
    );
    assert_eq!(
        user.get("display_username"),
        Some(&DbValue::String("New User".to_owned()))
    );
    Ok(())
}

fn router(adapter: Arc<MemoryAdapter>) -> Result<AuthRouter, RustAuthError> {
    router_with_options(adapter, options())
}

fn router_with_options(
    adapter: Arc<MemoryAdapter>,
    options: RustAuthOptions,
) -> Result<AuthRouter, RustAuthError> {
    let options = rustauth_core::test_utils::with_integration_test_defaults(options);
    let context = create_auth_context(options.clone())?;
    let hooked_adapter: Arc<dyn DbAdapter> = Arc::new(HookedAdapter::new(
        adapter,
        context.plugin_database_hooks.clone(),
    ));
    let adapter: Arc<dyn DbAdapter> = Arc::new(JoinAdapter::new(
        context.db_schema,
        hooked_adapter,
        options.experimental.joins,
    ));
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints())
}

fn options() -> RustAuthOptions {
    rustauth_core::test_utils::with_integration_test_defaults(RustAuthOptions {
        plugins: vec![rustauth_plugins::username::username(
            UsernameOptions::default(),
        )],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        advanced: test_advanced_options(),
        ..RustAuthOptions::default()
    })
}

fn router_with_username_options(
    adapter: Arc<MemoryAdapter>,
    username_options: UsernameOptions,
) -> Result<AuthRouter, RustAuthError> {
    router_with_options(
        adapter,
        RustAuthOptions {
            plugins: vec![rustauth_plugins::username::username(username_options)],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            advanced: test_advanced_options(),
            ..RustAuthOptions::default()
        },
    )
}

fn test_advanced_options() -> AdvancedOptions {
    AdvancedOptions {
        disable_csrf_check: true,
        disable_origin_check: true,
        ..AdvancedOptions::default()
    }
}

fn json_request(method: Method, path: &str, body: &str) -> Result<Request<Vec<u8>>, http::Error> {
    json_request_with_cookie(method, path, body, None)
}

fn json_request_with_cookie(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

async fn sign_up_username(
    router: &AuthRouter,
    name: &str,
    email: &str,
    username: &str,
) -> Result<(Value, String), Box<dyn std::error::Error>> {
    let request_body = json!({
        "name": name,
        "email": email,
        "password": "secret123",
        "username": username
    })
    .to_string();
    let response = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/sign-up/email",
            &request_body,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = session_cookie(&response)?;
    let body = serde_json::from_slice(response.body())?;
    Ok((body, cookie))
}

fn session_cookie(
    response: &http::Response<Vec<u8>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|value| value.to_str().ok())
        .ok_or("missing session cookie")?;
    Ok(cookie.to_owned())
}

async fn seed_unverified_username(adapter: &MemoryAdapter) -> Result<(), RustAuthError> {
    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("user")
                .data("id", DbValue::String("user_1".to_owned()))
                .data("name", DbValue::String("Ada".to_owned()))
                .data("email", DbValue::String("ada@example.com".to_owned()))
                .data("email_verified", DbValue::Boolean(false))
                .data("image", DbValue::Null)
                .data("username", DbValue::String("ada_user".to_owned()))
                .data("display_username", DbValue::String("Ada User".to_owned()))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    adapter
        .create(
            Create::new("account")
                .data("id", DbValue::String("account_1".to_owned()))
                .data("provider_id", DbValue::String("credential".to_owned()))
                .data("account_id", DbValue::String("user_1".to_owned()))
                .data("user_id", DbValue::String("user_1".to_owned()))
                .data("access_token", DbValue::Null)
                .data("refresh_token", DbValue::Null)
                .data("id_token", DbValue::Null)
                .data("access_token_expires_at", DbValue::Null)
                .data("refresh_token_expires_at", DbValue::Null)
                .data("scope", DbValue::Null)
                .data(
                    "password",
                    DbValue::String(fast_hash_password("secret123")?),
                )
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}
