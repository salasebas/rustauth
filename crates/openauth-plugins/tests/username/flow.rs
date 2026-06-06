use std::sync::{Arc, Mutex};

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::crypto::password::hash_password;
use openauth_core::db::{
    Create, DbAdapter, DbValue, FindOne, HookedAdapter, JoinAdapter, MemoryAdapter, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, EmailPasswordOptions, EmailVerificationOptions, OpenAuthOptions,
    VerificationEmail,
};
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
    assert_eq!(body["user"]["display_username"], "Ada_User");
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
        OpenAuthOptions {
            plugins: vec![openauth_plugins::username::username()],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            email_password: EmailPasswordOptions::new()
                .enabled(true)
                .require_email_verification(true),
            advanced: test_advanced_options(),
            ..OpenAuthOptions::default()
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
        OpenAuthOptions {
            plugins: vec![openauth_plugins::username::username()],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            email_password: EmailPasswordOptions::new()
                .enabled(true)
                .require_email_verification(true),
            advanced: test_advanced_options(),
            ..OpenAuthOptions::default()
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
        OpenAuthOptions {
            plugins: vec![openauth_plugins::username::username()],
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            email_password: EmailPasswordOptions::new()
                .enabled(true)
                .require_email_verification(true),
            email_verification: EmailVerificationOptions::builder()
                .send_on_sign_in(true)
                .send_verification_email(
                    move |email: VerificationEmail, _request: Option<&Request<Vec<u8>>>| {
                        capture
                            .lock()
                            .map_err(|_| {
                                OpenAuthError::Api("verification email mutex poisoned".to_owned())
                            })?
                            .push(email);
                        Ok(())
                    },
                ),
            advanced: test_advanced_options(),
            ..OpenAuthOptions::default()
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
    let sent = sent
        .lock()
        .map_err(|_| OpenAuthError::Api("verification email mutex poisoned".to_owned()))?;
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
async fn update_user_rejects_duplicate_username_with_different_casing(
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

fn router(adapter: Arc<MemoryAdapter>) -> Result<AuthRouter, OpenAuthError> {
    router_with_options(adapter, options())
}

fn router_with_options(
    adapter: Arc<MemoryAdapter>,
    options: OpenAuthOptions,
) -> Result<AuthRouter, OpenAuthError> {
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
    AuthRouter::with_async_endpoints(context, Vec::new(), core_auth_async_endpoints(adapter))
}

fn options() -> OpenAuthOptions {
    OpenAuthOptions {
        plugins: vec![openauth_plugins::username::username()],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        advanced: test_advanced_options(),
        email_password: EmailPasswordOptions::new().enabled(true),
        development: true,
        ..OpenAuthOptions::default()
    }
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

async fn seed_unverified_username(adapter: &MemoryAdapter) -> Result<(), OpenAuthError> {
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
                .data("password", DbValue::String(hash_password("secret123")?))
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now))
                .force_allow_id(),
        )
        .await?;
    Ok(())
}
