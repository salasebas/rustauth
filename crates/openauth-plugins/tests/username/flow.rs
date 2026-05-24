use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::db::{
    DbAdapter, DbValue, FindOne, HookedAdapter, JoinAdapter, MemoryAdapter, Where,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use serde_json::{json, Value};

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
    let options = options();
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
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
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
