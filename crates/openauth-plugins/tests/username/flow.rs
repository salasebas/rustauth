use std::sync::Arc;

use http::{header, Method, Request, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter};
use openauth_core::db::{DbAdapter, HookedAdapter, JoinAdapter, MemoryAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};
use serde_json::Value;

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
    Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.as_bytes().to_vec())
}
