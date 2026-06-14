use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use rustauth_axum::test_utils::with_loopback_client_ip;
use rustauth_core::options::{DeploymentMode, RustAuthOptions};
use rustauth_example_backend_reference::auth::AuthStack;
use rustauth_example_backend_reference::client::{
    register_and_sign_in, sign_in_email, SignInEmailBody,
};
use rustauth_example_backend_reference::config::AppConfig;
use rustauth_example_backend_reference::server::build_router;
use tower::ServiceExt;

fn test_config() -> AppConfig {
    AppConfig {
        host: "127.0.0.1".to_owned(),
        port: 3000,
        auth_base_path: rustauth_example_backend_reference::config::AUTH_BASE_PATH.to_owned(),
        base_url: "http://127.0.0.1:3000/api/auth".to_owned(),
        secret: rustauth_example_backend_reference::config::DEFAULT_SECRET.to_owned(),
        database_url: String::new(),
        trusted_origins: vec!["http://127.0.0.1:3000".to_owned()],
        cognito_domain: "rustauth-reference.auth.example.com".to_owned(),
        cognito_region: "us-east-1".to_owned(),
        cognito_user_pool_id: "us-east-1_rustauth_reference".to_owned(),
    }
}

#[tokio::test]
async fn health_and_catalog_respond() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stack = AuthStack::in_memory(test_config()).await?;
    let app = build_router(stack)?;

    for path in [
        "/health",
        "/reference/runtime",
        "/reference/endpoints",
        "/reference/groups",
        "/reference/openapi.json",
        "/reference/plugins",
        "/reference/access",
        "/reference/social-patterns",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "path {path}");
    }

    Ok(())
}

#[tokio::test]
async fn introspection_routes_are_hidden_outside_development(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = test_config();
    let options = rustauth_example_backend_reference::auth::options::build_rustauth_options(
        &AppConfig {
            secret: "production-strength-secret-at-least-32-chars".to_owned(),
            ..config
        },
    )?;
    let auth = rustauth::RustAuth::builder()
        .options(
            RustAuthOptions {
                mode: DeploymentMode::Production,
                ..options
            },
        )
        .adapter(rustauth::db::MemoryAdapter::new())
        .build()
        .await?;
    let stack = AuthStack {
        auth: std::sync::Arc::new(auth),
        config: AppConfig {
            secret: "production-strength-secret-at-least-32-chars".to_owned(),
            ..test_config()
        },
    };
    let app = build_router(stack)?;

    for path in [
        "/health",
        "/reference/runtime",
        "/reference/endpoints",
        "/reference/groups",
        "/reference/openapi.json",
        "/reference/plugins",
        "/reference/access",
        "/reference/social-patterns",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
    }

    Ok(())
}

#[tokio::test]
async fn email_sign_up_and_sign_in_via_http() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let config = test_config();
    let stack = AuthStack::in_memory(config.clone()).await?;
    let app = build_router(stack)?;

    let response = app
        .clone()
        .oneshot(with_loopback_client_ip(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/sign-up/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"name":"Ada","email":"ada@example.com","password":"password123456"}"#,
                ))?,
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value
            .to_str()
            .is_ok_and(|cookie| cookie.starts_with("rustauth-reference.session_token="))));

    let response = app
        .oneshot(with_loopback_client_ip(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/sign-in/email")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"email":"ada@example.com","password":"password123456"}"#,
                ))?,
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn client_flow_helper_signs_in() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = test_config();
    let stack = AuthStack::in_memory(config.clone()).await?;
    let cookie = register_and_sign_in(
        stack.auth.as_ref(),
        &config,
        "Grace",
        "grace@example.com",
        "password123456",
    )
    .await?;

    let sign_in = sign_in_email(
        &config,
        SignInEmailBody {
            email: "grace@example.com",
            password: "password123456",
            remember_me: None,
        },
    )?;
    let response = stack.auth.handler_async(sign_in).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!cookie.is_empty());
    Ok(())
}
