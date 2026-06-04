use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::api::{core_auth_async_endpoints, AuthRouter};
use openauth_core::context::create_auth_context_with_adapter;
use openauth_core::db::MemoryAdapter;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions, RateLimitOptions};
use openauth_passkey::{
    passkey, PasskeyChallengeRateLimit, PasskeyOptions, PasskeyRateLimit,
    PasskeyRegistrationOptions, RATE_LIMITED_CEREMONY_PATHS, UPSTREAM_PLUGIN_ID,
};
use serde_json::Value;

#[test]
fn passkey_plugin_registers_ceremony_rate_limit_rules() {
    let plugin = passkey(PasskeyOptions::default());
    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);
    assert_eq!(plugin.rate_limit.len(), RATE_LIMITED_CEREMONY_PATHS.len());
    for path in RATE_LIMITED_CEREMONY_PATHS {
        assert!(
            plugin.rate_limit.iter().any(|rule| rule.path == *path),
            "missing rate limit for {path}"
        );
    }
}

#[tokio::test]
async fn generate_authenticate_options_uses_passkey_rate_limit_rule(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = rate_limited_router(PasskeyRateLimit { window: 60, max: 1 }).await?;

    let first = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-authenticate-options",
    )
    .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let second = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-authenticate-options",
    )
    .await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_body(&second)?["code"], "TOO_MANY_REQUESTS");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_uses_passkey_rate_limit_rule(
) -> Result<(), Box<dyn std::error::Error>> {
    let router = rate_limited_router(PasskeyRateLimit { window: 60, max: 1 }).await?;

    let options_response = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-authenticate-options",
    )
    .await?;
    assert_eq!(options_response.status(), StatusCode::OK);
    let passkey_cookie = crate::support::cookie_header_from_response(&options_response);

    let first = json_request(
        &router,
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&passkey_cookie),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);

    let second = json_request(
        &router,
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&passkey_cookie),
    )
    .await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_body(&second)?["code"], "TOO_MANY_REQUESTS");
    Ok(())
}

#[tokio::test]
async fn verify_authentication_enforces_per_challenge_rate_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    crate::support::seed_user(adapter.as_ref()).await?;
    let backend = Arc::new(crate::support::FakeWebAuthnBackend::default());
    let router = build_rate_limited_router(
        adapter,
        passkey_options_with_limits(
            PasskeyRateLimit {
                window: 60,
                max: 100,
            },
            PasskeyChallengeRateLimit { window: 60, max: 3 },
            backend,
        ),
    )
    .await?;

    let options_response = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-authenticate-options",
    )
    .await?;
    assert_eq!(options_response.status(), StatusCode::OK);
    let passkey_cookie = crate::support::cookie_header_from_response(&options_response);

    for _ in 0..3 {
        let response = json_request(
            &router,
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&passkey_cookie),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let limited = json_request(
        &router,
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&passkey_cookie),
    )
    .await?;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_body(&limited)?["code"], "TOO_MANY_REQUESTS");
    Ok(())
}

#[tokio::test]
async fn fresh_challenge_cookie_has_independent_per_challenge_bucket(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    crate::support::seed_user(adapter.as_ref()).await?;
    let backend = Arc::new(crate::support::FakeWebAuthnBackend::default());
    let router = build_rate_limited_router(
        adapter,
        passkey_options_with_limits(
            PasskeyRateLimit {
                window: 60,
                max: 100,
            },
            PasskeyChallengeRateLimit { window: 60, max: 1 },
            backend,
        ),
    )
    .await?;

    let first_options = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-authenticate-options",
    )
    .await?;
    let first_cookie = crate::support::cookie_header_from_response(&first_options);
    let first_verify = json_request(
        &router,
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&first_cookie),
    )
    .await?;
    assert_eq!(first_verify.status(), StatusCode::BAD_REQUEST);

    let second_verify = json_request(
        &router,
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&first_cookie),
    )
    .await?;
    assert_eq!(second_verify.status(), StatusCode::TOO_MANY_REQUESTS);

    let second_options = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-authenticate-options",
    )
    .await?;
    let second_cookie = crate::support::cookie_header_from_response(&second_options);
    let fresh_verify = json_request(
        &router,
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&second_cookie),
    )
    .await?;
    assert_eq!(fresh_verify.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn ceremony_ip_rate_limit_still_applies_when_challenge_limit_not_exceeded(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    crate::support::seed_user(adapter.as_ref()).await?;
    let router = build_rate_limited_router(
        adapter,
        passkey_options_with_limits(
            PasskeyRateLimit { window: 60, max: 1 },
            PasskeyChallengeRateLimit {
                window: 60,
                max: 100,
            },
            Arc::new(crate::support::FakeWebAuthnBackend::default()),
        ),
    )
    .await?;

    let options_response = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-authenticate-options",
    )
    .await?;
    let passkey_cookie = crate::support::cookie_header_from_response(&options_response);

    let first = json_request(
        &router,
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&passkey_cookie),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);

    let second = json_request(
        &router,
        Method::POST,
        "/api/auth/passkey/verify-authentication",
        r#"{"response":{"id":"credential-id"}}"#,
        Some(&passkey_cookie),
    )
    .await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[tokio::test]
async fn ceremony_rate_limits_are_independent_per_path() -> Result<(), Box<dyn std::error::Error>> {
    let router =
        rate_limited_router_with_registration(PasskeyRateLimit { window: 60, max: 1 }).await?;

    let authenticate_options = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-authenticate-options",
    )
    .await?;
    assert_eq!(authenticate_options.status(), StatusCode::OK);

    let register_options = empty_request(
        &router,
        Method::GET,
        "/api/auth/passkey/generate-register-options?context=preauth@example.com",
    )
    .await?;
    assert_eq!(register_options.status(), StatusCode::OK);
    Ok(())
}

fn passkey_options_with_rate_limit(
    rate_limit: PasskeyRateLimit,
    backend: Arc<crate::support::FakeWebAuthnBackend>,
) -> PasskeyOptions {
    passkey_options_with_limits(rate_limit, PasskeyChallengeRateLimit::default(), backend)
}

fn passkey_options_with_limits(
    rate_limit: PasskeyRateLimit,
    challenge_rate_limit: PasskeyChallengeRateLimit,
    backend: Arc<crate::support::FakeWebAuthnBackend>,
) -> PasskeyOptions {
    PasskeyOptions::default()
        .backend(backend)
        .rate_limit(rate_limit)
        .challenge_rate_limit(challenge_rate_limit)
}

async fn rate_limited_router(
    rate_limit: PasskeyRateLimit,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    crate::support::seed_user(adapter.as_ref()).await?;
    let backend = Arc::new(crate::support::FakeWebAuthnBackend::default());
    build_rate_limited_router(
        adapter,
        passkey_options_with_rate_limit(rate_limit, backend),
    )
    .await
}

async fn rate_limited_router_with_registration(
    rate_limit: PasskeyRateLimit,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    crate::support::seed_user(adapter.as_ref()).await?;
    let backend = Arc::new(crate::support::FakeWebAuthnBackend::default());
    let options = passkey_options_with_rate_limit(rate_limit, backend).registration(
        PasskeyRegistrationOptions::new()
            .require_session(false)
            .resolve_user(|input| {
                Some(openauth_passkey::PasskeyRegistrationUser::new(
                    format!("user-{}", input.context.as_deref().unwrap_or("missing")),
                    input
                        .context
                        .unwrap_or_else(|| "missing@example.com".to_owned()),
                ))
            }),
    );
    build_rate_limited_router(adapter, options).await
}

async fn build_rate_limited_router(
    adapter: Arc<MemoryAdapter>,
    options: PasskeyOptions,
) -> Result<AuthRouter, Box<dyn std::error::Error>> {
    let context = create_auth_context_with_adapter(
        OpenAuthOptions {
            base_url: Some("http://localhost:3000".to_owned()),
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            plugins: vec![passkey(options)],
            rate_limit: RateLimitOptions {
                enabled: Some(true),
                ..RateLimitOptions::default()
            },
            ..OpenAuthOptions::default()
        },
        adapter.clone(),
    )?;
    Ok(AuthRouter::with_async_endpoints(
        context,
        Vec::new(),
        core_auth_async_endpoints(adapter),
    )?)
}

async fn empty_request(
    router: &AuthRouter,
    method: Method,
    path: &str,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(router
        .handle_async(crate::support::empty_request(method, path, None)?)
        .await?)
}

async fn json_request(
    router: &AuthRouter,
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<http::Response<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(router
        .handle_async(crate::support::json_request(method, path, body, cookie)?)
        .await?)
}

fn json_body(response: &http::Response<Vec<u8>>) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(response.body())?)
}
