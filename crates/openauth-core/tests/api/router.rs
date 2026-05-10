use http::{Method, Request, StatusCode};
use openauth_core::api::{
    core_endpoints, response, ApiErrorResponse, ApiRequest, ApiResponse, AuthEndpoint, AuthRouter,
};
use openauth_core::context::create_auth_context;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{AdvancedOptions, OpenAuthOptions, TrustedOriginOptions};

fn post_ok_endpoint() -> AuthEndpoint {
    AuthEndpoint {
        path: "/post-ok".to_owned(),
        method: Method::POST,
        handler: post_ok_handler,
    }
}

fn post_ok_handler(
    _context: &openauth_core::context::AuthContext,
    _request: ApiRequest,
) -> Result<ApiResponse, OpenAuthError> {
    response(StatusCode::OK, b"POST OK".to_vec())
}

fn assert_error_body(
    response: &ApiResponse,
    code: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .ok_or("missing content-type")?,
        "application/json"
    );
    let body: ApiErrorResponse = serde_json::from_slice(response.body())?;
    assert_eq!(body.code, code);
    assert_eq!(body.message, message);
    Ok(())
}

#[test]
fn auth_router_returns_not_found_for_disabled_path() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        disabled_paths: vec!["/sign-in/email".to_owned()],
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, core_endpoints());
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/sign-in/email")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_error_body(&response, "NOT_FOUND", "Not Found")?;
    Ok(())
}

#[test]
fn auth_router_exposes_ok_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, core_endpoints());
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"OK");
    Ok(())
}

#[test]
fn auth_router_rejects_trailing_slash_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, core_endpoints());
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok/")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_error_body(&response, "NOT_FOUND", "Not Found")?;
    Ok(())
}

#[test]
fn auth_router_can_skip_trailing_slashes() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        advanced: AdvancedOptions {
            skip_trailing_slashes: true,
            ..AdvancedOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, core_endpoints());
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://localhost:3000/api/auth/ok/")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn auth_router_blocks_cookie_post_with_untrusted_origin() -> Result<(), Box<dyn std::error::Error>>
{
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok")
        .header("cookie", "session=abc")
        .header("origin", "https://evil.example.com")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_error_body(&response, "INVALID_ORIGIN", "Invalid origin")?;
    Ok(())
}

#[test]
fn auth_router_allows_cookie_post_with_trusted_origin() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok")
        .header("cookie", "session=abc")
        .header("origin", "https://app.example.com")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"POST OK");
    Ok(())
}

#[test]
fn auth_router_allows_cookie_post_with_dynamic_trusted_origin(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::dynamic(
            |request: Option<&Request<Vec<u8>>>| -> Result<Vec<String>, OpenAuthError> {
                let Some(request) = request else {
                    return Ok(Vec::new());
                };
                let origin = request
                    .headers()
                    .get("x-tenant-origin")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                Ok(origin.into_iter().collect())
            },
        ),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok")
        .header("cookie", "session=abc")
        .header("origin", "https://tenant.example.com")
        .header("x-tenant-origin", "https://tenant.example.com")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), b"POST OK");
    Ok(())
}

#[test]
fn auth_router_rejects_untrusted_callback_url() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok?callbackURL=https://evil.example.com")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_error_body(&response, "INVALID_CALLBACK_URL", "Invalid callbackURL")?;
    Ok(())
}

#[test]
fn auth_router_allows_dynamic_trusted_callback_url() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::dynamic(
            |request: Option<&Request<Vec<u8>>>| -> Result<Vec<String>, OpenAuthError> {
                let Some(request) = request else {
                    return Ok(Vec::new());
                };
                let origin = request
                    .headers()
                    .get("x-tenant-origin")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                Ok(origin.into_iter().collect())
            },
        ),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok?callbackURL=https://tenant.example.com/dashboard")
        .header("x-tenant-origin", "https://tenant.example.com")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn auth_router_allows_relative_callback_url() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok?callbackURL=/dashboard")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn auth_router_allows_percent_encoded_trusted_callback_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok?callbackURL=https%3A%2F%2Fapp.example.com%2Fdashboard")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn auth_router_rejects_percent_encoded_unsafe_relative_callback_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok?callbackURL=%2F%2Fevil.example.com")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_error_body(&response, "INVALID_CALLBACK_URL", "Invalid callbackURL")?;
    Ok(())
}

#[test]
fn auth_router_skips_csrf_when_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            ..AdvancedOptions::default()
        },
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok")
        .header("cookie", "session=abc")
        .header("origin", "https://evil.example.com")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn auth_router_blocks_cross_site_navigation_without_cookie(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok")
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "navigate")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_error_body(
        &response,
        "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
        "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
    )?;
    Ok(())
}

#[test]
fn auth_router_requires_origin_when_fetch_metadata_is_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let context = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://app.example.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;
    let router = AuthRouter::new(context, vec![post_ok_endpoint()]);
    let request = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/post-ok")
        .header("sec-fetch-site", "same-origin")
        .body(Vec::new())?;

    let response = router.handle(request)?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_error_body(
        &response,
        "MISSING_OR_NULL_ORIGIN",
        "Missing or null Origin",
    )?;
    Ok(())
}
