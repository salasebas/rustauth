use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use http::{Method, Request, StatusCode};
use openauth_core::api::{create_auth_endpoint, response, AuthEndpointOptions, AuthRouter};
use openauth_core::context::create_auth_context;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    AdvancedOptions, IpAddressOptions, OpenAuthOptions, RateLimitOptions, RateLimitPathRule,
    RateLimitRule,
};
use openauth_plugins::captcha::{captcha, CaptchaConfigError, CaptchaOptions, CaptchaProvider};

#[test]
fn exposes_captcha_plugin_id() {
    assert_eq!(openauth_plugins::captcha::UPSTREAM_PLUGIN_ID, "captcha");
}

#[test]
fn captcha_rejects_empty_secret_key() {
    let result = captcha(CaptchaOptions::cloudflare_turnstile(""));

    assert!(matches!(result, Err(CaptchaConfigError::MissingSecretKey)));
}

#[test]
fn captcha_options_do_not_serialize_secret_key() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = captcha(CaptchaOptions::hcaptcha("secret").site_key("site"))?;
    let serialized = plugin
        .options
        .ok_or("captcha plugin should expose serializable options")?
        .to_string();

    assert!(!serialized.contains("secret"));
    assert!(serialized.contains("hcaptcha"));
    Ok(())
}

#[tokio::test]
async fn captcha_ignores_non_protected_endpoints() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = captcha(
        CaptchaOptions::cloudflare_turnstile("secret")
            .site_verify_url_override("http://127.0.0.1:1")
            .endpoints(["/sign-up/email"]),
    )?;
    let router = router(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[("x-captcha-response", "token")],
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn captcha_custom_endpoint_matches_containing_request_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = captcha(CaptchaOptions::cloudflare_turnstile("secret").endpoints(["/sign-up"]))?;
    let router = router(plugin, "/sign-up/email")?;

    let response = router.handle_async(request("/sign-up/email", &[])?).await?;

    assert_error(response.status(), response.body(), "MISSING_RESPONSE");
    Ok(())
}

#[tokio::test]
async fn captcha_ignores_protected_path_in_query_string() -> Result<(), Box<dyn std::error::Error>>
{
    // Default endpoints include `/sign-up/email`. A callback/return URL that merely
    // mentions a protected path in the query string must not arm CAPTCHA on an
    // otherwise unprotected route such as `/get-session`.
    let plugin = captcha(CaptchaOptions::cloudflare_turnstile("secret"))?;
    let router = router(plugin, "/get-session")?;

    let response = router
        .handle_async(request("/get-session?next=/sign-up/email", &[])?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn captcha_prefix_does_not_match_partial_segment() -> Result<(), Box<dyn std::error::Error>> {
    // `/sign-up` must match on path-segment boundaries only, so `/sign-up-email`
    // is not protected unless configured explicitly.
    let plugin = captcha(CaptchaOptions::cloudflare_turnstile("secret").endpoints(["/sign-up"]))?;
    let router = router(plugin, "/sign-up-email")?;

    let response = router.handle_async(request("/sign-up-email", &[])?).await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn captcha_prefix_does_not_match_nested_path() -> Result<(), Box<dyn std::error::Error>> {
    // The configured endpoint is a prefix anchor, not a substring: a path that
    // contains it deeper down (`/foo/sign-up/email`) must not be protected.
    let plugin = captcha(CaptchaOptions::cloudflare_turnstile("secret").endpoints(["/sign-up"]))?;
    let router = router(plugin, "/foo/sign-up/email")?;

    let response = router
        .handle_async(request("/foo/sign-up/email", &[])?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn captcha_returns_400_when_response_header_is_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = captcha(CaptchaOptions::cloudflare_turnstile("secret"))?;
    let router = router(plugin, "/sign-in/email")?;

    let response = router.handle_async(request("/sign-in/email", &[])?).await?;

    assert_error(response.status(), response.body(), "MISSING_RESPONSE");
    Ok(())
}

#[tokio::test]
async fn captcha_rejection_consumes_route_rate_limit() -> Result<(), Box<dyn std::error::Error>> {
    let plugin = captcha(CaptchaOptions::cloudflare_turnstile("secret"))?;
    let router = router_with_rate_limit(plugin, "/sign-in/email")?;

    // First rejected CAPTCHA attempt must still consume the route's rate-limit bucket.
    let first = router.handle_async(request("/sign-in/email", &[])?).await?;
    assert_error(first.status(), first.body(), "MISSING_RESPONSE");

    // A second attempt from the same IP/path is throttled instead of bypassing limits.
    let second = router.handle_async(request("/sign-in/email", &[])?).await?;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[tokio::test]
async fn cloudflare_turnstile_sends_json_payload_and_allows_success(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = JsonServer::spawn(200, r#"{"success":true}"#)?;
    let plugin = captcha(
        CaptchaOptions::cloudflare_turnstile("secret").site_verify_url_override(server.url()),
    )?;
    let router = router_trusting_forwarded_for(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[
                ("x-captcha-response", "token"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = server.request_body();
    assert!(body.contains(r#""secret":"secret""#));
    assert!(body.contains(r#""response":"token""#));
    assert!(body.contains(r#""remoteip":"127.0.0.1""#));
    Ok(())
}

#[tokio::test]
async fn cloudflare_turnstile_returns_403_when_provider_rejects(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = JsonServer::spawn(200, r#"{"success":false}"#)?;
    let plugin = captcha(
        CaptchaOptions::cloudflare_turnstile("secret").site_verify_url_override(server.url()),
    )?;
    let router = router(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[("x-captcha-response", "token")],
        )?)
        .await?;

    assert_error(response.status(), response.body(), "VERIFICATION_FAILED");
    Ok(())
}

#[tokio::test]
async fn google_recaptcha_sends_form_payload_with_remote_ip(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = JsonServer::spawn(200, r#"{"success":true}"#)?;
    let plugin =
        captcha(CaptchaOptions::google_recaptcha("secret").site_verify_url_override(server.url()))?;
    let router = router_trusting_forwarded_for(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[
                ("x-captcha-response", "token"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = server.request_body();
    assert!(body.contains("secret=secret"));
    assert!(body.contains("response=token"));
    assert!(body.contains("remoteip=127.0.0.1"));
    Ok(())
}

#[tokio::test]
async fn google_recaptcha_returns_403_when_score_is_too_low(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = JsonServer::spawn(200, r#"{"success":true,"score":0.4}"#)?;
    let plugin =
        captcha(CaptchaOptions::google_recaptcha("secret").site_verify_url_override(server.url()))?;
    let router = router(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[("x-captcha-response", "token")],
        )?)
        .await?;

    assert_error(response.status(), response.body(), "VERIFICATION_FAILED");
    Ok(())
}

#[tokio::test]
async fn hcaptcha_includes_site_key_and_remote_ip() -> Result<(), Box<dyn std::error::Error>> {
    let server = JsonServer::spawn(200, r#"{"success":true}"#)?;
    let plugin = captcha(
        CaptchaOptions::hcaptcha("secret")
            .site_key("site")
            .site_verify_url_override(server.url()),
    )?;
    let router = router_trusting_forwarded_for(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[
                ("x-captcha-response", "token"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = server.request_body();
    assert!(body.contains("sitekey=site"));
    assert!(body.contains("remoteip=127.0.0.1"));
    Ok(())
}

#[tokio::test]
async fn captchafox_uses_remote_ip_form_field() -> Result<(), Box<dyn std::error::Error>> {
    let server = JsonServer::spawn(200, r#"{"success":true}"#)?;
    let plugin = captcha(
        CaptchaOptions::captchafox("secret")
            .site_key("site")
            .site_verify_url_override(server.url()),
    )?;
    let router = router_trusting_forwarded_for(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[
                ("x-captcha-response", "token"),
                ("x-forwarded-for", "127.0.0.1"),
            ],
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = server.request_body();
    assert!(body.contains("sitekey=site"));
    assert!(body.contains("remoteIp=127.0.0.1"));
    Ok(())
}

#[tokio::test]
async fn captcha_returns_500_when_provider_is_unavailable() -> Result<(), Box<dyn std::error::Error>>
{
    let server = JsonServer::spawn(500, r#"{"error":"server_error"}"#)?;
    let plugin = captcha(
        CaptchaOptions::with_provider(CaptchaProvider::CloudflareTurnstile, "secret")
            .site_verify_url_override(server.url()),
    )?;
    let router = router(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[("x-captcha-response", "token")],
        )?)
        .await?;

    assert_error(response.status(), response.body(), "UNKNOWN_ERROR");
    Ok(())
}

#[tokio::test]
async fn captcha_returns_500_when_provider_returns_invalid_json(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = JsonServer::spawn(200, "not-json")?;
    let plugin = captcha(
        CaptchaOptions::cloudflare_turnstile("secret").site_verify_url_override(server.url()),
    )?;
    let router = router(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[("x-captcha-response", "token")],
        )?)
        .await?;

    assert_error(response.status(), response.body(), "UNKNOWN_ERROR");
    Ok(())
}

#[tokio::test]
async fn captcha_returns_500_when_provider_connection_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let plugin = captcha(
        CaptchaOptions::cloudflare_turnstile("secret")
            .site_verify_url_override("http://127.0.0.1:1"),
    )?;
    let router = router(plugin, "/sign-in/email")?;

    let response = router
        .handle_async(request(
            "/sign-in/email",
            &[("x-captcha-response", "token")],
        )?)
        .await?;

    assert_error(response.status(), response.body(), "UNKNOWN_ERROR");
    Ok(())
}

fn router(
    plugin: openauth_core::plugin::AuthPlugin,
    path: &str,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_advanced(plugin, path, AdvancedOptions::default())
}

fn router_trusting_forwarded_for(
    plugin: openauth_core::plugin::AuthPlugin,
    path: &str,
) -> Result<AuthRouter, OpenAuthError> {
    router_with_advanced(
        plugin,
        path,
        AdvancedOptions::default().ip_address(IpAddressOptions::new().headers(["x-forwarded-for"])),
    )
}

fn router_with_advanced(
    plugin: openauth_core::plugin::AuthPlugin,
    path: &str,
    advanced: AdvancedOptions,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..advanced
        },
        ..OpenAuthOptions::default()
    })?;
    let endpoint = create_auth_endpoint(
        path,
        Method::POST,
        AuthEndpointOptions::new(),
        |_context, _request| Box::pin(async { response(StatusCode::OK, b"OK".to_vec()) }),
    );

    AuthRouter::with_async_endpoints(context, Vec::new(), vec![endpoint])
}

fn router_with_rate_limit(
    plugin: openauth_core::plugin::AuthPlugin,
    path: &str,
) -> Result<AuthRouter, OpenAuthError> {
    let context = create_auth_context(OpenAuthOptions {
        plugins: vec![plugin],
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        rate_limit: RateLimitOptions {
            enabled: Some(true),
            custom_rules: vec![RateLimitPathRule {
                path: path.to_owned(),
                rule: Some(RateLimitRule { window: 60, max: 1 }),
            }],
            ..RateLimitOptions::default()
        },
        advanced: AdvancedOptions {
            disable_csrf_check: true,
            disable_origin_check: true,
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;
    let endpoint = create_auth_endpoint(
        path,
        Method::POST,
        AuthEndpointOptions::new(),
        |_context, _request| Box::pin(async { response(StatusCode::OK, b"OK".to_vec()) }),
    );

    AuthRouter::with_async_endpoints(context, Vec::new(), vec![endpoint])
}

fn request(path: &str, headers: &[(&str, &str)]) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:3000/api/auth{path}"));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Vec::new())
}

fn assert_error(status: StatusCode, body: &[u8], code: &str) {
    assert!(String::from_utf8_lossy(body).contains(&format!(r#""code":"{code}""#)));
    match code {
        "MISSING_RESPONSE" => assert_eq!(status, StatusCode::BAD_REQUEST),
        "VERIFICATION_FAILED" => assert_eq!(status, StatusCode::FORBIDDEN),
        "UNKNOWN_ERROR" => assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR),
        _ => unreachable!("unexpected code"),
    }
}

struct JsonServer {
    url: String,
    request_body: Arc<Mutex<String>>,
    handle: Option<thread::JoinHandle<std::io::Result<()>>>,
}

impl JsonServer {
    fn spawn(status: u16, body: &'static str) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        let request_body = Arc::new(Mutex::new(String::new()));
        let body_for_thread = Arc::clone(&request_body);
        let handle = thread::spawn(move || -> std::io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let mut buffer = [0; 8192];
            let read = stream.read(&mut buffer)?;
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            if let Some((_, request_body)) = request.split_once("\r\n\r\n") {
                if let Ok(mut body) = body_for_thread.lock() {
                    *body = request_body.to_owned();
                }
            }
            let response = format!(
                "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes())
        });

        Ok(Self {
            url,
            request_body,
            handle: Some(handle),
        })
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn request_body(&self) -> String {
        match self.request_body.lock() {
            Ok(body) => body.clone(),
            Err(_) => String::new(),
        }
    }
}

impl Drop for JsonServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
