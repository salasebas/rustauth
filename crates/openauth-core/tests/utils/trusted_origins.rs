use http::Request;
use openauth_core::auth::trusted_origins::matches_origin_pattern;
use openauth_core::context::create_auth_context;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{OpenAuthOptions, TrustedOriginOptions};

#[test]
fn context_trusts_configured_base_origin() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(OpenAuthOptions {
        base_url: Some("https://app.example.com/api/auth".to_owned()),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert!(ctx.is_trusted_origin("https://app.example.com/dashboard", None));
    Ok(())
}

#[test]
fn context_rejects_origin_prefix_confusion() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::Static(vec!["https://trusted.com".to_owned()]),
        secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert!(!ctx.is_trusted_origin("https://trusted.com.malicious.com", None));
    Ok(())
}

#[test]
fn context_merges_request_aware_trusted_origins() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = create_auth_context(OpenAuthOptions {
        trusted_origins: TrustedOriginOptions::dynamic_with_static(
            vec!["https://static.example.com".to_owned()],
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
    let request = Request::builder()
        .uri("http://localhost:3000/api/auth/ok")
        .header("x-tenant-origin", "https://tenant.example.com")
        .body(Vec::new())?;

    assert!(ctx.is_trusted_origin("https://static.example.com/dashboard", None));
    assert!(!ctx.is_trusted_origin("https://tenant.example.com/dashboard", None));
    assert!(ctx.is_trusted_origin_for_request(
        "https://tenant.example.com/dashboard",
        None,
        Some(&request)
    )?);
    Ok(())
}

#[test]
fn matches_origin_pattern_supports_host_wildcards() {
    assert!(matches_origin_pattern(
        "https://api.my-site.com/callback",
        "*.my-site.com",
        None
    ));
    assert!(!matches_origin_pattern(
        "https://my-site.com.evil.test",
        "*.my-site.com",
        None
    ));
}

#[test]
fn matches_origin_pattern_supports_protocol_specific_wildcards() {
    assert!(matches_origin_pattern(
        "https://api.protocol-site.com",
        "https://*.protocol-site.com",
        None
    ));
    assert!(!matches_origin_pattern(
        "http://api.protocol-site.com",
        "https://*.protocol-site.com",
        None
    ));
}

#[test]
fn matches_origin_pattern_supports_custom_scheme_wildcards() {
    assert!(matches_origin_pattern(
        "exp://10.0.0.29:8081/--/",
        "exp://10.0.0.*:*/*",
        None
    ));
    assert!(!matches_origin_pattern(
        "exp://203.0.113.0:8081/--/",
        "exp://10.0.0.*:*/*",
        None
    ));
}

#[test]
fn relative_paths_are_rejected_by_default() {
    assert!(!matches_origin_pattern("/", "https://example.com", None));
    assert!(!matches_origin_pattern(
        "/dashboard",
        "https://example.com",
        None
    ));
}

#[test]
fn safe_relative_paths_can_be_allowed() {
    let settings = Some(openauth_core::auth::trusted_origins::OriginMatchSettings {
        allow_relative_paths: true,
    });

    assert!(matches_origin_pattern("/", "https://example.com", settings));
    assert!(matches_origin_pattern(
        "/dashboard?email=123@email.com",
        "https://example.com",
        settings
    ));
    assert!(!matches_origin_pattern(
        "//evil.com",
        "https://example.com",
        settings
    ));
    assert!(!matches_origin_pattern(
        "/%5C/evil.com",
        "https://example.com",
        settings
    ));
}
