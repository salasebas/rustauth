use http::{Method, StatusCode};
use openauth_core::cookies::{parse_set_cookie_header, ParsedCookie};
use openauth_core::options::{AdvancedOptions, CookieAttributesOverride, CookieConfig};
use openauth_passkey::PasskeyOptions;
use serde_json::Value;

use crate::support::{
    cookie_header_from_response, empty_request, json_request_with_origin, seed_passkey,
    seeded_router_with_advanced, set_cookie_values,
};

/// Locate the passkey challenge cookie among a response's `Set-Cookie` headers.
fn challenge_set_cookie(
    response: &http::Response<Vec<u8>>,
) -> Result<(String, ParsedCookie), Box<dyn std::error::Error>> {
    set_cookie_values(response)
        .iter()
        .flat_map(|value| parse_set_cookie_header(value))
        .find(|(name, _)| name.ends_with("better-auth-passkey"))
        .ok_or_else(|| "passkey challenge cookie present".into())
}

#[tokio::test]
async fn passkey_challenge_cookie_is_namespaced_by_cookie_prefix(
) -> Result<(), Box<dyn std::error::Error>> {
    let advanced = AdvancedOptions {
        cookie_prefix: Some("tenant-a".to_owned()),
        disable_csrf_check: true,
        disable_origin_check: true,
        ..AdvancedOptions::default()
    };
    let (_adapter, router, _backend) =
        seeded_router_with_advanced(PasskeyOptions::default(), advanced).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let (name, _) = challenge_set_cookie(&response)?;
    // Namespaced with the same `{prefix}.` convention as session cookies, not
    // the raw default `better-auth-passkey` name.
    assert_eq!(name, "tenant-a.better-auth-passkey");
    Ok(())
}

#[tokio::test]
async fn passkey_challenge_cookie_inherits_cross_subdomain_and_default_attributes(
) -> Result<(), Box<dyn std::error::Error>> {
    let advanced = AdvancedOptions {
        use_secure_cookies: Some(true),
        cross_subdomain_cookies: Some(CookieConfig::new().enabled(true).domain("example.com")),
        default_cookie_attributes: CookieAttributesOverride::new()
            .same_site("Strict")
            .partitioned(true),
        disable_csrf_check: true,
        disable_origin_check: true,
        ..AdvancedOptions::default()
    };
    let (_adapter, router, _backend) =
        seeded_router_with_advanced(PasskeyOptions::default(), advanced).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let (name, cookie) = challenge_set_cookie(&response)?;
    assert_eq!(name, "__Secure-open-auth.better-auth-passkey");
    assert_eq!(cookie.domain.as_deref(), Some("example.com"));
    assert_eq!(cookie.path.as_deref(), Some("/"));
    assert_eq!(cookie.same_site.as_deref(), Some("strict"));
    assert_eq!(cookie.secure, Some(true));
    assert_eq!(cookie.partitioned, Some(true));
    assert_eq!(cookie.max_age, Some(60 * 5));
    Ok(())
}

#[tokio::test]
async fn verify_authentication_reads_prefixed_challenge_cookie_only(
) -> Result<(), Box<dyn std::error::Error>> {
    let advanced = AdvancedOptions {
        cookie_prefix: Some("tenant-a".to_owned()),
        disable_csrf_check: true,
        disable_origin_check: true,
        ..AdvancedOptions::default()
    };
    let (adapter, router, _backend) =
        seeded_router_with_advanced(PasskeyOptions::default(), advanced).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;

    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let prefixed_cookie = cookie_header_from_response(&options_response);
    let (name, value) = prefixed_cookie
        .split_once('=')
        .ok_or("challenge cookie header")?;
    assert_eq!(name, "tenant-a.better-auth-passkey");

    // The same signed token under the raw default name must be ignored.
    let raw_cookie = format!("better-auth-passkey={value}");
    let raw_response = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&raw_cookie),
        )?)
        .await?;
    assert_eq!(raw_response.status(), StatusCode::BAD_REQUEST);
    let raw_body: Value = serde_json::from_slice(raw_response.body())?;
    assert_eq!(raw_body["code"], "CHALLENGE_NOT_FOUND");

    // The derived, prefixed cookie name is read and the ceremony succeeds.
    let response = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&prefixed_cookie),
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body["user"]["id"], "user_1");
    Ok(())
}
