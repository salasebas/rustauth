use openauth_core::cookies::{
    get_cookies, get_session_cookie, parse_cookies, parse_set_cookie_header,
    strip_secure_cookie_prefix, to_cookie_options, CookieConfig, SECURE_COOKIE_PREFIX,
};
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};

#[test]
fn get_cookies_uses_default_names_and_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;

    assert_eq!(cookies.session_token.name, "better-auth.session_token");
    assert_eq!(cookies.session_token.attributes.path.as_deref(), Some("/"));
    assert_eq!(cookies.session_token.attributes.http_only, Some(true));
    assert_eq!(
        cookies.session_token.attributes.same_site.as_deref(),
        Some("lax")
    );
    Ok(())
}

#[test]
fn get_cookies_uses_secure_prefix_when_https_base_url() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions {
        base_url: Some("https://example.com".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    assert!(cookies.session_token.name.starts_with(SECURE_COOKIE_PREFIX));
    assert_eq!(cookies.session_token.attributes.secure, Some(true));
    Ok(())
}

#[test]
fn get_cookies_applies_custom_prefix_and_domain() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions {
        base_url: Some("https://example.com".to_owned()),
        advanced: AdvancedOptions {
            cookie_prefix: Some("custom".to_owned()),
            cross_subdomain_cookies: Some(CookieConfig {
                enabled: true,
                domain: Some("example.com".to_owned()),
            }),
            ..AdvancedOptions::default()
        },
        ..OpenAuthOptions::default()
    })?;

    assert!(cookies.session_token.name.contains("custom.session_token"));
    assert_eq!(
        cookies.session_token.attributes.domain.as_deref(),
        Some("example.com")
    );
    Ok(())
}

#[test]
fn parse_cookies_preserves_values_containing_equals() {
    let cookies = parse_cookies("a=1; token=hello=world");

    assert_eq!(
        cookies.get("token").map(String::as_str),
        Some("hello=world")
    );
}

#[test]
fn parse_set_cookie_header_handles_expires_commas_and_multiple_cookies() {
    let parsed = parse_set_cookie_header(
        "a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/, b=2; Path=/auth",
    );

    assert_eq!(parsed.get("a").map(|c| c.value.as_str()), Some("1"));
    assert_eq!(
        parsed.get("b").map(|c| c.path.as_deref()),
        Some(Some("/auth"))
    );
}

#[test]
fn parse_set_cookie_header_decodes_uri_encoded_values() {
    let parsed = parse_set_cookie_header("token=hello%20world%3Dfoo; Path=/");

    assert_eq!(
        parsed.get("token").map(|c| c.value.as_str()),
        Some("hello world=foo")
    );
}

#[test]
fn parse_set_cookie_header_parses_partitioned_attribute() {
    let parsed = parse_set_cookie_header(
        "session=xyz; Path=/; Secure; HttpOnly; SameSite=None; Partitioned",
    );

    assert_eq!(parsed.get("session").and_then(|c| c.secure), Some(true));
    assert_eq!(
        parsed.get("session").and_then(|c| c.partitioned),
        Some(true)
    );
}

#[test]
fn to_cookie_options_converts_parsed_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let parsed = parse_set_cookie_header(
        "session=xyz; Path=/auth; Max-Age=300; Secure; HttpOnly; SameSite=None; Partitioned",
    );
    let options = to_cookie_options(parsed.get("session").ok_or("session")?);

    assert_eq!(options.path.as_deref(), Some("/auth"));
    assert_eq!(options.max_age, Some(300));
    assert_eq!(options.secure, Some(true));
    assert_eq!(options.http_only, Some(true));
    assert_eq!(options.same_site.as_deref(), Some("none"));
    assert_eq!(options.partitioned, Some(true));
    Ok(())
}

#[test]
fn strip_secure_cookie_prefix_removes_secure_prefix() {
    assert_eq!(
        strip_secure_cookie_prefix("__Secure-better-auth.session_token"),
        "better-auth.session_token"
    );
}

#[test]
fn get_session_cookie_reads_default_and_secure_cookie_names() {
    let plain = get_session_cookie("better-auth.session_token=plain", None, None);
    let secure = get_session_cookie("__Secure-better-auth.session_token=secure", None, None);

    assert_eq!(plain.as_deref(), Some("plain"));
    assert_eq!(secure.as_deref(), Some("secure"));
}

#[test]
fn get_session_cookie_supports_custom_prefix_and_name() {
    let token = get_session_cookie(
        "custom.auth_token=value",
        Some("custom"),
        Some("auth_token"),
    );

    assert_eq!(token.as_deref(), Some("value"));
}
