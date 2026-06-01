use openauth_core::cookies::{
    delete_session_cookie, get_cookies, get_session_cookie, parse_cookies, parse_set_cookie_header,
    strip_secure_cookie_prefix, to_cookie_options, CookieConfig, SECURE_COOKIE_PREFIX,
};
use openauth_core::options::{AdvancedOptions, OpenAuthOptions};

#[test]
fn get_cookies_uses_default_names_and_attributes() -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;

    assert_eq!(cookies.session_token.name, "open-auth.session_token");
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
        strip_secure_cookie_prefix("__Secure-open-auth.session_token"),
        "open-auth.session_token"
    );
}

#[test]
fn get_session_cookie_reads_default_and_secure_cookie_names() {
    let plain = get_session_cookie("open-auth.session_token=plain", None, None, false);
    let secure = get_session_cookie("__Secure-open-auth.session_token=secure", None, None, true);

    assert_eq!(plain.as_deref(), Some("plain"));
    assert_eq!(secure.as_deref(), Some("secure"));
}

#[test]
fn get_session_cookie_supports_custom_prefix_and_name() {
    let token = get_session_cookie(
        "custom.auth_token=value",
        Some("custom"),
        Some("auth_token"),
        false,
    );

    assert_eq!(token.as_deref(), Some("value"));
}

#[test]
fn get_session_cookie_prefers_secure_name_when_both_present() {
    let header = "open-auth.session_token=attacker; __Secure-open-auth.session_token=victim";

    let resolved = get_session_cookie(header, None, None, true);

    assert_eq!(resolved.as_deref(), Some("victim"));
}

#[test]
fn get_session_cookie_ignores_unprefixed_name_in_secure_mode() {
    let resolved = get_session_cookie("open-auth.session_token=attacker", None, None, true);

    assert_eq!(resolved, None);
}

#[test]
fn get_session_cookie_ignores_secure_name_in_plain_mode() {
    let resolved = get_session_cookie("__Secure-open-auth.session_token=secure", None, None, false);

    assert_eq!(resolved, None);
}

#[test]
fn delete_session_cookie_expires_unprefixed_fallback_in_secure_mode(
) -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions {
        base_url: Some("https://example.com".to_owned()),
        ..OpenAuthOptions::default()
    })?;

    let expired = delete_session_cookie(&cookies, "open-auth.session_token=attacker", false);

    let unprefixed = expired
        .iter()
        .find(|cookie| cookie.name == "open-auth.session_token")
        .ok_or("expected unprefixed session cookie to be expired")?;
    assert_eq!(unprefixed.value, "");
    assert_eq!(unprefixed.attributes.max_age, Some(0));

    let secure = expired
        .iter()
        .find(|cookie| cookie.name == cookies.session_token.name)
        .ok_or("expected secure session cookie to be expired")?;
    assert_eq!(secure.attributes.max_age, Some(0));
    Ok(())
}

#[test]
fn delete_session_cookie_skips_unprefixed_fallback_in_plain_mode(
) -> Result<(), Box<dyn std::error::Error>> {
    let cookies = get_cookies(&OpenAuthOptions::default())?;

    let expired = delete_session_cookie(&cookies, "open-auth.session_token=token", false);

    assert_eq!(
        expired
            .iter()
            .filter(|cookie| cookie.name == "open-auth.session_token")
            .count(),
        1
    );
    Ok(())
}
