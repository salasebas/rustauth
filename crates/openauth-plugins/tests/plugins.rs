#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration tests intentionally fail fast with contextual setup errors"
)]

#[path = "access/mod.rs"]
mod access;
#[path = "additional_fields/mod.rs"]
mod additional_fields;
#[path = "admin/mod.rs"]
mod admin;
#[path = "anonymous/mod.rs"]
mod anonymous;
#[path = "api_key/mod.rs"]
mod api_key;
#[path = "bearer/mod.rs"]
mod bearer;
#[path = "captcha/mod.rs"]
mod captcha;
#[path = "custom_session/mod.rs"]
mod custom_session;
#[path = "device_authorization/mod.rs"]
mod device_authorization;
#[path = "email_otp/mod.rs"]
mod email_otp;
#[path = "generic_oauth/mod.rs"]
mod generic_oauth;
#[path = "have_i_been_pwned/mod.rs"]
mod have_i_been_pwned;
#[path = "integration_matrix/mod.rs"]
mod integration_matrix;
#[path = "jwt/mod.rs"]
mod jwt;
#[path = "last_login_method/mod.rs"]
mod last_login_method;
#[path = "magic_link/mod.rs"]
mod magic_link;
#[path = "multi_session/mod.rs"]
mod multi_session;
#[path = "oauth_proxy/mod.rs"]
mod oauth_proxy;
#[path = "one_tap/mod.rs"]
mod one_tap;
#[path = "one_time_token/mod.rs"]
mod one_time_token;
#[path = "open_api/mod.rs"]
mod open_api;
#[path = "organization/mod.rs"]
mod organization;
#[path = "phone_number/mod.rs"]
mod phone_number;
#[path = "siwe/mod.rs"]
mod siwe;
#[path = "two_factor/mod.rs"]
mod two_factor;
#[path = "username/mod.rs"]
mod username;

#[test]
fn plugin_ids_expose_supported_server_plugins() {
    let supported = supported_server_plugins();
    assert_eq!(openauth_plugins::PLUGIN_IDS, supported.as_slice(),);
}

#[test]
fn upstream_server_plugin_parity_is_explicit_about_replaced_oidc_provider() {
    let upstream = upstream_server_plugins();
    let supported = supported_server_plugins();
    let replaced = replaced_server_plugins();

    for plugin_id in upstream {
        assert!(
            supported.contains(&plugin_id) || replaced.iter().any(|(id, _)| id == &plugin_id),
            "upstream server plugin `{plugin_id}` is neither supported nor explicitly replaced",
        );
    }
    assert!(replaced.contains(&("oidc-provider", "openauth-oauth-provider")));
    assert!(replaced.contains(&("mcp", "openauth-oauth-provider")));
    assert!(!supported.contains(&"oidc-provider"));
    assert!(!supported.contains(&"mcp"));
}

fn supported_server_plugins() -> Vec<&'static str> {
    vec![
        "access",
        "additional-fields",
        "admin",
        "anonymous",
        "api-key",
        "bearer",
        "captcha",
        "custom-session",
        "device-authorization",
        "email-otp",
        "generic-oauth",
        "haveibeenpwned",
        "jwt",
        "last-login-method",
        "magic-link",
        "multi-session",
        "oauth-proxy",
        "one-tap",
        "one-time-token",
        "open-api",
        "organization",
        "phone-number",
        "siwe",
        "two-factor",
        "username",
    ]
}

fn upstream_server_plugins() -> Vec<&'static str> {
    vec![
        "access",
        "additional-fields",
        "admin",
        "anonymous",
        "api-key",
        "bearer",
        "captcha",
        "custom-session",
        "device-authorization",
        "email-otp",
        "generic-oauth",
        "haveibeenpwned",
        "jwt",
        "last-login-method",
        "magic-link",
        "mcp",
        "multi-session",
        "oauth-proxy",
        "oidc-provider",
        "one-tap",
        "one-time-token",
        "open-api",
        "organization",
        "phone-number",
        "siwe",
        "two-factor",
        "username",
    ]
}

fn replaced_server_plugins() -> Vec<(&'static str, &'static str)> {
    vec![
        ("oidc-provider", "openauth-oauth-provider"),
        ("mcp", "openauth-oauth-provider"),
    ]
}
