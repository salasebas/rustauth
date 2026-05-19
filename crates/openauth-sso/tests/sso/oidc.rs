use openauth_sso::oidc::discovery::{compute_discovery_url, normalize_url};
use openauth_sso::oidc::flow::oidc_redirect_uri;
use openauth_sso::SsoOptions;

#[test]
fn discovery_url_trims_trailing_slash() {
    assert_eq!(
        compute_discovery_url("https://idp.example.com/"),
        "https://idp.example.com/.well-known/openid-configuration"
    );
}

#[test]
fn shared_redirect_uri_accepts_path_or_absolute_url() {
    let path_options = SsoOptions::default().redirect_uri("/auth/sso/callback");
    assert_eq!(
        oidc_redirect_uri("https://app.example.com", "okta", &path_options),
        "https://app.example.com/auth/sso/callback"
    );

    let absolute_options = SsoOptions::default().redirect_uri("https://auth.example.com/callback");
    assert_eq!(
        oidc_redirect_uri("https://app.example.com", "okta", &absolute_options),
        "https://auth.example.com/callback"
    );
}

#[test]
fn normalize_url_rejects_relative_values() {
    assert!(normalize_url("/relative").is_err());
}
