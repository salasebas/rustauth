use rustauth_oidc::{compute_discovery_url, normalize_url, oidc_redirect_uri, OidcFlowOptions};

#[derive(Default)]
struct TestFlowOptions {
    redirect_uri: Option<String>,
}

impl OidcFlowOptions for TestFlowOptions {
    fn redirect_uri(&self) -> Option<&str> {
        self.redirect_uri.as_deref()
    }
}

#[test]
fn discovery_url_trims_trailing_slash() {
    assert_eq!(
        compute_discovery_url("https://idp.example.com/"),
        "https://idp.example.com/.well-known/openid-configuration"
    );
}

#[test]
fn shared_redirect_uri_accepts_path_or_absolute_url() {
    let path_options = TestFlowOptions {
        redirect_uri: Some("/auth/sso/callback".to_owned()),
    };
    assert_eq!(
        oidc_redirect_uri("https://app.example.com", "okta", &path_options),
        "https://app.example.com/auth/sso/callback"
    );

    let absolute_options = TestFlowOptions {
        redirect_uri: Some("https://auth.example.com/callback".to_owned()),
    };
    assert_eq!(
        oidc_redirect_uri("https://app.example.com", "okta", &absolute_options),
        "https://auth.example.com/callback"
    );
}

#[test]
fn normalize_url_rejects_relative_values() {
    assert!(normalize_url("/relative").is_err());
}
