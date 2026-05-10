use openauth_core::utils::fetch_metadata::is_browser_fetch_request;
use openauth_core::utils::url::normalize_pathname;

#[test]
fn normalize_pathname_removes_base_path_and_trailing_slash() {
    assert_eq!(
        normalize_pathname(
            "http://localhost:3000/api/auth/sso/saml2/callback/provider1/",
            "/api/auth",
        ),
        "/sso/saml2/callback/provider1"
    );
}

#[test]
fn normalize_pathname_returns_root_for_exact_base_path_match() {
    assert_eq!(
        normalize_pathname("http://localhost:3000/api/auth", "/api/auth"),
        "/"
    );
}

#[test]
fn normalize_pathname_does_not_match_partial_base_path() {
    assert_eq!(
        normalize_pathname("http://localhost:3000/api/authevil/session", "/api/auth"),
        "/api/authevil/session"
    );
}

#[test]
fn normalize_pathname_returns_root_for_invalid_url() {
    assert_eq!(normalize_pathname("not a url", "/api/auth"), "/");
}

#[test]
fn is_browser_fetch_request_returns_true_for_cors() {
    assert!(is_browser_fetch_request(Some("cors")));
}

#[test]
fn is_browser_fetch_request_returns_false_for_navigation() {
    assert!(!is_browser_fetch_request(Some("navigate")));
}

#[test]
fn is_browser_fetch_request_returns_false_without_metadata() {
    assert!(!is_browser_fetch_request(None));
}
