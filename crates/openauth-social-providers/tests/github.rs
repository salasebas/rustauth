#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, ProviderOptions};
use openauth_social_providers::advanced::github::{
    github, map_github_user_info, GitHubAuthorizationUrlRequest, GitHubEmail, GitHubProfile,
    GitHubValidateAuthorizationCodeRequest,
};

#[test]
fn github_authorization_url_uses_upstream_defaults() {
    let provider = github(ProviderOptions {
        client_id: Some(ClientId::from("github-client")),
        scope: vec!["repo".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider
        .create_authorization_url(GitHubAuthorizationUrlRequest {
            state: "state-token".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: vec!["workflow".to_owned()],
            login_hint: Some("octocat".to_owned()),
            ..GitHubAuthorizationUrlRequest::default()
        })
        .expect("authorization URL should be created");

    assert_eq!(url.as_str(), "https://github.com/login/oauth/authorize?response_type=code&client_id=github-client&state=state-token&scope=read%3Auser+user%3Aemail+repo+workflow&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&login_hint=octocat");
}

#[test]
fn github_authorization_url_can_disable_default_scopes() {
    let provider = github(ProviderOptions {
        client_id: Some(ClientId::from("github-client")),
        scope: vec!["repo".to_owned()],
        disable_default_scope: true,
        ..ProviderOptions::default()
    });

    let url = provider
        .create_authorization_url(GitHubAuthorizationUrlRequest {
            state: "state-token".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            ..GitHubAuthorizationUrlRequest::default()
        })
        .expect("authorization URL should be created");

    let scope = url
        .query_pairs()
        .find(|(key, _)| key == "scope")
        .map(|(_, value)| value.into_owned());
    assert_eq!(scope, Some("repo".to_owned()));
}

#[test]
fn github_authorization_code_request_matches_upstream_form_contract() {
    let provider = github(ProviderOptions {
        client_id: Some(ClientId::from("github-client")),
        client_secret: Some("github-secret".to_owned()),
        ..ProviderOptions::default()
    });

    let request = provider
        .create_authorization_code_request(GitHubValidateAuthorizationCodeRequest {
            code: "auth-code".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            redirect_uri: "https://app.example.com/callback".to_owned(),
        })
        .expect("authorization code request should be created");

    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("auth-code"));
    assert_eq!(
        request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/callback")
    );
    assert_eq!(request.form_value("client_id"), Some("github-client"));
    assert_eq!(request.form_value("client_secret"), Some("github-secret"));
    assert_eq!(request.header("accept"), Some("application/json"));
}

#[test]
fn github_user_info_falls_back_to_primary_email_and_verification_state() {
    let mapped = map_github_user_info(
        GitHubProfile {
            login: "octocat".to_owned(),
            id: "583231".to_owned(),
            avatar_url: Some("https://avatars.githubusercontent.com/u/583231?v=4".to_owned()),
            name: None,
            email: None,
            ..GitHubProfile::default()
        },
        &[
            GitHubEmail {
                email: "secondary@example.com".to_owned(),
                primary: false,
                verified: true,
                visibility: Some("private".to_owned()),
            },
            GitHubEmail {
                email: "octocat@github.example".to_owned(),
                primary: true,
                verified: false,
                visibility: Some("private".to_owned()),
            },
        ],
    );

    assert_eq!(mapped.user.id, "583231");
    assert_eq!(mapped.user.name.as_deref(), Some("octocat"));
    assert_eq!(mapped.user.email.as_deref(), Some("octocat@github.example"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://avatars.githubusercontent.com/u/583231?v=4")
    );
    assert!(!mapped.user.email_verified);
    assert_eq!(mapped.data.email.as_deref(), Some("octocat@github.example"));
}
