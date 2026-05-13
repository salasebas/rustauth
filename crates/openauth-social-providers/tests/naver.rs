#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, ProviderOptions};
use openauth_social_providers::naver::{
    naver, NaverAuthorizationUrlRequest, NaverProfile, NaverProfileResponse, NaverProvider,
    NaverProviderOptions, NAVER_AUTHORIZATION_ENDPOINT, NAVER_ID, NAVER_NAME, NAVER_TOKEN_ENDPOINT,
};

#[test]
fn naver_provider_exposes_upstream_metadata() {
    let provider = NaverProvider::new(NaverProviderOptions {
        oauth: provider_options(),
    });

    assert_eq!(provider.id(), NAVER_ID);
    assert_eq!(provider.name(), NAVER_NAME);
}

#[test]
fn authorization_url_includes_upstream_default_scopes() {
    let provider = naver(provider_options());

    let url = provider
        .create_authorization_url(NaverAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/naver/callback".to_owned(),
            scopes: Vec::new(),
            ..NaverAuthorizationUrlRequest::default()
        })
        .expect("authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some(NAVER_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("naver-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/naver/callback".to_owned())
    );
    assert_eq!(query_value(&url, "scope"), Some("profile email".to_owned()));
}

#[test]
fn authorization_url_appends_configured_and_request_scopes() {
    let provider = naver(ProviderOptions {
        scope: vec!["name".to_owned()],
        ..provider_options()
    });

    let url = provider
        .create_authorization_url(NaverAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/naver/callback".to_owned(),
            scopes: vec!["birthday".to_owned()],
            ..NaverAuthorizationUrlRequest::default()
        })
        .expect("authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("profile email name birthday".to_owned())
    );
}

#[test]
fn authorization_url_can_disable_default_scope() {
    let provider = naver(ProviderOptions {
        disable_default_scope: true,
        scope: vec!["name".to_owned()],
        ..provider_options()
    });

    let url = provider
        .create_authorization_url(NaverAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/naver/callback".to_owned(),
            scopes: vec!["birthday".to_owned()],
            ..NaverAuthorizationUrlRequest::default()
        })
        .expect("authorization URL should build");

    assert_eq!(query_value(&url, "scope"), Some("name birthday".to_owned()));
}

#[test]
fn token_requests_use_naver_token_endpoint_and_post_auth() {
    let provider = naver(provider_options());

    let code_request = provider
        .authorization_code_request(
            "code-1",
            Some("verifier-1"),
            "https://app.example.com/auth/naver/callback",
        )
        .expect("authorization code request should build");

    assert_eq!(provider.token_endpoint(), NAVER_TOKEN_ENDPOINT);
    assert_eq!(code_request.header("authorization"), None);
    assert_eq!(
        code_request.form_value("grant_type"),
        Some("authorization_code")
    );
    assert_eq!(code_request.form_value("code"), Some("code-1"));
    assert_eq!(code_request.form_value("code_verifier"), Some("verifier-1"));
    assert_eq!(code_request.form_value("client_id"), Some("naver-client"));
    assert_eq!(
        code_request.form_value("client_secret"),
        Some("naver-secret")
    );
    assert_eq!(code_request.form_value("client_key"), Some("naver-key"));

    let refresh_request = provider
        .refresh_access_token_request("refresh-1")
        .expect("refresh token request should build");

    assert_eq!(refresh_request.header("authorization"), None);
    assert_eq!(
        refresh_request.form_value("grant_type"),
        Some("refresh_token")
    );
    assert_eq!(
        refresh_request.form_value("refresh_token"),
        Some("refresh-1")
    );
    assert_eq!(
        refresh_request.form_value("client_id"),
        Some("naver-client")
    );
    assert_eq!(
        refresh_request.form_value("client_secret"),
        Some("naver-secret")
    );
    assert_eq!(refresh_request.form_value("client_key"), Some("naver-key"));
}

#[test]
fn maps_naver_profile_to_oauth_user_info() {
    let mapped = NaverProvider::map_profile(success_profile(NaverProfileResponse {
        id: "naver-user-1".to_owned(),
        nickname: "Ada".to_owned(),
        name: "Ada Lovelace".to_owned(),
        email: "ada@example.com".to_owned(),
        profile_image: "https://img.example.com/ada.jpg".to_owned(),
        ..NaverProfileResponse::default()
    }))
    .expect("successful profile should map");

    assert_eq!(mapped.user.id, "naver-user-1");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert!(!mapped.user.email_verified);
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://img.example.com/ada.jpg")
    );
}

#[test]
fn maps_naver_profile_name_fallbacks() {
    let nickname_mapped = NaverProvider::map_profile(success_profile(NaverProfileResponse {
        id: "naver-user-1".to_owned(),
        nickname: "Ada".to_owned(),
        name: String::new(),
        ..NaverProfileResponse::default()
    }))
    .expect("successful profile should map");
    assert_eq!(nickname_mapped.user.name.as_deref(), Some("Ada"));

    let empty_mapped = NaverProvider::map_profile(success_profile(NaverProfileResponse {
        id: "naver-user-1".to_owned(),
        nickname: String::new(),
        name: String::new(),
        ..NaverProfileResponse::default()
    }))
    .expect("successful profile should map");
    assert_eq!(empty_mapped.user.name.as_deref(), Some(""));
}

#[test]
fn invalid_naver_result_code_maps_to_none() {
    let mapped = NaverProvider::map_profile(NaverProfile {
        resultcode: "024".to_owned(),
        message: "Authentication failed".to_owned(),
        response: Some(NaverProfileResponse {
            id: "naver-user-1".to_owned(),
            ..NaverProfileResponse::default()
        }),
    });

    assert!(mapped.is_none());
}

#[tokio::test]
async fn naver_get_user_info_returns_none_when_access_token_is_missing() {
    let provider = NaverProvider::default();

    let info = provider
        .get_user_info(&OAuth2Tokens::default())
        .await
        .expect("missing access token should not error");

    assert!(info.is_none());
}

fn success_profile(response: NaverProfileResponse) -> NaverProfile {
    NaverProfile {
        resultcode: "00".to_owned(),
        message: "success".to_owned(),
        response: Some(response),
    }
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("naver-client")),
        client_secret: Some("naver-secret".to_owned()),
        client_key: Some("naver-key".to_owned()),
        ..ProviderOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
