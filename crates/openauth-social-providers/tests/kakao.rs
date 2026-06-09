#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, ProviderOptions};
use openauth_social_providers::advanced::kakao::{
    kakao, KakaoAccount, KakaoAccountProfile, KakaoAuthorizationUrlRequest, KakaoProfile,
    KakaoProvider, KakaoProviderOptions, KAKAO_AUTHORIZATION_ENDPOINT, KAKAO_ID, KAKAO_NAME,
    KAKAO_TOKEN_ENDPOINT,
};

#[test]
fn kakao_provider_exposes_upstream_metadata() {
    let provider = KakaoProvider::new(KakaoProviderOptions {
        oauth: provider_options(),
    });

    assert_eq!(provider.id(), KAKAO_ID);
    assert_eq!(provider.name(), KAKAO_NAME);
}

#[test]
fn authorization_url_includes_upstream_default_scopes() {
    let provider = kakao(provider_options());

    let url = provider
        .create_authorization_url(KakaoAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/kakao/callback".to_owned(),
            scopes: Vec::new(),
            ..KakaoAuthorizationUrlRequest::default()
        })
        .expect("authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some(KAKAO_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("kakao-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/kakao/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("account_email profile_image profile_nickname".to_owned())
    );
}

#[test]
fn authorization_url_appends_configured_and_request_scopes() {
    let provider = kakao(ProviderOptions {
        scope: vec!["name".to_owned()],
        ..provider_options()
    });

    let url = provider
        .create_authorization_url(KakaoAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/kakao/callback".to_owned(),
            scopes: vec!["birthday".to_owned()],
            ..KakaoAuthorizationUrlRequest::default()
        })
        .expect("authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("account_email profile_image profile_nickname name birthday".to_owned())
    );
}

#[test]
fn authorization_url_can_disable_default_scope() {
    let provider = kakao(ProviderOptions {
        disable_default_scope: true,
        scope: vec!["name".to_owned()],
        ..provider_options()
    });

    let url = provider
        .create_authorization_url(KakaoAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/kakao/callback".to_owned(),
            scopes: vec!["birthday".to_owned()],
            ..KakaoAuthorizationUrlRequest::default()
        })
        .expect("authorization URL should build");

    assert_eq!(query_value(&url, "scope"), Some("name birthday".to_owned()));
}

#[test]
fn token_requests_use_kakao_token_endpoint_and_post_auth() {
    let provider = kakao(provider_options());

    let code_request = provider
        .authorization_code_request(
            "code-1",
            Some("01234567890123456789012345678901234567890123456789"),
            "https://app.example.com/auth/kakao/callback",
        )
        .expect("authorization code request should build");

    assert_eq!(provider.token_endpoint(), KAKAO_TOKEN_ENDPOINT);
    assert_eq!(code_request.header("authorization"), None);
    assert_eq!(
        code_request.form_value("grant_type"),
        Some("authorization_code")
    );
    assert_eq!(code_request.form_value("code"), Some("code-1"));
    assert_eq!(
        code_request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(code_request.form_value("client_id"), Some("kakao-client"));
    assert_eq!(
        code_request.form_value("client_secret"),
        Some("kakao-secret")
    );
    assert_eq!(
        code_request.form_value("client_key"),
        Some("kakao-admin-key")
    );

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
        Some("kakao-client")
    );
    assert_eq!(
        refresh_request.form_value("client_secret"),
        Some("kakao-secret")
    );
}

#[test]
fn maps_kakao_profile_to_oauth_user_info() {
    let profile = KakaoProfile {
        id: 123456789,
        kakao_account: KakaoAccount {
            profile: Some(KakaoAccountProfile {
                nickname: Some("Ada".to_owned()),
                thumbnail_image_url: Some("https://img.example.com/thumb.jpg".to_owned()),
                profile_image_url: Some("https://img.example.com/profile.jpg".to_owned()),
                ..KakaoAccountProfile::default()
            }),
            name: Some("Ada Lovelace".to_owned()),
            email: Some("ada@example.com".to_owned()),
            is_email_valid: Some(true),
            is_email_verified: Some(true),
            ..KakaoAccount::default()
        },
        ..KakaoProfile::default()
    };

    let mapped = KakaoProvider::map_profile(profile);

    assert_eq!(mapped.user.id, "123456789");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert!(mapped.user.email_verified);
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://img.example.com/profile.jpg")
    );
}

#[test]
fn maps_kakao_profile_without_optional_account_fields() {
    let mapped = KakaoProvider::map_profile(KakaoProfile {
        id: 123456789,
        kakao_account: KakaoAccount::default(),
        ..KakaoProfile::default()
    });

    assert_eq!(mapped.user.id, "123456789");
    assert_eq!(mapped.user.name.as_deref(), Some(""));
    assert_eq!(mapped.user.email, None);
    assert_eq!(mapped.user.image, None);
    assert!(!mapped.user.email_verified);
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("kakao-client")),
        client_secret: Some("kakao-secret".to_owned()),
        client_key: Some("kakao-admin-key".to_owned()),
        ..ProviderOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
