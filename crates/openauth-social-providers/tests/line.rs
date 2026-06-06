#![allow(
    clippy::expect_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::line::{
    line, LineAuthorizationUrlRequest, LineIdTokenPayload, LineOptions, LineProvider, LineUserInfo,
};
use serde_json::json;

#[test]
fn line_provider_exposes_upstream_metadata() {
    let provider = line(LineOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("line-client")),
            client_secret: Some("line-secret".to_owned()),
            ..ProviderOptions::default()
        },
    });

    assert_eq!(provider.id(), "line");
    assert_eq!(provider.name(), "LINE");
}

#[test]
fn authorization_url_uses_line_defaults_redirect_override_login_hint_and_pkce(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = LineProvider::new(LineOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("line-client")),
            client_secret: Some("line-secret".to_owned()),
            redirect_uri: Some("https://auth.example.com/line/callback".to_owned()),
            scope: vec!["friends".to_owned()],
            ..ProviderOptions::default()
        },
    });

    let url = provider.create_authorization_url(LineAuthorizationUrlRequest {
        state: "state-123".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["groups".to_owned()],
        login_hint: Some("ada@example.com".to_owned()),
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://access.line.me/oauth2/v2.1/authorize")
    );
    assert_eq!(
        query_value(&url, "client_id"),
        Some("line-client".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid profile email friends groups".to_owned())
    );
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/line/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "login_hint"),
        Some("ada@example.com".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
    Ok(())
}

#[test]
fn authorization_url_can_disable_default_scope() -> Result<(), Box<dyn std::error::Error>> {
    let provider = LineProvider::new(LineOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("line-client")),
            client_secret: Some("line-secret".to_owned()),
            disable_default_scope: true,
            scope: vec!["profile".to_owned()],
            ..ProviderOptions::default()
        },
    });

    let url = provider.create_authorization_url(LineAuthorizationUrlRequest {
        state: "state".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scopes: vec!["email".to_owned()],
        ..LineAuthorizationUrlRequest::default()
    })?;

    assert_eq!(query_value(&url, "scope"), Some("profile email".to_owned()));
    Ok(())
}

#[test]
fn id_token_payload_maps_to_oauth_user_info_with_unverified_email() {
    let profile = LineIdTokenPayload {
        iss: "https://access.line.me".to_owned(),
        sub: "line-subject".to_owned(),
        aud: "line-client".to_owned(),
        exp: 4_102_444_800,
        iat: 1_704_067_200,
        name: Some("Ada Lovelace".to_owned()),
        picture: Some("https://profile.line-scdn.net/ada".to_owned()),
        email: Some("ada@example.com".to_owned()),
        amr: vec!["pwd".to_owned()],
        nonce: Some("nonce".to_owned()),
        extra: Default::default(),
    };

    let mapped = LineProvider::map_id_token_payload(profile);

    assert_eq!(mapped.user.id, "line-subject");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://profile.line-scdn.net/ada")
    );
    assert!(!mapped.user.email_verified);
}

#[test]
fn userinfo_payload_maps_to_oauth_user_info_with_unverified_email() {
    let profile = LineUserInfo {
        sub: "line-subject".to_owned(),
        name: Some("Ada Lovelace".to_owned()),
        picture: Some("https://profile.line-scdn.net/ada".to_owned()),
        email: Some("ada@example.com".to_owned()),
        extra: Default::default(),
    };

    let mapped = LineProvider::map_user_info(profile);

    assert_eq!(mapped.user.id, "line-subject");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://profile.line-scdn.net/ada")
    );
    assert!(!mapped.user.email_verified);
}

#[tokio::test]
async fn get_user_info_returns_none_when_id_token_and_access_token_are_missing() {
    let provider = LineProvider::default();

    let info = provider
        .get_user_info(&OAuth2Tokens::default())
        .await
        .expect("missing tokens should not error");

    assert!(info.is_none());
}

#[tokio::test]
async fn get_user_info_ignores_invalid_id_token_and_falls_back_without_panic() {
    let provider = LineProvider::default();
    let tokens = OAuth2Tokens {
        id_token: Some("not-a-jwt".to_owned()),
        ..OAuth2Tokens::default()
    };

    let info = provider
        .get_user_info(&tokens)
        .await
        .expect("invalid id token should not error");

    assert!(info.is_none());
}

#[tokio::test]
async fn decoded_id_token_is_preferred_for_user_info_mapping() {
    let provider = LineProvider::default();
    let tokens = OAuth2Tokens {
        id_token: Some(unsigned_jwt(json!({
            "iss": "https://access.line.me",
            "sub": "line-subject",
            "aud": "line-client",
            "exp": 4_102_444_800i64,
            "iat": 1_704_067_200i64,
            "name": "Ada Lovelace",
            "picture": "https://profile.line-scdn.net/ada",
            "email": "ada@example.com",
            "custom": "kept"
        }))),
        ..OAuth2Tokens::default()
    };

    let info = provider
        .get_user_info(&tokens)
        .await
        .expect("id token mapping should not error")
        .expect("id token should produce profile");

    assert_eq!(info.user.id, "line-subject");
    assert_eq!(info.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
    assert!(!info.user.email_verified);
}

#[test]
fn verify_id_token_payload_accepts_matching_audience_and_nonce() {
    let provider = provider_with_client_id("line-client", false);
    let payload = verify_payload("line-client", Some("nonce"));

    assert!(provider.validate_id_token_payload(&payload, Some("nonce")));
}

#[test]
fn verify_id_token_payload_rejects_missing_expected_nonce() {
    let provider = provider_with_client_id("line-client", false);

    assert!(
        !provider.validate_id_token_payload(&verify_payload("line-client", None), Some("nonce"))
    );
}

#[test]
fn verify_id_token_payload_accepts_missing_nonce_when_not_expected() {
    let provider = provider_with_client_id("line-client", false);

    assert!(provider.validate_id_token_payload(&verify_payload("line-client", None), None));
}

#[test]
fn verify_id_token_payload_rejects_wrong_audience_wrong_nonce_and_disabled_sign_in() {
    let provider = provider_with_client_id("line-client", false);

    assert!(!provider.validate_id_token_payload(
        &verify_payload("other-client", Some("nonce")),
        Some("nonce")
    ));
    assert!(!provider
        .validate_id_token_payload(&verify_payload("line-client", Some("nonce")), Some("other")));

    let disabled = provider_with_client_id("line-client", true);
    assert!(!disabled
        .validate_id_token_payload(&verify_payload("line-client", Some("nonce")), Some("nonce")));
}

fn provider_with_client_id(client_id: &str, disable_id_token_sign_in: bool) -> LineProvider {
    LineProvider::new(LineOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from(client_id)),
            client_secret: Some("line-secret".to_owned()),
            disable_id_token_sign_in,
            ..ProviderOptions::default()
        },
    })
}

fn verify_payload(audience: &str, nonce: Option<&str>) -> LineIdTokenPayload {
    LineIdTokenPayload {
        iss: "https://access.line.me".to_owned(),
        sub: "line-subject".to_owned(),
        aud: audience.to_owned(),
        exp: 4_102_444_800,
        iat: 1_704_067_200,
        name: None,
        picture: None,
        email: None,
        amr: Vec::new(),
        nonce: nonce.map(str::to_owned),
        extra: Default::default(),
    }
}

fn unsigned_jwt(payload: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
    format!("{header}.{payload}.")
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
