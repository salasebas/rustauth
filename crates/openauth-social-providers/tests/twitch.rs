#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::twitch::{
    twitch, TwitchAuthorizationUrlRequest, TwitchOptions, TWITCH_AUTHORIZATION_ENDPOINT,
    TWITCH_DEFAULT_CLAIMS, TWITCH_DEFAULT_SCOPES, TWITCH_ID, TWITCH_NAME, TWITCH_TOKEN_ENDPOINT,
};
use serde_json::json;

#[test]
fn twitch_provider_exposes_upstream_metadata() {
    let provider = twitch(twitch_options());
    let provider_contract: &dyn OAuthProviderContract = &provider;

    assert_eq!(
        (provider_contract.id(), provider_contract.name()),
        (TWITCH_ID, TWITCH_NAME)
    );
}

#[test]
fn twitch_authorization_url_uses_upstream_default_scopes_and_claims() -> Result<(), OAuthError> {
    let provider = twitch(TwitchOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("twitch-client")),
            scope: vec!["channel:read:subscriptions".to_owned()],
            ..ProviderOptions::default()
        },
        ..TwitchOptions::default()
    });

    let url = provider.create_authorization_url(TwitchAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/twitch".to_owned(),
        scopes: vec!["bits:read".to_owned()],
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some(TWITCH_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("twitch-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/callback/twitch".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("user:read:email openid channel:read:subscriptions bits:read".to_owned())
    );
    assert_eq!(TWITCH_DEFAULT_SCOPES, &["user:read:email", "openid"]);
    assert_eq!(
        TWITCH_DEFAULT_CLAIMS,
        &["email", "email_verified", "preferred_username", "picture"]
    );
    assert_claims(
        &url,
        &["email", "email_verified", "preferred_username", "picture"],
    );
    Ok(())
}

#[test]
fn twitch_authorization_url_can_disable_default_scope() -> Result<(), OAuthError> {
    let provider = twitch(TwitchOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("twitch-client")),
            scope: vec!["channel:read:subscriptions".to_owned()],
            disable_default_scope: true,
            ..ProviderOptions::default()
        },
        ..TwitchOptions::default()
    });

    let url = provider.create_authorization_url(TwitchAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/twitch".to_owned(),
        scopes: vec!["bits:read".to_owned()],
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("channel:read:subscriptions bits:read".to_owned())
    );
    Ok(())
}

#[test]
fn twitch_authorization_url_allows_claim_override() -> Result<(), OAuthError> {
    let provider = twitch(TwitchOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("twitch-client")),
            ..ProviderOptions::default()
        },
        claims: vec!["preferred_username".to_owned()],
    });

    let url = provider.create_authorization_url(TwitchAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/twitch".to_owned(),
        scopes: Vec::new(),
    })?;

    assert_claims(&url, &["preferred_username"]);
    Ok(())
}

#[test]
fn twitch_authorization_code_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = twitch(twitch_options());
    let request =
        provider.authorization_code_request("code-1", "https://app.example.com/auth/callback")?;

    assert_eq!(provider.token_endpoint(), TWITCH_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("client_id"), Some("twitch-client"));
    assert_eq!(request.form_value("client_secret"), Some("twitch-secret"));
    Ok(())
}

#[test]
fn twitch_refresh_token_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = twitch(twitch_options());
    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_id"), Some("twitch-client"));
    assert_eq!(request.form_value("client_secret"), Some("twitch-secret"));
    Ok(())
}

#[tokio::test]
async fn twitch_get_user_info_maps_decoded_id_token_profile() -> Result<(), OAuthError> {
    let provider = twitch(twitch_options());
    let id_token = unsigned_jwt(json!({
        "sub": "twitch-user-1",
        "preferred_username": "ada_streams",
        "email": "ada@example.com",
        "email_verified": true,
        "picture": "https://static-cdn.jtvnw.net/jtv_user_pictures/ada-profile_image.png",
        "custom_claim": "custom-value"
    }));

    let info = provider
        .get_user_info(&OAuth2Tokens {
            id_token: Some(id_token),
            ..OAuth2Tokens::default()
        })
        .await?
        .expect("profile should exist");

    assert_eq!(info.user.id, "twitch-user-1");
    assert_eq!(info.user.name.as_deref(), Some("ada_streams"));
    assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        info.user.image.as_deref(),
        Some("https://static-cdn.jtvnw.net/jtv_user_pictures/ada-profile_image.png")
    );
    assert!(info.user.email_verified);
    assert_eq!(info.data.extra["custom_claim"], "custom-value");
    Ok(())
}

#[tokio::test]
async fn twitch_get_user_info_returns_none_without_id_token() -> Result<(), OAuthError> {
    let provider = twitch(twitch_options());

    let info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert!(info.is_none());
    Ok(())
}

fn twitch_options() -> TwitchOptions {
    TwitchOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("twitch-client")),
            client_secret: Some("twitch-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..TwitchOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn assert_claims(url: &url::Url, expected: &[&str]) {
    let claims = query_value(url, "claims").expect("claims query parameter should exist");
    let value: serde_json::Value =
        serde_json::from_str(&claims).expect("claims should be valid JSON");
    let id_token = value
        .get("id_token")
        .and_then(serde_json::Value::as_object)
        .expect("claims should contain id_token object");

    for claim in expected {
        assert!(id_token.contains_key(*claim), "missing claim {claim}");
    }
}

fn unsigned_jwt(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}
