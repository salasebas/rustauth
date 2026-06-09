#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthError, ProviderOptions};
use openauth_social_providers::advanced::railway::{
    railway, RailwayAuthorizationUrlRequest, RailwayProfile, RAILWAY_AUTHORIZATION_ENDPOINT,
    RAILWAY_ID, RAILWAY_NAME, RAILWAY_TOKEN_ENDPOINT,
};

#[test]
fn railway_provider_exposes_upstream_metadata() {
    let provider = railway(provider_options());

    assert_eq!((provider.id(), provider.name()), (RAILWAY_ID, RAILWAY_NAME));
}

#[test]
fn railway_authorization_url_uses_default_scopes_and_pkce() -> Result<(), OAuthError> {
    let provider = railway(provider_options());
    let url = provider.create_authorization_url(RailwayAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/railway".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["offline_access".to_owned()],
    })?;

    assert!(url.as_str().starts_with(RAILWAY_AUTHORIZATION_ENDPOINT));
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid email profile offline_access".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert_eq!(
        query_value(&url, "client_id"),
        Some("railway-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    Ok(())
}

#[test]
fn railway_authorization_url_appends_provider_scopes_before_request_scopes(
) -> Result<(), OAuthError> {
    let provider = railway(ProviderOptions {
        client_id: Some(ClientId::from("railway-client")),
        client_secret: Some("railway-secret".to_owned()),
        scope: vec!["team:read".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider.create_authorization_url(RailwayAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/railway".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["offline_access".to_owned()],
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("openid email profile team:read offline_access".to_owned())
    );
    Ok(())
}

#[test]
fn railway_authorization_url_requires_client_id_and_secret() {
    let provider = railway(ProviderOptions::default());

    let error = provider
        .create_authorization_url(RailwayAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback/railway".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            scopes: Vec::new(),
        })
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "missing OAuth provider option `client_id`"
    );
}

#[test]
fn railway_authorization_url_allows_missing_code_verifier() {
    let provider = railway(provider_options());

    let url = provider
        .create_authorization_url(RailwayAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback/railway".to_owned(),
            code_verifier: None,
            scopes: Vec::new(),
        })
        .expect("railway authorization URL should build without PKCE");

    assert!(url
        .query_pairs()
        .all(|(key, _)| key != "code_challenge" && key != "code_challenge_method"));
}

#[test]
fn railway_token_requests_use_basic_auth() -> Result<(), OAuthError> {
    let provider = railway(provider_options());
    let request = provider.authorization_code_request(
        "code-1",
        Some("01234567890123456789012345678901234567890123456789"),
        "https://app.example.com/auth/callback/railway",
    )?;

    assert_eq!(
        request.header("authorization"),
        basic_auth_header().as_deref()
    );
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback/railway")
    );
    Ok(())
}

#[test]
fn railway_refresh_requests_use_basic_auth() -> Result<(), OAuthError> {
    let provider = railway(provider_options());
    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(provider.token_endpoint(), RAILWAY_TOKEN_ENDPOINT);
    assert_eq!(
        request.header("authorization"),
        basic_auth_header().as_deref()
    );
    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
    Ok(())
}

#[test]
fn railway_profile_maps_to_unverified_user_info() {
    let profile = RailwayProfile {
        sub: "user_railway_123".to_owned(),
        email: "railway@test.com".to_owned(),
        name: "Railway User".to_owned(),
        picture: "https://avatars.example.com/railway.png".to_owned(),
    };

    let user = profile.to_user_info();

    assert!(!user.email_verified);
    assert_eq!(user.id, "user_railway_123");
    assert_eq!(user.name.as_deref(), Some("Railway User"));
    assert_eq!(user.email.as_deref(), Some("railway@test.com"));
    assert_eq!(
        user.image.as_deref(),
        Some("https://avatars.example.com/railway.png")
    );
}

#[tokio::test]
async fn railway_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = railway(provider_options());

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("railway-client")),
        client_secret: Some("railway-secret".to_owned()),
        ..ProviderOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn basic_auth_header() -> Option<String> {
    Some("Basic cmFpbHdheS1jbGllbnQ6cmFpbHdheS1zZWNyZXQ=".to_owned())
}
