#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::advanced::paybin::{
    paybin, PaybinAuthorizationUrlRequest, PaybinOptions, PAYBIN_AUTHORIZATION_ENDPOINT,
    PAYBIN_DEFAULT_ISSUER, PAYBIN_ID, PAYBIN_NAME, PAYBIN_TOKEN_ENDPOINT,
};
use serde_json::json;

#[test]
fn paybin_provider_exposes_upstream_metadata() {
    let provider = paybin(paybin_options());
    let provider_contract: &dyn OAuthProviderContract = &provider;

    assert_eq!(
        (provider_contract.id(), provider_contract.name()),
        (PAYBIN_ID, PAYBIN_NAME)
    );
}

#[test]
fn paybin_authorization_url_uses_default_issuer_scopes_pkce_prompt_and_login_hint(
) -> Result<(), OAuthError> {
    let mut options = paybin_options();
    options.oauth.prompt = Some("login".to_owned());
    options.oauth.scope = vec!["transactions".to_owned()];
    let provider = paybin(options);

    let url = provider.create_authorization_url(PaybinAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/paybin".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["wallets".to_owned()],
        login_hint: Some("ada@example.com".to_owned()),
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some(PAYBIN_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("paybin-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/callback/paybin".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid email profile transactions wallets".to_owned())
    );
    assert_eq!(query_value(&url, "prompt"), Some("login".to_owned()));
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
fn paybin_custom_issuer_derives_endpoints() {
    let provider = paybin(PaybinOptions {
        issuer: Some("https://login.example.com".to_owned()),
        ..paybin_options()
    });

    assert_eq!(
        provider.authorization_endpoint(),
        "https://login.example.com/oauth2/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://login.example.com/oauth2/token"
    );
}

#[test]
fn paybin_authorization_url_can_disable_default_scopes() -> Result<(), OAuthError> {
    let mut options = paybin_options();
    options.oauth.disable_default_scope = true;
    options.oauth.scope = vec!["transactions".to_owned()];
    let provider = paybin(options);

    let url = provider.create_authorization_url(PaybinAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/paybin".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["wallets".to_owned()],
        login_hint: None,
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("transactions wallets".to_owned())
    );
    Ok(())
}

#[test]
fn paybin_authorization_url_requires_client_id_secret_and_code_verifier() {
    let mut missing_client_id = paybin_options();
    missing_client_id.oauth.client_id = None;
    assert!(matches!(
        paybin(missing_client_id)
            .create_authorization_url(auth_request())
            .unwrap_err(),
        OAuthError::MissingOption("client_id")
    ));

    let mut missing_secret = paybin_options();
    missing_secret.oauth.client_secret = None;
    assert!(matches!(
        paybin(missing_secret)
            .create_authorization_url(auth_request())
            .unwrap_err(),
        OAuthError::MissingOption("client_secret")
    ));

    let mut missing_verifier = auth_request();
    missing_verifier.code_verifier = None;
    assert!(matches!(
        paybin(paybin_options())
            .create_authorization_url(missing_verifier)
            .unwrap_err(),
        OAuthError::MissingOption("code_verifier")
    ));
}

#[test]
fn paybin_authorization_code_request_requires_code_verifier() {
    let provider = paybin(paybin_options());

    let error = provider
        .authorization_code_request(
            "code-1",
            None::<String>,
            "https://app.example.com/auth/callback/paybin",
        )
        .unwrap_err();

    assert!(matches!(error, OAuthError::MissingOption("code_verifier")));
}

#[test]
fn paybin_authorization_code_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = paybin(paybin_options());
    let request = provider.authorization_code_request(
        "code-1",
        Some("01234567890123456789012345678901234567890123456789"),
        "https://app.example.com/auth/callback/paybin",
    )?;

    assert_eq!(provider.token_endpoint(), PAYBIN_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback/paybin")
    );
    assert_eq!(request.form_value("client_id"), Some("paybin-client"));
    assert_eq!(request.form_value("client_secret"), Some("paybin-secret"));
    Ok(())
}

#[test]
fn paybin_refresh_token_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = paybin(paybin_options());
    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_id"), Some("paybin-client"));
    assert_eq!(request.form_value("client_secret"), Some("paybin-secret"));
    Ok(())
}

#[tokio::test]
async fn paybin_get_user_info_maps_decoded_id_token_profile() -> Result<(), OAuthError> {
    let provider = paybin(paybin_options());
    let id_token = unsigned_jwt(json!({
        "sub": "user-123",
        "email": "ada@example.com",
        "email_verified": true,
        "preferred_username": "ada",
        "picture": "https://example.com/ada.png",
        "given_name": "Ada",
        "family_name": "Lovelace",
        "custom_claim": "custom-value"
    }));

    let info = provider
        .get_user_info(&OAuth2Tokens {
            id_token: Some(id_token),
            ..OAuth2Tokens::default()
        })
        .await?
        .expect("profile should exist");

    assert_eq!(info.user.id, "user-123");
    assert_eq!(info.user.name.as_deref(), Some("ada"));
    assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        info.user.image.as_deref(),
        Some("https://example.com/ada.png")
    );
    assert!(info.user.email_verified);
    assert_eq!(info.data.extra["custom_claim"], "custom-value");
    Ok(())
}

#[tokio::test]
async fn paybin_get_user_info_returns_none_without_id_token() -> Result<(), OAuthError> {
    let provider = paybin(paybin_options());

    let info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert!(info.is_none());
    Ok(())
}

fn paybin_options() -> PaybinOptions {
    PaybinOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("paybin-client")),
            client_secret: Some("paybin-secret".to_owned()),
            ..ProviderOptions::default()
        },
        issuer: None,
    }
}

fn auth_request() -> PaybinAuthorizationUrlRequest {
    PaybinAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/paybin".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: Vec::new(),
        login_hint: None,
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn unsigned_jwt(claims: serde_json::Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

#[test]
fn paybin_default_issuer_is_upstream_default() {
    assert_eq!(PAYBIN_DEFAULT_ISSUER, "https://idp.paybin.io");
}
