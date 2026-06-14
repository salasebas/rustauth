#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use rustauth_oauth::oauth2::{
    create_authorization_code_request, create_refresh_access_token_request,
    AuthorizationCodeRequest, ClientAuthentication, ClientId, ClientSecret, OAuth2Tokens,
    OAuthError, ProviderOptions, RefreshAccessTokenRequest,
};
use rustauth_social_providers::advanced::figma::{
    figma, FigmaAuthorizationUrlRequest, FigmaProfile, FIGMA_AUTHORIZATION_ENDPOINT, FIGMA_ID,
    FIGMA_NAME, FIGMA_TOKEN_ENDPOINT,
};

#[test]
fn figma_provider_exposes_upstream_metadata() {
    let provider = figma(provider_options()).expect("provider should construct");

    assert_eq!((provider.id(), provider.name()), (FIGMA_ID, FIGMA_NAME));
}

#[test]
fn figma_authorization_url_uses_default_scope_and_pkce() -> Result<(), OAuthError> {
    let provider = figma(provider_options()).expect("provider should construct");
    let url = provider.create_authorization_url(FigmaAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["file_read".to_owned()],
    })?;

    assert!(url.as_str().starts_with(FIGMA_AUTHORIZATION_ENDPOINT));
    assert_eq!(
        query_value(&url, "scope"),
        Some("current_user:read file_read".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert_eq!(
        query_value(&url, "client_id"),
        Some("figma-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    Ok(())
}

#[test]
fn figma_authorization_url_requires_client_id_and_secret() {
    assert!(matches!(
        figma(ProviderOptions::default()),
        Err(OAuthError::MissingOption("client_id"))
    ));

    assert!(matches!(
        figma(ProviderOptions {
            client_id: Some(ClientId::from("figma-client")),
            ..ProviderOptions::default()
        }),
        Err(OAuthError::MissingOption("client_secret"))
    ));
}

#[test]
fn figma_authorization_url_requires_code_verifier() {
    let provider = figma(provider_options()).expect("provider should construct");

    let error = provider
        .create_authorization_url(FigmaAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            code_verifier: None,
            scopes: Vec::new(),
        })
        .err()
        .map(|error| error.to_string())
        .expect("error should be present");

    assert_eq!(error, "missing OAuth provider option `code_verifier`");
}

#[tokio::test]
async fn figma_validate_authorization_code_requires_code_verifier() {
    let provider = figma(provider_options()).expect("provider should construct");

    let error = provider
        .validate_authorization_code(
            "code-1",
            None::<String>,
            "https://app.example.com/auth/callback",
        )
        .await
        .unwrap_err()
        .to_string();

    assert_eq!(error, "missing OAuth provider option `code_verifier`");
}

#[test]
fn figma_token_requests_use_basic_auth() -> Result<(), OAuthError> {
    let provider = figma(provider_options()).expect("provider should construct");
    let request = create_authorization_code_request(
        AuthorizationCodeRequest::try_new(
            "code-1",
            "https://app.example.com/auth/callback",
            provider.options(),
        )?
        .authentication(ClientAuthentication::Basic)
        .code_verifier("01234567890123456789012345678901234567890123456789"),
    )?;

    assert_eq!(
        request.header("authorization"),
        basic_auth_header().as_deref()
    );
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    Ok(())
}

#[test]
fn figma_refresh_requests_use_basic_auth() -> Result<(), OAuthError> {
    let provider = figma(provider_options()).expect("provider should construct");
    let request = create_refresh_access_token_request(
        RefreshAccessTokenRequest::try_new("refresh-1", provider.options())?
            .authentication(ClientAuthentication::Basic),
    )?;

    assert_eq!(provider.token_endpoint(), FIGMA_TOKEN_ENDPOINT);
    assert_eq!(
        request.header("authorization"),
        basic_auth_header().as_deref()
    );
    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    Ok(())
}

#[test]
fn figma_profile_maps_to_unverified_user_info() {
    let profile = FigmaProfile {
        id: "figma-user-1".to_owned(),
        email: "ada@example.com".to_owned(),
        handle: "Ada".to_owned(),
        img_url: "https://cdn.example.com/ada.png".to_owned(),
    };

    let user = profile.to_user_info();

    assert!(!user.email_verified);
    assert_eq!(user.id, "figma-user-1");
    assert_eq!(user.name.as_deref(), Some("Ada"));
    assert_eq!(user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        user.image.as_deref(),
        Some("https://cdn.example.com/ada.png")
    );
}

#[tokio::test]
async fn figma_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = figma(provider_options()).expect("provider should construct");

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("figma-client")),
        client_secret: Some(ClientSecret::new("figma-secret").expect("valid client secret")),
        ..ProviderOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn basic_auth_header() -> Option<String> {
    Some("Basic ZmlnbWEtY2xpZW50OmZpZ21hLXNlY3JldA==".to_owned())
}
