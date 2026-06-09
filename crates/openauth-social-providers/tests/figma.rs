use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthError, ProviderOptions};
use openauth_social_providers::advanced::figma::{
    figma, FigmaAuthorizationUrlRequest, FigmaProfile, FIGMA_AUTHORIZATION_ENDPOINT, FIGMA_ID,
    FIGMA_NAME, FIGMA_TOKEN_ENDPOINT,
};

#[test]
fn figma_provider_exposes_upstream_metadata() {
    let provider = figma(provider_options());

    assert_eq!((provider.id(), provider.name()), (FIGMA_ID, FIGMA_NAME));
}

#[test]
fn figma_authorization_url_uses_default_scope_and_pkce() -> Result<(), OAuthError> {
    let provider = figma(provider_options());
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
    let provider = figma(ProviderOptions::default());

    let error = provider
        .create_authorization_url(FigmaAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            scopes: Vec::new(),
        })
        .err()
        .map(|error| error.to_string());

    assert_eq!(
        error.as_deref(),
        Some("missing OAuth provider option `client_id`")
    );
}

#[test]
fn figma_authorization_url_requires_code_verifier() {
    let provider = figma(provider_options());

    let error = provider
        .create_authorization_url(FigmaAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            code_verifier: None,
            scopes: Vec::new(),
        })
        .err()
        .map(|error| error.to_string());

    assert_eq!(
        error.as_deref(),
        Some("missing OAuth provider option `code_verifier`")
    );
}

#[test]
fn figma_authorization_code_request_requires_code_verifier() {
    let provider = figma(provider_options());

    let error = provider
        .authorization_code_request(
            "code-1",
            None::<String>,
            "https://app.example.com/auth/callback",
        )
        .err()
        .map(|error| error.to_string());

    assert_eq!(
        error.as_deref(),
        Some("missing OAuth provider option `code_verifier`")
    );
}

#[test]
fn figma_token_requests_use_basic_auth() -> Result<(), OAuthError> {
    let provider = figma(provider_options());
    let request = provider.authorization_code_request(
        "code-1",
        Some("01234567890123456789012345678901234567890123456789"),
        "https://app.example.com/auth/callback",
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
    let provider = figma(provider_options());
    let request = provider.refresh_access_token_request("refresh-1")?;

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
    let provider = figma(provider_options());

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("figma-client")),
        client_secret: Some("figma-secret".to_owned()),
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
