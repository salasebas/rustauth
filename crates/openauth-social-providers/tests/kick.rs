use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::kick::{
    kick, KickAuthorizationUrlRequest, KickProfile, KickProvider, KICK_AUTHORIZATION_ENDPOINT,
    KICK_ID, KICK_NAME, KICK_TOKEN_ENDPOINT,
};

#[test]
fn kick_provider_exposes_upstream_metadata() {
    let provider = kick(provider_options());

    assert_eq!(provider.id(), KICK_ID);
    assert_eq!(provider.name(), KICK_NAME);
}

#[test]
fn kick_authorization_url_uses_default_configured_and_request_scopes() -> Result<(), OAuthError> {
    let provider = kick(ProviderOptions {
        client_id: Some(ClientId::from("kick-client")),
        scope: vec!["channel:read".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider.create_authorization_url(KickAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["chat:write".to_owned()],
    })?;

    assert!(url.as_str().starts_with(KICK_AUTHORIZATION_ENDPOINT));
    assert_eq!(
        query_value(&url, "scope"),
        Some("user:read channel:read chat:write".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
    Ok(())
}

#[test]
fn kick_authorization_url_can_disable_default_scope() -> Result<(), OAuthError> {
    let provider = kick(ProviderOptions {
        client_id: Some(ClientId::from("kick-client")),
        scope: vec!["channel:read".to_owned()],
        disable_default_scope: true,
        ..ProviderOptions::default()
    });

    let url = provider.create_authorization_url(KickAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        ..KickAuthorizationUrlRequest::default()
    })?;

    assert_eq!(query_value(&url, "scope"), Some("channel:read".to_owned()));
    Ok(())
}

#[test]
fn kick_authorization_code_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = kick(provider_options());

    let request = provider.create_authorization_code_request(
        "code-1",
        Some("01234567890123456789012345678901234567890123456789".to_owned()),
        "https://app.example.com/auth/callback",
    )?;

    assert_eq!(provider.token_endpoint(), KICK_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("client_id"), Some("kick-client"));
    assert_eq!(request.form_value("client_secret"), Some("kick-secret"));
    Ok(())
}

#[test]
fn kick_refresh_access_token_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = kick(provider_options());

    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_id"), Some("kick-client"));
    assert_eq!(request.form_value("client_secret"), Some("kick-secret"));
    Ok(())
}

#[test]
fn kick_profile_maps_to_unverified_user_info() {
    let profile = KickProfile {
        user_id: "kick-user-1".to_owned(),
        name: "Ada".to_owned(),
        email: "ada@example.com".to_owned(),
        profile_picture: "https://cdn.example.com/ada.png".to_owned(),
    };

    let user = KickProvider::map_profile_to_user_info(&profile);

    assert_eq!(user.id, "kick-user-1");
    assert_eq!(user.name.as_deref(), Some("Ada"));
    assert_eq!(user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        user.image.as_deref(),
        Some("https://cdn.example.com/ada.png")
    );
    assert!(!user.email_verified);
}

#[test]
fn kick_empty_user_info_response_returns_none() {
    let profiles = Vec::<KickProfile>::new();

    assert_eq!(KickProvider::map_profiles_to_user_info(profiles), None);
}

#[tokio::test]
async fn kick_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = kick(provider_options());

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("kick-client")),
        client_secret: Some("kick-secret".to_owned()),
        ..ProviderOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
