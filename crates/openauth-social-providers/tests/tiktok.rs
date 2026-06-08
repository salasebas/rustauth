use openauth_oauth::oauth2::{OAuth2Tokens, OAuthError, ProviderOptions};
use openauth_social_providers::tiktok::{
    tiktok, TiktokAuthorizationUrlRequest, TiktokProfile, TiktokProfileData, TiktokProvider,
    TiktokUser, TiktokValidateAuthorizationCodeRequest, TIKTOK_AUTHORIZATION_ENDPOINT, TIKTOK_ID,
    TIKTOK_NAME, TIKTOK_TOKEN_ENDPOINT,
};

#[test]
fn tiktok_provider_exposes_upstream_metadata() {
    let provider = tiktok(provider_options());

    assert_eq!(provider.id(), TIKTOK_ID);
    assert_eq!(provider.name(), TIKTOK_NAME);
}

#[test]
fn tiktok_authorization_url_uses_client_key_and_comma_joined_scopes() -> Result<(), OAuthError> {
    let provider = tiktok(ProviderOptions {
        scope: vec!["video.list".to_owned()],
        ..provider_options()
    });

    let url = provider.create_authorization_url(TiktokAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["user.info.stats".to_owned()],
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some(TIKTOK_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_key"),
        Some("tiktok-key".to_owned())
    );
    assert_eq!(query_value(&url, "client_id"), None);
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("user.info.profile,video.list,user.info.stats".to_owned())
    );
    Ok(())
}

#[test]
fn tiktok_authorization_url_can_disable_default_scope() -> Result<(), OAuthError> {
    let provider = tiktok(ProviderOptions {
        scope: vec!["video.list".to_owned()],
        disable_default_scope: true,
        ..provider_options()
    });

    let url = provider.create_authorization_url(TiktokAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["user.info.stats".to_owned()],
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("video.list,user.info.stats".to_owned())
    );
    Ok(())
}

#[test]
fn tiktok_authorization_url_rejects_empty_state() {
    let provider = tiktok(provider_options());

    let error = provider
        .create_authorization_url(TiktokAuthorizationUrlRequest {
            state: String::new(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            scopes: Vec::new(),
        })
        .err()
        .map(|error| error.to_string());

    assert!(error
        .as_deref()
        .is_some_and(|message| message.contains("authorization state")));
}

#[test]
fn tiktok_authorization_url_rejects_invalid_redirect_uri_without_override() {
    let provider = tiktok(provider_options());

    let error = provider
        .create_authorization_url(TiktokAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "notaurl".to_owned(),
            scopes: Vec::new(),
        })
        .err()
        .map(|error| error.to_string());

    assert!(error
        .as_deref()
        .is_some_and(|message| message.contains("OAuth URL")));
}

#[test]
fn tiktok_authorization_url_uses_redirect_override_when_configured() -> Result<(), OAuthError> {
    let provider = tiktok(ProviderOptions {
        redirect_uri: Some("https://auth.example.com/tiktok/callback".to_owned()),
        ..provider_options()
    });

    let url = provider.create_authorization_url(TiktokAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "notaurl".to_owned(),
        scopes: Vec::new(),
    })?;

    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/tiktok/callback".to_owned())
    );
    Ok(())
}

#[test]
fn tiktok_authorization_url_requires_client_key() {
    let provider = tiktok(ProviderOptions {
        client_secret: Some("tiktok-secret".to_owned()),
        ..ProviderOptions::default()
    });

    let error = provider
        .create_authorization_url(TiktokAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            scopes: Vec::new(),
        })
        .err()
        .map(|error| error.to_string());

    assert_eq!(
        error.as_deref(),
        Some("missing OAuth provider option `client_key`")
    );
}

#[test]
fn tiktok_authorization_code_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = tiktok(provider_options());

    let request = provider.authorization_code_request(TiktokValidateAuthorizationCodeRequest {
        code: "code-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
    })?;

    assert_eq!(provider.token_endpoint(), TIKTOK_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("client_key"), Some("tiktok-key"));
    assert_eq!(request.form_value("client_secret"), Some("tiktok-secret"));
    assert_eq!(request.form_value("client_id"), None);
    Ok(())
}

#[test]
fn tiktok_refresh_token_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = tiktok(provider_options());

    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_key"), Some("tiktok-key"));
    assert_eq!(request.form_value("client_secret"), Some("tiktok-secret"));
    assert_eq!(request.form_value("client_id"), None);
    Ok(())
}

#[test]
fn tiktok_profile_maps_username_as_email_fallback() {
    let profile = tiktok_profile("Ada Lovelace", None);

    let mapped = TiktokProvider::user_info_from_profile(profile);

    assert_eq!(mapped.user.id, "tiktok-open-id-1");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada_lovelace"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://cdn.example.com/ada-large.png")
    );
    assert!(!mapped.user.email_verified);
}

#[test]
fn tiktok_profile_prefers_email_when_present() {
    let profile = tiktok_profile("Ada Lovelace", Some("ada@example.com"));

    let mapped = TiktokProvider::user_info_from_profile(profile);

    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
}

#[test]
fn tiktok_profile_uses_username_when_display_name_is_empty() {
    let profile = tiktok_profile("", None);

    let mapped = TiktokProvider::user_info_from_profile(profile);

    assert_eq!(mapped.user.name.as_deref(), Some("ada_lovelace"));
}

#[tokio::test]
async fn tiktok_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = TiktokProvider::new(provider_options());

    assert!(provider
        .get_user_info(&OAuth2Tokens::default())
        .await?
        .is_none());
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_secret: Some("tiktok-secret".to_owned()),
        client_key: Some("tiktok-key".to_owned()),
        ..ProviderOptions::default()
    }
}

fn tiktok_profile(display_name: &str, email: Option<&str>) -> TiktokProfile {
    TiktokProfile {
        data: TiktokProfileData {
            user: TiktokUser {
                open_id: "tiktok-open-id-1".to_owned(),
                union_id: Some("tiktok-union-id-1".to_owned()),
                avatar_url: Some("https://cdn.example.com/ada.png".to_owned()),
                avatar_url_100: Some("https://cdn.example.com/ada-100.png".to_owned()),
                avatar_large_url: "https://cdn.example.com/ada-large.png".to_owned(),
                display_name: display_name.to_owned(),
                username: "ada_lovelace".to_owned(),
                email: email.map(str::to_owned),
                bio_description: Some("mathematician".to_owned()),
                profile_deep_link: Some("https://www.tiktok.com/@ada_lovelace".to_owned()),
                is_verified: Some(true),
                follower_count: Some(42),
                following_count: Some(7),
                likes_count: Some(9000),
                video_count: Some(3),
            },
        },
        error: None,
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
