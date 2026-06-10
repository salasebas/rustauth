use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::advanced::reddit::{
    reddit, RedditAuthorizationUrlRequest, RedditOptions, RedditProfile, RedditProvider,
    REDDIT_AUTHORIZATION_ENDPOINT, REDDIT_DEFAULT_SCOPE, REDDIT_ID, REDDIT_NAME,
    REDDIT_TOKEN_ENDPOINT,
};

#[test]
fn reddit_provider_exposes_upstream_metadata() {
    let provider = reddit(reddit_options());

    assert_eq!((provider.id(), provider.name()), (REDDIT_ID, REDDIT_NAME));
}

#[test]
fn reddit_authorization_url_includes_default_scopes_and_duration() -> Result<(), OAuthError> {
    let provider = reddit(RedditOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("reddit-client")),
            scope: vec!["history".to_owned()],
            ..ProviderOptions::default()
        },
        duration: Some("permanent".to_owned()),
    });

    let url = provider.create_authorization_url(RedditAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["read".to_owned()],
    })?;

    assert!(url.as_str().starts_with(REDDIT_AUTHORIZATION_ENDPOINT));
    assert_eq!(
        query_value(&url, "scope"),
        Some("identity history read".to_owned())
    );
    assert_eq!(query_value(&url, "duration"), Some("permanent".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("reddit-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    Ok(())
}

#[test]
fn reddit_authorization_url_can_disable_default_scope() -> Result<(), OAuthError> {
    let provider = reddit(RedditOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("reddit-client")),
            scope: vec!["history".to_owned()],
            disable_default_scope: true,
            ..ProviderOptions::default()
        },
        ..RedditOptions::default()
    });

    let url = provider.create_authorization_url(RedditAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["read".to_owned()],
    })?;

    assert_eq!(query_value(&url, "scope"), Some("history read".to_owned()));
    assert_ne!(
        query_value(&url, "scope"),
        Some(REDDIT_DEFAULT_SCOPE.to_owned())
    );
    Ok(())
}

#[test]
fn reddit_authorization_code_request_uses_basic_auth_and_upstream_headers() -> Result<(), OAuthError>
{
    let provider = reddit(reddit_options());
    let request =
        provider.authorization_code_request("code-1", "https://app.example.com/auth/callback")?;

    assert_eq!(provider.token_endpoint(), REDDIT_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
    assert_eq!(
        request.header("authorization"),
        Some("Basic cmVkZGl0LWNsaWVudDpyZWRkaXQtc2VjcmV0")
    );
    assert_eq!(request.header("accept"), Some("text/plain"));
    assert_eq!(request.header("user-agent"), Some("better-auth"));
    Ok(())
}

#[test]
fn reddit_refresh_request_uses_basic_auth() -> Result<(), OAuthError> {
    let provider = reddit(reddit_options());
    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
    assert_eq!(
        request.header("authorization"),
        Some("Basic cmVkZGl0LWNsaWVudDpyZWRkaXQtc2VjcmV0")
    );
    Ok(())
}

#[test]
fn reddit_profile_maps_to_user_info_and_strips_icon_query() {
    let profile = RedditProfile {
        id: "reddit-user-1".to_owned(),
        name: "spez".to_owned(),
        icon_img: Some("https://styles.redditmedia.com/icon.png?width=256".to_owned()),
        has_verified_email: true,
        oauth_client_id: "oauth-client-id".to_owned(),
        verified: true,
        ..RedditProfile::default()
    };

    let mapped = RedditProvider::map_profile(profile);

    assert_eq!(mapped.user.id, "reddit-user-1");
    assert_eq!(mapped.user.name.as_deref(), Some("spez"));
    assert_eq!(mapped.user.email.as_deref(), Some("oauth-client-id"));
    assert!(mapped.user.email_verified);
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://styles.redditmedia.com/icon.png")
    );
}

#[test]
fn reddit_profile_without_icon_maps_to_no_image() {
    let profile = RedditProfile {
        id: "reddit-user-1".to_owned(),
        name: "spez".to_owned(),
        icon_img: None,
        has_verified_email: false,
        oauth_client_id: "oauth-client-id".to_owned(),
        verified: false,
        ..RedditProfile::default()
    };

    let mapped = RedditProvider::map_profile(profile);

    assert_eq!(mapped.user.image, None);
    assert!(!mapped.user.email_verified);
}

#[tokio::test]
async fn reddit_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = reddit(reddit_options());

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn reddit_options() -> RedditOptions {
    RedditOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("reddit-client")),
            client_secret: Some("reddit-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..RedditOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
