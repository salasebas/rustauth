#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::spotify::{
    spotify, SpotifyAuthorizationUrlRequest, SpotifyImage, SpotifyProfile, SpotifyProvider,
    SPOTIFY_AUTHORIZATION_ENDPOINT, SPOTIFY_DEFAULT_SCOPE, SPOTIFY_ID, SPOTIFY_NAME,
    SPOTIFY_TOKEN_ENDPOINT,
};

#[test]
fn spotify_provider_exposes_upstream_metadata() {
    let provider = spotify(spotify_options());

    assert_eq!((provider.id(), provider.name()), (SPOTIFY_ID, SPOTIFY_NAME));
}

#[test]
fn spotify_authorization_url_includes_default_configured_request_scopes_and_pkce() {
    let provider = spotify(ProviderOptions {
        client_id: Some(ClientId::from("spotify-client")),
        scope: vec!["playlist-read-private".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider
        .create_authorization_url(SpotifyAuthorizationUrlRequest {
            state: "state-token".to_owned(),
            redirect_uri: "https://app.example.com/callback/spotify".to_owned(),
            scopes: vec!["user-top-read".to_owned()],
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        })
        .expect("spotify authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some(SPOTIFY_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("spotify-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-token".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/callback/spotify".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("user-read-email playlist-read-private user-top-read".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
}

#[test]
fn spotify_authorization_url_can_disable_default_scope() {
    let provider = spotify(ProviderOptions {
        client_id: Some(ClientId::from("spotify-client")),
        scope: vec!["playlist-read-private".to_owned()],
        disable_default_scope: true,
        ..ProviderOptions::default()
    });

    let url = provider
        .create_authorization_url(SpotifyAuthorizationUrlRequest {
            state: "state-token".to_owned(),
            redirect_uri: "https://app.example.com/callback/spotify".to_owned(),
            scopes: vec!["user-top-read".to_owned()],
            ..SpotifyAuthorizationUrlRequest::default()
        })
        .expect("spotify authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("playlist-read-private user-top-read".to_owned())
    );
    assert_ne!(
        query_value(&url, "scope"),
        Some(SPOTIFY_DEFAULT_SCOPE.to_owned())
    );
}

#[test]
fn spotify_authorization_code_request_uses_post_client_authentication() {
    let provider = spotify(spotify_options());
    let request = provider
        .authorization_code_request("auth-code", "https://app.example.com/callback/spotify")
        .expect("authorization code request should build");

    assert_eq!(provider.token_endpoint(), SPOTIFY_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("auth-code"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/callback/spotify")
    );
    assert_eq!(request.form_value("client_id"), Some("spotify-client"));
    assert_eq!(request.form_value("client_secret"), Some("spotify-secret"));
    assert_eq!(request.header("authorization"), None);
}

#[test]
fn spotify_refresh_token_request_uses_post_client_authentication() {
    let provider = spotify(spotify_options());
    let request = provider
        .refresh_access_token_request("refresh-token")
        .expect("refresh token request should build");

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-token"));
    assert_eq!(request.form_value("client_id"), Some("spotify-client"));
    assert_eq!(request.form_value("client_secret"), Some("spotify-secret"));
    assert_eq!(request.header("authorization"), None);
}

#[test]
fn spotify_profile_maps_first_image_and_unverified_email() {
    let mapped = SpotifyProvider::user_info_from_profile(SpotifyProfile {
        id: "spotify-user-1".to_owned(),
        display_name: "Ada Lovelace".to_owned(),
        email: "ada@example.com".to_owned(),
        images: vec![
            SpotifyImage {
                url: "https://images.example.com/first.png".to_owned(),
            },
            SpotifyImage {
                url: "https://images.example.com/second.png".to_owned(),
            },
        ],
    });

    assert_eq!(mapped.user.id, "spotify-user-1");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://images.example.com/first.png")
    );
    assert!(!mapped.user.email_verified);
    assert_eq!(mapped.data.id, "spotify-user-1");
}

#[test]
fn spotify_profile_without_images_maps_to_no_image() {
    let mapped = SpotifyProvider::user_info_from_profile(SpotifyProfile {
        id: "spotify-user-1".to_owned(),
        display_name: "Ada Lovelace".to_owned(),
        email: "ada@example.com".to_owned(),
        images: Vec::new(),
    });

    assert_eq!(mapped.user.image, None);
    assert!(!mapped.user.email_verified);
}

#[tokio::test]
async fn spotify_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = spotify(spotify_options());

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn spotify_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("spotify-client")),
        client_secret: Some("spotify-secret".to_owned()),
        ..ProviderOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
