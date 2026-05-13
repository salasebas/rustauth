#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use std::pin::Pin;
use std::sync::Arc;

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::twitter::{
    twitter, TwitterAuthorizationUrlRequest, TwitterOptions, TwitterProfile, TwitterProfileData,
    TwitterProvider, TwitterUserInfo, TwitterUserPatch, TwitterValidateAuthorizationCodeRequest,
    TWITTER_AUTHORIZATION_ENDPOINT, TWITTER_DEFAULT_SCOPES, TWITTER_ID, TWITTER_NAME,
    TWITTER_TOKEN_ENDPOINT,
};

#[test]
fn twitter_provider_exposes_upstream_metadata() {
    let provider = twitter(provider_options());

    assert_eq!((provider.id(), provider.name()), (TWITTER_ID, TWITTER_NAME));
}

#[test]
fn twitter_authorization_url_uses_default_configured_request_scopes_and_pkce(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = twitter(ProviderOptions {
        client_id: Some(ClientId::from("twitter-client")),
        scope: vec!["like.read".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider.create_authorization_url(TwitterAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["bookmark.read".to_owned()],
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some(TWITTER_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some(
            TWITTER_DEFAULT_SCOPES
                .iter()
                .chain(["like.read", "bookmark.read"].iter())
                .copied()
                .collect::<Vec<_>>()
                .join(" ")
        )
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert_eq!(
        query_value(&url, "client_id"),
        Some("twitter-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/callback".to_owned())
    );
    Ok(())
}

#[test]
fn twitter_authorization_url_can_disable_default_scopes() -> Result<(), Box<dyn std::error::Error>>
{
    let provider = twitter(ProviderOptions {
        client_id: Some(ClientId::from("twitter-client")),
        disable_default_scope: true,
        scope: vec!["users.read".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider.create_authorization_url(TwitterAuthorizationUrlRequest {
        state: "state-2".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["tweet.read".to_owned()],
        ..TwitterAuthorizationUrlRequest::default()
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("users.read tweet.read".to_owned())
    );
    Ok(())
}

#[test]
fn twitter_authorization_code_request_uses_basic_auth() -> Result<(), Box<dyn std::error::Error>> {
    let provider = twitter(provider_options());

    let request =
        provider.create_authorization_code_request(TwitterValidateAuthorizationCodeRequest {
            code: "auth-code".to_owned(),
            code_verifier: Some("verifier".to_owned()),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        })?;

    assert_eq!(provider.token_endpoint(), TWITTER_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("auth-code"));
    assert_eq!(request.form_value("code_verifier"), Some("verifier"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
    assert_eq!(
        request.header("authorization"),
        Some("Basic dHdpdHRlci1jbGllbnQ6dHdpdHRlci1zZWNyZXQ=")
    );
    Ok(())
}

#[test]
fn twitter_refresh_token_request_uses_basic_auth() -> Result<(), Box<dyn std::error::Error>> {
    let provider = twitter(provider_options());

    let request = provider.create_refresh_access_token_request("refresh-token")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-token"));
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
    assert_eq!(
        request.header("authorization"),
        Some("Basic dHdpdHRlci1jbGllbnQ6dHdpdHRlci1zZWNyZXQ=")
    );
    Ok(())
}

#[test]
fn twitter_profile_with_confirmed_email_maps_verified_user() {
    let profile = profile_with_email(None);

    let user_info =
        TwitterProvider::user_info_from_profile(profile, Some("confirmed@example.com".to_owned()));

    assert_eq!(user_info.user.id, "twitter-user-1");
    assert_eq!(user_info.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(
        user_info.user.email.as_deref(),
        Some("confirmed@example.com")
    );
    assert_eq!(
        user_info.user.image.as_deref(),
        Some("https://pbs.twimg.com/profile_images/ada.jpg")
    );
    assert!(user_info.user.email_verified);
    assert_eq!(
        user_info.data.data.email.as_deref(),
        Some("confirmed@example.com")
    );
}

#[test]
fn twitter_profile_without_confirmed_email_falls_back_to_username() {
    let profile = profile_with_email(None);

    let user_info = TwitterProvider::user_info_from_profile(profile, None);

    assert_eq!(user_info.user.email.as_deref(), Some("ada"));
    assert!(!user_info.user.email_verified);
}

#[test]
fn twitter_profile_without_email_or_username_maps_no_email() {
    let mut profile = profile_with_email(None);
    profile.data.username.clear();

    let user_info = TwitterProvider::user_info_from_profile(profile, None);

    assert_eq!(user_info.user.email, None);
    assert!(!user_info.user.email_verified);
}

#[test]
fn twitter_profile_prefers_profile_email_before_username_without_confirmed_email() {
    let profile = profile_with_email(Some("profile@example.com"));

    let user_info = TwitterProvider::user_info_from_profile(profile, None);

    assert_eq!(user_info.user.email.as_deref(), Some("profile@example.com"));
    assert!(!user_info.user.email_verified);
}

#[test]
fn twitter_partial_mapper_overrides_selected_user_fields() {
    let provider = twitter(TwitterOptions {
        oauth: provider_options(),
        map_profile_to_user: Some(Arc::new(|profile| TwitterUserPatch {
            name: Some(Some(format!("@{}", profile.data.username))),
            email_verified: Some(true),
            ..TwitterUserPatch::default()
        })),
        ..TwitterOptions::default()
    });

    let user_info = provider.map_profile(profile_with_email(None), None);

    assert_eq!(user_info.user.name.as_deref(), Some("@ada"));
    assert_eq!(user_info.user.email.as_deref(), Some("ada"));
    assert!(user_info.user.email_verified);
}

#[tokio::test]
async fn twitter_custom_get_user_info_callback_is_used() -> Result<(), Box<dyn std::error::Error>> {
    let provider = twitter(TwitterOptions {
        oauth: provider_options(),
        get_user_info: Some(Arc::new(|_token| {
            Box::pin(async {
                Ok(Some(TwitterUserInfo {
                    user: openauth_oauth::oauth2::OAuth2UserInfo {
                        id: "custom-user".to_owned(),
                        name: Some("Custom".to_owned()),
                        email: None,
                        image: None,
                        email_verified: true,
                    },
                    data: profile_with_email(None),
                }))
            }) as Pin<Box<_>>
        })),
        ..TwitterOptions::default()
    });

    let info = provider
        .get_user_info(&OAuth2Tokens {
            access_token: Some("unused".to_owned()),
            ..OAuth2Tokens::default()
        })
        .await?
        .ok_or("custom user info")?;

    assert_eq!(info.user.id, "custom-user");
    assert!(info.user.email_verified);
    Ok(())
}

#[tokio::test]
async fn twitter_custom_refresh_access_token_callback_is_used(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = twitter(TwitterOptions {
        oauth: provider_options(),
        refresh_access_token: Some(Arc::new(|refresh_token| {
            Box::pin(async move {
                Ok(OAuth2Tokens {
                    access_token: Some(format!("access-for-{refresh_token}")),
                    refresh_token: Some(refresh_token),
                    ..OAuth2Tokens::default()
                })
            }) as Pin<Box<_>>
        })),
        ..TwitterOptions::default()
    });

    let tokens = provider.refresh_access_token("refresh-1").await?;

    assert_eq!(tokens.access_token.as_deref(), Some("access-for-refresh-1"));
    assert_eq!(tokens.refresh_token.as_deref(), Some("refresh-1"));
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("twitter-client")),
        client_secret: Some("twitter-secret".to_owned()),
        client_key: Some("twitter-key".to_owned()),
        ..ProviderOptions::default()
    }
}

fn profile_with_email(email: Option<&str>) -> TwitterProfile {
    TwitterProfile {
        data: TwitterProfileData {
            id: "twitter-user-1".to_owned(),
            name: "Ada Lovelace".to_owned(),
            username: "ada".to_owned(),
            email: email.map(str::to_owned),
            profile_image_url: Some("https://pbs.twimg.com/profile_images/ada.jpg".to_owned()),
            ..TwitterProfileData::default()
        },
        ..TwitterProfile::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
