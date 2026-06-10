#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::advanced::roblox::{
    roblox, RobloxAuthorizationUrlRequest, RobloxOptions, RobloxProfile, RobloxPrompt,
    RobloxProvider, ROBLOX_AUTHORIZATION_ENDPOINT, ROBLOX_ID, ROBLOX_NAME, ROBLOX_TOKEN_ENDPOINT,
};

#[test]
fn roblox_provider_exposes_upstream_metadata() {
    let provider = RobloxProvider::new(RobloxOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("roblox-client")),
            ..ProviderOptions::default()
        },
        ..RobloxOptions::default()
    });

    assert_eq!(provider.id(), ROBLOX_ID);
    assert_eq!(provider.name(), ROBLOX_NAME);
}

#[test]
fn roblox_authorization_url_uses_default_scopes_prompt_and_redirect_override() {
    let provider = roblox(RobloxOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("roblox-client")),
            redirect_uri: Some("https://auth.example.com/roblox/callback".to_owned()),
            scope: vec!["extra-scope".to_owned()],
            ..ProviderOptions::default()
        },
        ..RobloxOptions::default()
    });

    let url = provider
        .create_authorization_url(RobloxAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: vec!["request-scope".to_owned()],
        })
        .expect("roblox authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some(ROBLOX_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid+profile+extra-scope+request-scope".to_owned())
    );
    assert_eq!(
        query_value(&url, "prompt"),
        Some("select_account consent".to_owned())
    );
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/roblox/callback".to_owned())
    );
}

#[test]
fn roblox_authorization_url_can_disable_default_scope_and_choose_prompt() {
    let provider = roblox(RobloxOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("roblox-client")),
            disable_default_scope: true,
            scope: vec!["openid".to_owned()],
            ..ProviderOptions::default()
        },
        prompt: RobloxPrompt::Login,
    });

    let url = provider
        .create_authorization_url(RobloxAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: vec!["profile".to_owned()],
        })
        .expect("roblox authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("openid+profile".to_owned())
    );
    assert_eq!(query_value(&url, "prompt"), Some("login".to_owned()));
}

#[test]
fn roblox_authorization_code_request_uses_post_client_authentication() {
    let provider = roblox(provider_options());

    let request = provider
        .create_authorization_code_request("auth-code", "https://app.example.com/callback")
        .expect("authorization code request should build");

    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("auth-code"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/callback")
    );
    assert_eq!(request.form_value("client_id"), Some("roblox-client"));
    assert_eq!(request.form_value("client_secret"), Some("roblox-secret"));
    assert_eq!(request.header("authorization"), None);
}

#[test]
fn roblox_refresh_access_token_request_uses_post_client_authentication() {
    let provider = roblox(provider_options());

    let request = provider
        .refresh_access_token_request("refresh-token")
        .expect("refresh request should build");

    assert_eq!(provider.token_endpoint(), ROBLOX_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-token"));
    assert_eq!(request.form_value("client_id"), Some("roblox-client"));
    assert_eq!(request.form_value("client_secret"), Some("roblox-secret"));
    assert_eq!(request.header("authorization"), None);
}

#[test]
fn roblox_profile_maps_to_unverified_oauth_user_info() {
    let profile = RobloxProfile {
        sub: "123456".to_owned(),
        preferred_username: "builderman".to_owned(),
        nickname: "Builder".to_owned(),
        name: "Builder".to_owned(),
        created_at: 1_700_000_000,
        profile: "https://www.roblox.com/users/123456/profile".to_owned(),
        picture: "https://tr.rbxcdn.com/avatar.png".to_owned(),
        extra: Default::default(),
    };

    let mapped = RobloxProvider::map_profile(profile);

    assert_eq!(mapped.user.id, "123456");
    assert_eq!(mapped.user.name.as_deref(), Some("Builder"));
    assert_eq!(mapped.user.email.as_deref(), Some("builderman"));
    assert!(!mapped.user.email_verified);
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://tr.rbxcdn.com/avatar.png")
    );
}

#[test]
fn roblox_profile_name_falls_back_to_preferred_username() {
    let profile = RobloxProfile {
        sub: "123456".to_owned(),
        preferred_username: "builderman".to_owned(),
        nickname: String::new(),
        name: String::new(),
        created_at: 1_700_000_000,
        profile: "https://www.roblox.com/users/123456/profile".to_owned(),
        picture: "https://tr.rbxcdn.com/avatar.png".to_owned(),
        extra: Default::default(),
    };

    let mapped = RobloxProvider::map_profile(profile);

    assert_eq!(mapped.user.name.as_deref(), Some("builderman"));
}

#[tokio::test]
async fn roblox_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = roblox(provider_options());

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn provider_options() -> RobloxOptions {
    RobloxOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("roblox-client")),
            client_secret: Some("roblox-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..RobloxOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
