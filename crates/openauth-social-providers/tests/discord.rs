#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::advanced::discord::{
    discord, DiscordAuthorizationUrlRequest, DiscordOptions, DiscordProfile, DiscordPrompt,
    DiscordProvider,
};

#[test]
fn discord_provider_exposes_upstream_metadata() {
    let provider = discord(DiscordOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            ..ProviderOptions::default()
        },
        ..DiscordOptions::default()
    });

    assert_eq!(provider.id(), "discord");
    assert_eq!(provider.name(), "Discord");
}

#[test]
fn discord_authorization_url_uses_default_scopes_prompt_and_redirect_override() {
    let provider = DiscordProvider::new(DiscordOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            redirect_uri: Some("https://auth.example.com/discord/callback".to_owned()),
            ..ProviderOptions::default()
        },
        ..DiscordOptions::default()
    });

    let url = provider
        .create_authorization_url(DiscordAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: Vec::new(),
        })
        .expect("discord authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://discord.com/api/oauth2/authorize")
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "scope")
            .map(|(_, value)| value.into_owned()),
        Some("identify+email".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "prompt")
            .map(|(_, value)| value.into_owned()),
        Some("none".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .map(|(_, value)| value.into_owned()),
        Some("https://auth.example.com/discord/callback".to_owned())
    );
}

#[test]
fn discord_authorization_url_adds_bot_permissions_only_for_bot_scope() {
    let provider = DiscordProvider::new(DiscordOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::Single("client-id".to_owned())),
            scope: vec!["bot".to_owned()],
            ..ProviderOptions::default()
        },
        permissions: Some(8),
        prompt: DiscordPrompt::Consent,
    });

    let url = provider
        .create_authorization_url(DiscordAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: vec!["guilds".to_owned()],
        })
        .expect("discord authorization URL should build");

    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "scope")
            .map(|(_, value)| value.into_owned()),
        Some("identify+email+guilds+bot".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "permissions")
            .map(|(_, value)| value.into_owned()),
        Some("8".to_owned())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "prompt")
            .map(|(_, value)| value.into_owned()),
        Some("consent".to_owned())
    );
}

#[test]
fn discord_profile_without_avatar_maps_to_default_avatar_for_migrated_username() {
    let profile = DiscordProfile {
        id: "80351110224678912".to_owned(),
        username: "nelly".to_owned(),
        discriminator: "0".to_owned(),
        global_name: Some("Nelly".to_owned()),
        avatar: None,
        verified: true,
        email: Some("nelly@example.com".to_owned()),
        ..DiscordProfile::default()
    };

    let mapped = DiscordProvider::map_profile(profile);

    assert_eq!(mapped.user.id, "80351110224678912");
    assert_eq!(mapped.user.name.as_deref(), Some("Nelly"));
    assert_eq!(mapped.user.email.as_deref(), Some("nelly@example.com"));
    assert!(mapped.user.email_verified);
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://cdn.discordapp.com/embed/avatars/5.png")
    );
}

#[test]
fn discord_profile_with_animated_avatar_maps_to_gif_cdn_url() {
    let profile = DiscordProfile {
        id: "123".to_owned(),
        username: "nelly".to_owned(),
        discriminator: "1234".to_owned(),
        global_name: None,
        avatar: Some("a_hash".to_owned()),
        verified: false,
        ..DiscordProfile::default()
    };

    let mapped = DiscordProvider::map_profile(profile);

    assert_eq!(mapped.user.name.as_deref(), Some("nelly"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://cdn.discordapp.com/avatars/123/a_hash.gif")
    );
}

#[tokio::test]
async fn discord_get_user_info_returns_none_when_access_token_is_missing() {
    let provider = DiscordProvider::default();

    let info = provider
        .get_user_info(&OAuth2Tokens::default())
        .await
        .expect("missing access token should not error");

    assert!(info.is_none());
}
