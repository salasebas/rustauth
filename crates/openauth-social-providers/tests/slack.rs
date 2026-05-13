#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, ProviderOptions};
use openauth_social_providers::slack::{
    slack, SlackAuthorizationUrlRequest, SlackOptions, SlackProfile, SlackProvider,
    SLACK_AUTHORIZATION_ENDPOINT, SLACK_ID, SLACK_NAME,
};

#[test]
fn slack_provider_exposes_upstream_metadata() {
    let provider = slack(slack_options());

    assert_eq!(provider.id(), SLACK_ID);
    assert_eq!(provider.name(), SLACK_NAME);
}

#[test]
fn slack_authorization_url_uses_upstream_defaults() {
    let provider = SlackProvider::new(slack_options());

    let url = provider
        .create_authorization_url(SlackAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: Vec::new(),
        })
        .expect("slack authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some(SLACK_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("slack-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-123".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid profile email".to_owned())
    );
}

#[test]
fn slack_authorization_url_uses_redirect_override_and_extra_scopes() {
    let provider = SlackProvider::new(SlackOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("slack-client")),
            redirect_uri: Some("https://auth.example.com/slack/callback".to_owned()),
            scope: vec!["team".to_owned()],
            ..ProviderOptions::default()
        },
    });

    let url = provider
        .create_authorization_url(SlackAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: vec!["users:read".to_owned()],
        })
        .expect("slack authorization URL should build");

    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/slack/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid profile email team users:read".to_owned())
    );
}

#[test]
fn slack_authorization_url_can_disable_default_scope() {
    let provider = SlackProvider::new(SlackOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("slack-client")),
            disable_default_scope: true,
            scope: vec!["team".to_owned()],
            ..ProviderOptions::default()
        },
    });

    let url = provider
        .create_authorization_url(SlackAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            scopes: vec!["users:read".to_owned()],
        })
        .expect("slack authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("team users:read".to_owned())
    );
}

#[test]
fn slack_profile_maps_user_id_before_subject() {
    let profile = slack_profile();

    let user = SlackProvider::map_profile_to_user_info(&profile);

    assert_eq!(user.id, "slack-user-1");
    assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(user.email.as_deref(), Some("ada@example.com"));
    assert!(user.email_verified);
    assert_eq!(
        user.image.as_deref(),
        Some("https://img.example.com/ada.png")
    );
}

#[test]
fn slack_profile_falls_back_to_subject_when_user_id_is_missing() {
    let profile = SlackProfile {
        user_id: None,
        ..slack_profile()
    };

    let user = SlackProvider::map_profile_to_user_info(&profile);

    assert_eq!(user.id, "slack-subject-1");
}

#[test]
fn slack_profile_uses_large_user_image_when_picture_is_missing() {
    let profile = SlackProfile {
        picture: None,
        user_image_512: Some("https://img.example.com/ada-512.png".to_owned()),
        ..slack_profile()
    };

    let user = SlackProvider::map_profile_to_user_info(&profile);

    assert_eq!(
        user.image.as_deref(),
        Some("https://img.example.com/ada-512.png")
    );
}

#[tokio::test]
async fn slack_get_user_info_returns_none_when_access_token_is_missing() {
    let provider = SlackProvider::default();

    let info = provider
        .get_user_info(&OAuth2Tokens::default())
        .await
        .expect("missing access token should not error");

    assert!(info.is_none());
}

fn slack_options() -> SlackOptions {
    SlackOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("slack-client")),
            client_secret: Some("slack-secret".to_owned()),
            ..ProviderOptions::default()
        },
    }
}

fn slack_profile() -> SlackProfile {
    SlackProfile {
        ok: Some(true),
        sub: "slack-subject-1".to_owned(),
        user_id: Some("slack-user-1".to_owned()),
        team_id: Some("slack-team-1".to_owned()),
        email: Some("ada@example.com".to_owned()),
        email_verified: true,
        date_email_verified: Some(1_704_067_200),
        name: Some("Ada Lovelace".to_owned()),
        picture: Some("https://img.example.com/ada.png".to_owned()),
        given_name: Some("Ada".to_owned()),
        family_name: Some("Lovelace".to_owned()),
        locale: Some("en-US".to_owned()),
        team_name: Some("Example".to_owned()),
        team_domain: Some("example".to_owned()),
        user_image_24: None,
        user_image_32: None,
        user_image_48: None,
        user_image_72: None,
        user_image_192: None,
        user_image_512: Some("https://img.example.com/ada-512.png".to_owned()),
        team_image_34: None,
        team_image_44: None,
        team_image_68: None,
        team_image_88: None,
        team_image_102: None,
        team_image_132: None,
        team_image_230: None,
        team_image_default: None,
        extra: Default::default(),
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
