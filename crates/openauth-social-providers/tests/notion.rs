#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::advanced::notion::{
    NotionAuthorizationUrlRequest, NotionOwner, NotionOwnerUser, NotionPerson, NotionProfile,
    NotionProvider, NotionUserInfoResponse,
};

#[test]
fn notion_provider_exposes_upstream_metadata() {
    let provider = NotionProvider::new(ProviderOptions {
        client_id: Some(ClientId::from("notion-client")),
        ..ProviderOptions::default()
    });

    assert_eq!(provider.id(), "notion");
    assert_eq!(provider.name(), "Notion");
}

#[test]
fn notion_authorization_url_uses_owner_user_and_no_default_scope() {
    let provider = NotionProvider::new(ProviderOptions {
        client_id: Some(ClientId::from("notion-client")),
        scope: vec!["workspace.content".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider
        .create_authorization_url(NotionAuthorizationUrlRequest {
            state: "state-token".to_owned(),
            redirect_uri: "https://app.example.com/callback/notion".to_owned(),
            scopes: vec!["workspace.user".to_owned()],
            login_hint: Some("ada@example.com".to_owned()),
        })
        .expect("notion authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://api.notion.com/v1/oauth/authorize")
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("notion-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-token".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/callback/notion".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("workspace.content workspace.user".to_owned())
    );
    assert_eq!(
        query_value(&url, "login_hint"),
        Some("ada@example.com".to_owned())
    );
    assert_eq!(query_value(&url, "owner"), Some("user".to_owned()));
}

#[test]
fn notion_authorization_url_omits_scope_when_no_scopes_are_configured() {
    let provider = NotionProvider::new(ProviderOptions {
        client_id: Some(ClientId::from("notion-client")),
        ..ProviderOptions::default()
    });

    let url = provider
        .create_authorization_url(NotionAuthorizationUrlRequest {
            state: "state-token".to_owned(),
            redirect_uri: "https://app.example.com/callback/notion".to_owned(),
            ..NotionAuthorizationUrlRequest::default()
        })
        .expect("notion authorization URL should build");

    assert_eq!(query_value(&url, "scope"), None);
}

#[test]
fn notion_authorization_code_request_uses_basic_auth() {
    let provider = NotionProvider::new(ProviderOptions {
        client_id: Some(ClientId::from("notion-client")),
        client_secret: Some("notion-secret".to_owned()),
        ..ProviderOptions::default()
    });

    let request = provider
        .authorization_code_request("auth-code", "https://app.example.com/callback/notion")
        .expect("authorization code request should build");

    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("auth-code"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/callback/notion")
    );
    assert_eq!(request.form_value("client_id"), None);
    assert_eq!(request.form_value("client_secret"), None);
    assert_eq!(
        request.header("authorization"),
        Some("Basic bm90aW9uLWNsaWVudDpub3Rpb24tc2VjcmV0")
    );
}

#[test]
fn notion_refresh_token_request_uses_post_auth_like_upstream_helper_default() {
    let provider = NotionProvider::new(ProviderOptions {
        client_id: Some(ClientId::from("notion-client")),
        client_secret: Some("notion-secret".to_owned()),
        ..ProviderOptions::default()
    });

    let request = provider
        .refresh_access_token_request("refresh-token")
        .expect("refresh token request should build");

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-token"));
    assert_eq!(request.form_value("client_id"), Some("notion-client"));
    assert_eq!(request.form_value("client_secret"), Some("notion-secret"));
    assert_eq!(request.header("authorization"), None);
}

#[test]
fn notion_users_me_response_maps_owner_user_to_unverified_oauth_user() {
    let response = NotionUserInfoResponse {
        bot: NotionOwner {
            owner: NotionOwnerUser {
                user: NotionProfile {
                    id: "notion-user-1".to_owned(),
                    kind: "person".to_owned(),
                    name: Some("Ada Lovelace".to_owned()),
                    avatar_url: Some("https://images.example.com/ada.png".to_owned()),
                    person: Some(NotionPerson {
                        email: Some("ada@example.com".to_owned()),
                    }),
                },
            },
        },
    };

    let mapped = NotionProvider::user_info_from_response(response)
        .expect("owner user should map to user info");

    assert_eq!(mapped.user.id, "notion-user-1");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://images.example.com/ada.png")
    );
    assert!(!mapped.user.email_verified);
    assert_eq!(mapped.data.id, "notion-user-1");
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
