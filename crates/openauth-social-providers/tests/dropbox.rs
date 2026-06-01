#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::dropbox::{
    DropboxAccessType, DropboxAuthorizationUrlRequest, DropboxName, DropboxProfile,
    DropboxProvider, DropboxProviderOptions,
};

#[test]
fn dropbox_provider_exposes_upstream_metadata() {
    let provider = DropboxProvider::new(DropboxProviderOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("dropbox-client")),
            ..ProviderOptions::default()
        },
        ..DropboxProviderOptions::default()
    });

    assert_eq!(provider.id(), "dropbox");
    assert_eq!(provider.name(), "Dropbox");
}

#[test]
fn authorization_url_includes_default_scope_and_access_type() {
    let provider = DropboxProvider::new(DropboxProviderOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("dropbox-client")),
            ..ProviderOptions::default()
        },
        access_type: Some(DropboxAccessType::Offline),
    });

    let url = provider
        .create_authorization_url(DropboxAuthorizationUrlRequest {
            state: "state".to_owned(),
            redirect_uri: "https://app.example.com/callback/dropbox".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            scopes: vec!["files.metadata.read".to_owned()],
        })
        .expect("authorization url should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://www.dropbox.com/oauth2/authorize")
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("dropbox-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/callback/dropbox".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("account_info.read files.metadata.read".to_owned())
    );
    assert_eq!(
        query_value(&url, "token_access_type"),
        Some("offline".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
}

#[test]
fn authorization_url_can_disable_default_scope() {
    let provider = DropboxProvider::new(DropboxProviderOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("dropbox-client")),
            disable_default_scope: true,
            scope: vec!["sharing.read".to_owned()],
            ..ProviderOptions::default()
        },
        ..DropboxProviderOptions::default()
    });

    let url = provider
        .create_authorization_url(DropboxAuthorizationUrlRequest {
            state: "state".to_owned(),
            redirect_uri: "https://app.example.com/callback/dropbox".to_owned(),
            scopes: vec!["files.metadata.read".to_owned()],
            ..DropboxAuthorizationUrlRequest::default()
        })
        .expect("authorization url should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("sharing.read files.metadata.read".to_owned())
    );
}

#[test]
fn maps_dropbox_profile_to_oauth_user_info() {
    let profile = DropboxProfile {
        account_id: "dbid:account".to_owned(),
        name: DropboxName {
            display_name: "Ada Lovelace".to_owned(),
            ..DropboxName::default()
        },
        email: "ada@example.com".to_owned(),
        email_verified: true,
        profile_photo_url: Some("https://photos.example.com/ada.jpg".to_owned()),
    };

    let user = DropboxProvider::map_profile_to_user_info(&profile);

    assert_eq!(user.id, "dbid:account");
    assert_eq!(user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(user.email.as_deref(), Some("ada@example.com"));
    assert!(user.email_verified);
    assert_eq!(
        user.image.as_deref(),
        Some("https://photos.example.com/ada.jpg")
    );
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
