#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use std::sync::Arc;

use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, OAuthError, OAuthProviderContract, ProviderOptions,
};
use openauth_social_providers::advanced::polar::{
    PolarAuthorizationUrlRequest, PolarOptions, PolarProfile, PolarProvider,
};

#[test]
fn polar_provider_exposes_upstream_metadata() {
    let provider = PolarProvider::new(PolarOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("polar-client")),
            ..ProviderOptions::default()
        },
        ..PolarOptions::default()
    });

    assert_eq!(provider.id(), "polar");
    assert_eq!(provider.name(), "Polar");
}

#[test]
fn polar_authorization_url_uses_defaults_prompt_pkce_and_redirect_override() {
    let provider = PolarProvider::new(PolarOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("polar-client")),
            redirect_uri: Some("https://auth.example.com/callback/polar".to_owned()),
            prompt: Some("consent".to_owned()),
            ..ProviderOptions::default()
        },
        ..PolarOptions::default()
    });

    let url = provider
        .create_authorization_url(PolarAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            scopes: vec!["custom:read".to_owned()],
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            redirect_uri: "https://app.example.com/callback".to_owned(),
        })
        .expect("polar authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://polar.sh/oauth2/authorize")
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("polar-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-123".to_owned()));
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid profile email custom:read".to_owned())
    );
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/callback/polar".to_owned())
    );
    assert_eq!(query_value(&url, "prompt"), Some("consent".to_owned()));
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
}

#[test]
fn polar_authorization_url_can_disable_default_scope() {
    let provider = PolarProvider::new(PolarOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("polar-client")),
            scope: vec!["benefits:read".to_owned()],
            disable_default_scope: true,
            ..ProviderOptions::default()
        },
        ..PolarOptions::default()
    });

    let url = provider
        .create_authorization_url(PolarAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            scopes: vec!["pledges:read".to_owned()],
            redirect_uri: "https://app.example.com/callback".to_owned(),
            ..PolarAuthorizationUrlRequest::default()
        })
        .expect("polar authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("benefits:read pledges:read".to_owned())
    );
}

#[test]
fn polar_profile_maps_public_name_before_username() {
    let mapped = PolarProvider::map_profile(PolarProfile {
        id: "polar-user".to_owned(),
        email: "ada@example.com".to_owned(),
        username: "ada_dev".to_owned(),
        avatar_url: "https://cdn.example.com/ada.png".to_owned(),
        public_name: Some("Ada Lovelace".to_owned()),
        email_verified: Some(true),
        ..PolarProfile::default()
    });

    assert_eq!(mapped.user.id, "polar-user");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://cdn.example.com/ada.png")
    );
    assert!(mapped.user.email_verified);
}

#[test]
fn polar_profile_defaults_email_verified_to_false() {
    let mapped = PolarProvider::map_profile(PolarProfile {
        id: "polar-user".to_owned(),
        username: "ada_dev".to_owned(),
        ..PolarProfile::default()
    });

    assert_eq!(mapped.user.name.as_deref(), Some("ada_dev"));
    assert!(!mapped.user.email_verified);
}

#[test]
fn polar_profile_mapper_can_override_normalized_user() {
    let provider = PolarProvider::new(PolarOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("polar-client")),
            ..ProviderOptions::default()
        },
        map_profile_to_user: Some(Arc::new(|profile| {
            let mut user = PolarProvider::map_profile(profile.clone()).user;
            user.name = Some("Mapped User".to_owned());
            user.email_verified = true;
            user
        })),
    });

    let mapped = provider.map_user_info(PolarProfile {
        id: "polar-user".to_owned(),
        email: "ada@example.com".to_owned(),
        username: "ada_dev".to_owned(),
        ..PolarProfile::default()
    });

    assert_eq!(mapped.user.name.as_deref(), Some("Mapped User"));
    assert!(mapped.user.email_verified);
}

#[tokio::test]
async fn polar_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = PolarProvider::new(PolarOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("polar-client")),
            ..ProviderOptions::default()
        },
        ..PolarOptions::default()
    });

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
