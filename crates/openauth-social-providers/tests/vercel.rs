#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use std::sync::Arc;

use openauth_oauth::oauth2::{ClientId, OAuthError, ProviderOptions};
use openauth_social_providers::advanced::vercel::{
    vercel, VercelAuthorizationUrlRequest, VercelOptions, VercelProfile, VercelUserPatch,
    VERCEL_AUTHORIZATION_ENDPOINT, VERCEL_ID, VERCEL_NAME, VERCEL_TOKEN_ENDPOINT,
};

#[test]
fn vercel_provider_exposes_upstream_metadata() {
    let provider = vercel(vercel_options());

    assert_eq!((provider.id(), provider.name()), (VERCEL_ID, VERCEL_NAME));
}

#[test]
fn vercel_authorization_url_requires_pkce_and_uses_upstream_endpoint() -> Result<(), OAuthError> {
    let provider = vercel(vercel_options());
    let url = provider.create_authorization_url(VercelAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/vercel".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: Vec::new(),
    })?;

    assert!(url.as_str().starts_with(VERCEL_AUTHORIZATION_ENDPOINT));
    assert_eq!(query_value(&url, "scope"), None);
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert_eq!(
        query_value(&url, "client_id"),
        Some("vercel-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    Ok(())
}

#[test]
fn vercel_authorization_url_appends_provider_scopes_before_request_scopes() -> Result<(), OAuthError>
{
    let provider = vercel(VercelOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("vercel-client")),
            client_secret: Some("vercel-secret".to_owned()),
            scope: vec!["openid".to_owned(), "email".to_owned()],
            ..ProviderOptions::default()
        },
        map_profile_to_user: None,
        ..VercelOptions::default()
    });

    let url = provider.create_authorization_url(VercelAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback/vercel".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["offline_access".to_owned()],
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("openid email offline_access".to_owned())
    );
    Ok(())
}

#[test]
fn vercel_authorization_url_requires_code_verifier() {
    let provider = vercel(vercel_options());

    let error = provider
        .create_authorization_url(VercelAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback/vercel".to_owned(),
            code_verifier: None,
            scopes: Vec::new(),
        })
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "missing OAuth provider option `code_verifier`"
    );
}

#[test]
fn vercel_authorization_code_request_requires_code_verifier() {
    let provider = vercel(vercel_options());

    let error = provider
        .authorization_code_request(
            "code-1",
            None::<String>,
            "https://app.example.com/auth/callback/vercel",
        )
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "missing OAuth provider option `code_verifier`"
    );
}

#[test]
fn vercel_authorization_code_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = vercel(vercel_options());
    let request = provider.authorization_code_request(
        "code-1",
        Some("01234567890123456789012345678901234567890123456789"),
        "https://app.example.com/auth/callback/vercel",
    )?;

    assert_eq!(provider.token_endpoint(), VERCEL_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback/vercel")
    );
    assert_eq!(request.form_value("client_id"), Some("vercel-client"));
    assert_eq!(request.form_value("client_secret"), Some("vercel-secret"));
    Ok(())
}

#[test]
fn vercel_profile_maps_name_preferred_username_and_email_verified() {
    let provider = vercel(vercel_options());

    let named = provider.map_profile(vercel_profile(Some("Vercel User"), Some("verceluser")));
    assert_eq!(named.user.name.as_deref(), Some("Vercel User"));
    assert!(named.user.email_verified);

    let fallback = provider.map_profile(vercel_profile(None, Some("cooldev")));
    assert_eq!(fallback.user.name.as_deref(), Some("cooldev"));

    let empty = provider.map_profile(vercel_profile(None, None));
    assert_eq!(empty.user.name.as_deref(), Some(""));
}

#[test]
fn vercel_custom_mapper_can_override_user_info_fields() {
    let provider = vercel(VercelOptions {
        oauth: provider_options(),
        map_profile_to_user: Some(Arc::new(|profile| VercelUserPatch {
            id: Some(format!("vercel:{}", profile.sub)),
            name: Some(Some("Custom Vercel User".to_owned())),
            image: Some(None),
            ..VercelUserPatch::default()
        })),
        ..VercelOptions::default()
    });

    let mapped = provider.map_profile(vercel_profile(Some("Vercel User"), Some("verceluser")));

    assert_eq!(mapped.user.id, "vercel:vercel-user-1");
    assert_eq!(mapped.user.name.as_deref(), Some("Custom Vercel User"));
    assert_eq!(mapped.user.image, None);
}

fn vercel_options() -> VercelOptions {
    VercelOptions {
        oauth: provider_options(),
        map_profile_to_user: None,
        ..VercelOptions::default()
    }
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("vercel-client")),
        client_secret: Some("vercel-secret".to_owned()),
        ..ProviderOptions::default()
    }
}

fn vercel_profile(name: Option<&str>, preferred_username: Option<&str>) -> VercelProfile {
    VercelProfile {
        sub: "vercel-user-1".to_owned(),
        name: name.map(str::to_owned),
        preferred_username: preferred_username.map(str::to_owned),
        email: Some("ada@example.com".to_owned()),
        email_verified: Some(true),
        picture: Some("https://vercel.com/avatar.png".to_owned()),
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
