use std::sync::Arc;

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions};
use openauth_social_providers::advanced::linear::{
    linear, LinearAuthorizationUrlRequest, LinearOptions, LinearUser,
    LinearValidateAuthorizationCodeRequest, LINEAR_AUTHORIZATION_ENDPOINT, LINEAR_ID, LINEAR_NAME,
    LINEAR_TOKEN_ENDPOINT,
};

#[test]
fn linear_provider_exposes_upstream_metadata() {
    let provider = linear(linear_options());

    assert_eq!((provider.id(), provider.name()), (LINEAR_ID, LINEAR_NAME));
}

#[test]
fn linear_authorization_url_uses_upstream_defaults() -> Result<(), OAuthError> {
    let mut options = linear_options();
    options.oauth.scope = vec!["issues:create".to_owned()];
    let provider = linear(options);

    let url = provider.create_authorization_url(LinearAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["comments:create".to_owned()],
        login_hint: Some("ada@example.com".to_owned()),
    })?;

    assert!(url.as_str().starts_with(LINEAR_AUTHORIZATION_ENDPOINT));
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("linear-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "login_hint"),
        Some("ada@example.com".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("read issues:create comments:create".to_owned())
    );
    Ok(())
}

#[test]
fn linear_authorization_url_can_disable_default_scope() -> Result<(), OAuthError> {
    let mut options = linear_options();
    options.oauth.disable_default_scope = true;
    options.oauth.scope = vec!["issues:create".to_owned()];
    let provider = linear(options);

    let url = provider.create_authorization_url(LinearAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["comments:create".to_owned()],
        login_hint: None,
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("issues:create comments:create".to_owned())
    );
    Ok(())
}

#[test]
fn linear_authorization_code_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = linear(linear_options());

    let request = provider.authorization_code_request(LinearValidateAuthorizationCodeRequest {
        code: "code-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
    })?;

    assert_eq!(provider.token_endpoint(), LINEAR_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("client_id"), Some("linear-client"));
    assert_eq!(request.form_value("client_secret"), Some("linear-secret"));
    assert_eq!(request.form_value("client_key"), Some("linear-key"));
    assert_eq!(request.header("accept"), Some("application/json"));
    Ok(())
}

#[test]
fn linear_refresh_token_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = linear(linear_options());

    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_id"), Some("linear-client"));
    assert_eq!(request.form_value("client_secret"), Some("linear-secret"));
    assert_eq!(request.form_value("client_key"), Some("linear-key"));
    Ok(())
}

#[test]
fn linear_user_maps_to_unverified_user_info() {
    let user = linear_user();

    let mapped = user.to_user_info();

    assert!(!mapped.email_verified);
    assert_eq!(mapped.id, "linear-user-1");
    assert_eq!(mapped.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        mapped.image.as_deref(),
        Some("https://uploads.linear.app/ada.png")
    );
}

#[test]
fn linear_custom_mapper_can_override_user_info_fields() {
    let provider = linear(LinearOptions {
        oauth: provider_options(),
        map_profile_to_user: Some(Arc::new(|profile| OAuth2UserInfo {
            id: format!("linear:{}", profile.id),
            name: Some(profile.name.to_uppercase()),
            email: Some(profile.email.clone()),
            image: None,
            email_verified: true,
        })),
    });

    let mapped = provider.user_info_from_profile(linear_user());

    assert_eq!(mapped.user.id, "linear:linear-user-1");
    assert_eq!(mapped.user.name.as_deref(), Some("ADA LOVELACE"));
    assert!(mapped.user.email_verified);
    assert_eq!(mapped.user.image, None);
}

#[tokio::test]
async fn linear_get_user_info_returns_none_without_access_token() -> Result<(), OAuthError> {
    let provider = linear(linear_options());

    let user_info = provider.get_user_info(&OAuth2Tokens::default()).await?;

    assert_eq!(user_info, None);
    Ok(())
}

fn linear_options() -> LinearOptions {
    LinearOptions {
        oauth: provider_options(),
        map_profile_to_user: None,
    }
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("linear-client")),
        client_secret: Some("linear-secret".to_owned()),
        client_key: Some("linear-key".to_owned()),
        ..ProviderOptions::default()
    }
}

fn linear_user() -> LinearUser {
    LinearUser {
        id: "linear-user-1".to_owned(),
        name: "Ada Lovelace".to_owned(),
        email: "ada@example.com".to_owned(),
        avatar_url: Some("https://uploads.linear.app/ada.png".to_owned()),
        active: true,
        created_at: "2026-01-01T00:00:00.000Z".to_owned(),
        updated_at: "2026-01-02T00:00:00.000Z".to_owned(),
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
