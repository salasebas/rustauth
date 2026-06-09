use openauth_oauth::oauth2::{ClientId, OAuthError, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::advanced::vk::{
    vk, VkAuthorizationUrlRequest, VkProfile, VkProfileUser, VkProvider, VK_AUTHORIZATION_ENDPOINT,
    VK_ID, VK_NAME, VK_TOKEN_ENDPOINT,
};

#[test]
fn vk_provider_exposes_upstream_metadata() {
    let provider = vk(VkOptionsFixture::default().into_options());

    assert_eq!(provider.id(), VK_ID);
    assert_eq!(provider.name(), VK_NAME);
}

#[test]
fn vk_authorization_url_uses_upstream_endpoint_and_default_scopes() -> Result<(), OAuthError> {
    let provider = vk(VkOptionsFixture::default().into_options());

    let url = provider.create_authorization_url(VkAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        ..VkAuthorizationUrlRequest::default()
    })?;

    assert!(url.as_str().starts_with(VK_AUTHORIZATION_ENDPOINT));
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(query_value(&url, "client_id"), Some("vk-client".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/callback".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(query_value(&url, "scope"), Some("email phone".to_owned()));
    Ok(())
}

#[test]
fn vk_authorization_url_uses_default_configured_and_request_scopes() -> Result<(), OAuthError> {
    let provider = vk(VkOptionsFixture {
        scope: vec!["friends".to_owned()],
        ..VkOptionsFixture::default()
    }
    .into_options());

    let url = provider.create_authorization_url(VkAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["groups".to_owned()],
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("email phone friends groups".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
    Ok(())
}

#[test]
fn vk_authorization_url_can_disable_default_scope() -> Result<(), OAuthError> {
    let provider = vk(VkOptionsFixture {
        scope: vec!["friends".to_owned()],
        disable_default_scope: true,
    }
    .into_options());

    let url = provider.create_authorization_url(VkAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        ..VkAuthorizationUrlRequest::default()
    })?;

    assert_eq!(query_value(&url, "scope"), Some("friends".to_owned()));
    Ok(())
}

#[test]
fn vk_authorization_code_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = vk(VkOptionsFixture::default().into_options());

    let request = provider.create_authorization_code_request(
        "code-1",
        Some("01234567890123456789012345678901234567890123456789".to_owned()),
        "https://app.example.com/auth/callback",
        Some("device-1".to_owned()),
    )?;

    assert_eq!(provider.token_endpoint(), VK_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("code-1"));
    assert_eq!(
        request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("device_id"), Some("device-1"));
    assert_eq!(request.form_value("client_id"), Some("vk-client"));
    assert_eq!(request.form_value("client_secret"), Some("vk-secret"));
    assert_eq!(request.form_value("client_key"), Some("vk-client-key"));
    Ok(())
}

#[test]
fn vk_refresh_access_token_request_matches_upstream_form_contract() -> Result<(), OAuthError> {
    let provider = vk(VkOptionsFixture::default().into_options());

    let request = provider.refresh_access_token_request("refresh-1")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-1"));
    assert_eq!(request.form_value("client_id"), Some("vk-client"));
    assert_eq!(request.form_value("client_secret"), Some("vk-secret"));
    assert_eq!(request.form_value("client_key"), Some("vk-client-key"));
    Ok(())
}

#[test]
fn vk_profile_maps_to_unverified_user_info() {
    let profile = profile_with_email(Some("ada@example.com"));

    let info = VkProvider::user_info_from_profile(profile);
    assert!(info.is_some());
    let Some(info) = info else {
        return;
    };

    assert_eq!(info.user.id, "vk-user-1");
    assert_eq!(info.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        info.user.image.as_deref(),
        Some("https://cdn.example.com/ada.png")
    );
    assert!(!info.user.email_verified);
    assert_eq!(info.data.user.birthday, "1815-12-10");
    assert_eq!(info.data.user.sex, Some(1));
}

#[test]
fn vk_profile_without_email_returns_none() {
    let profile = profile_with_email(None);

    assert_eq!(VkProvider::user_info_from_profile(profile), None);
}

#[tokio::test]
async fn vk_get_user_info_returns_none_when_access_token_is_missing() -> Result<(), OAuthError> {
    let provider = vk(VkOptionsFixture::default().into_options());

    let info = provider
        .get_user_info(&openauth_oauth::oauth2::OAuth2Tokens::default())
        .await?;

    assert!(info.is_none());
    Ok(())
}

fn profile_with_email(email: Option<&str>) -> VkProfile {
    VkProfile {
        user: VkProfileUser {
            user_id: "vk-user-1".to_owned(),
            first_name: "Ada".to_owned(),
            last_name: "Lovelace".to_owned(),
            email: email.map(str::to_owned),
            phone: Some(123456789),
            avatar: Some("https://cdn.example.com/ada.png".to_owned()),
            sex: Some(1),
            verified: Some(true),
            birthday: "1815-12-10".to_owned(),
        },
    }
}

#[derive(Debug, Default)]
struct VkOptionsFixture {
    scope: Vec<String>,
    disable_default_scope: bool,
}

impl VkOptionsFixture {
    fn into_options(self) -> openauth_social_providers::advanced::vk::VkOptions {
        openauth_social_providers::advanced::vk::VkOptions {
            oauth: ProviderOptions {
                client_id: Some(ClientId::from("vk-client")),
                client_secret: Some("vk-secret".to_owned()),
                client_key: Some("vk-client-key".to_owned()),
                scope: self.scope,
                disable_default_scope: self.disable_default_scope,
                ..ProviderOptions::default()
            },
        }
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
