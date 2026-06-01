#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use std::pin::Pin;
use std::sync::Arc;

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::huggingface::{
    huggingface, HuggingFaceAuthorizationUrlRequest, HuggingFaceOptions, HuggingFaceOrg,
    HuggingFaceOrgEnterprise, HuggingFaceProfile, HuggingFaceProvider, HuggingFaceResourceGroup,
    HuggingFaceRole, HuggingFaceUserInfo, HUGGINGFACE_AUTHORIZATION_ENDPOINT, HUGGINGFACE_ID,
    HUGGINGFACE_NAME, HUGGINGFACE_TOKEN_ENDPOINT,
};

#[test]
fn huggingface_provider_exposes_upstream_metadata() {
    let provider = huggingface(provider_options());

    assert_eq!(
        (provider.id(), provider.name()),
        (HUGGINGFACE_ID, HUGGINGFACE_NAME)
    );
}

#[test]
fn huggingface_authorization_url_uses_default_scopes_custom_scopes_and_pkce(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = huggingface(ProviderOptions {
        client_id: Some(ClientId::from("hf-client")),
        scope: vec!["inference-api".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider.create_authorization_url(HuggingFaceAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["read-repos".to_owned()],
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some(HUGGINGFACE_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid profile email inference-api read-repos".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert_eq!(query_value(&url, "client_id"), Some("hf-client".to_owned()));
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    Ok(())
}

#[test]
fn huggingface_authorization_url_can_disable_default_scopes_and_override_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = huggingface(ProviderOptions {
        client_id: Some(ClientId::from("hf-client")),
        redirect_uri: Some("https://auth.example.com/huggingface/callback".to_owned()),
        disable_default_scope: true,
        scope: vec!["profile".to_owned()],
        ..ProviderOptions::default()
    });

    let url = provider.create_authorization_url(HuggingFaceAuthorizationUrlRequest {
        state: "state-2".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        scopes: vec!["email".to_owned()],
        ..HuggingFaceAuthorizationUrlRequest::default()
    })?;

    assert_eq!(query_value(&url, "scope"), Some("profile email".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/huggingface/callback".to_owned())
    );
    Ok(())
}

#[test]
fn huggingface_authorization_code_request_matches_upstream_form_contract(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = huggingface(provider_options());

    let request = provider.create_authorization_code_request(
        "auth-code",
        Some("01234567890123456789012345678901234567890123456789"),
        "https://app.example.com/auth/callback",
    )?;

    assert_eq!(provider.token_endpoint(), HUGGINGFACE_TOKEN_ENDPOINT);
    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("auth-code"));
    assert_eq!(
        request.form_value("code_verifier"),
        Some("01234567890123456789012345678901234567890123456789")
    );
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/auth/callback")
    );
    assert_eq!(request.form_value("client_id"), Some("hf-client"));
    assert_eq!(request.form_value("client_secret"), Some("hf-secret"));
    Ok(())
}

#[test]
fn huggingface_refresh_request_uses_provider_credentials() -> Result<(), Box<dyn std::error::Error>>
{
    let provider = huggingface(provider_options());

    let request = provider.create_refresh_access_token_request("refresh-token")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-token"));
    assert_eq!(request.form_value("client_id"), Some("hf-client"));
    assert_eq!(request.form_value("client_secret"), Some("hf-secret"));
    Ok(())
}

#[test]
fn huggingface_profile_deserializes_orgs_and_maps_to_user_defaults(
) -> Result<(), Box<dyn std::error::Error>> {
    let profile: HuggingFaceProfile = serde_json::from_value(serde_json::json!({
        "sub": "user-1",
        "name": "",
        "preferred_username": "ada",
        "profile": "https://huggingface.co/ada",
        "picture": "https://cdn.example.com/ada.png",
        "email": "ada@example.com",
        "isPro": true,
        "canPay": false,
        "orgs": [{
            "sub": "org-1",
            "name": "OpenAuth",
            "picture": "https://cdn.example.com/org.png",
            "preferred_username": "openauth",
            "isEnterprise": "plus",
            "canPay": true,
            "roleInOrg": "admin",
            "pendingSSO": false,
            "missingMFA": true,
            "resourceGroups": [{
                "sub": "resource-1",
                "name": "Production",
                "role": "write"
            }]
        }]
    }))?;

    let user_info = HuggingFaceProvider::user_info_from_profile(profile);

    assert_eq!(user_info.user.id, "user-1");
    assert_eq!(user_info.user.name.as_deref(), Some("ada"));
    assert_eq!(user_info.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        user_info.user.image.as_deref(),
        Some("https://cdn.example.com/ada.png")
    );
    assert!(!user_info.user.email_verified);
    assert_eq!(user_info.data.orgs.as_ref().map(Vec::len), Some(1));
    assert_eq!(
        user_info
            .data
            .orgs
            .as_ref()
            .and_then(|orgs| orgs.first())
            .map(|org| org.is_enterprise.clone()),
        Some(HuggingFaceOrgEnterprise::Plus)
    );
    Ok(())
}

#[test]
fn huggingface_partial_mapper_overrides_selected_user_fields() {
    let provider = huggingface(HuggingFaceOptions {
        oauth: provider_options(),
        map_profile_to_user: Some(Arc::new(|profile| {
            let mut patch = openauth_social_providers::huggingface::HuggingFaceUserPatch::default();
            patch.name = Some(Some(format!("{} on HF", profile.preferred_username)));
            patch.email_verified = Some(true);
            patch
        })),
        ..HuggingFaceOptions::default()
    });

    let user_info = provider.map_profile(profile_without_verified_email());

    assert_eq!(user_info.user.name.as_deref(), Some("ada on HF"));
    assert_eq!(user_info.user.email.as_deref(), Some("ada@example.com"));
    assert!(user_info.user.email_verified);
    assert_eq!(user_info.data.sub, "user-1");
}

#[tokio::test]
async fn huggingface_custom_get_user_info_callback_is_used(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = huggingface(HuggingFaceOptions {
        oauth: provider_options(),
        get_user_info: Some(Arc::new(|_token| {
            Box::pin(async {
                Ok(Some(HuggingFaceUserInfo {
                    user: openauth_oauth::oauth2::OAuth2UserInfo {
                        id: "custom-user".to_owned(),
                        name: Some("Custom".to_owned()),
                        email: None,
                        image: None,
                        email_verified: true,
                    },
                    data: profile_without_verified_email(),
                }))
            }) as Pin<Box<_>>
        })),
        ..HuggingFaceOptions::default()
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
async fn huggingface_custom_refresh_access_token_callback_is_used(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = huggingface(HuggingFaceOptions {
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
        ..HuggingFaceOptions::default()
    });

    let tokens = provider.refresh_access_token("refresh-1").await?;

    assert_eq!(tokens.access_token.as_deref(), Some("access-for-refresh-1"));
    assert_eq!(tokens.refresh_token.as_deref(), Some("refresh-1"));
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("hf-client")),
        client_secret: Some("hf-secret".to_owned()),
        client_key: Some("hf-key".to_owned()),
        ..ProviderOptions::default()
    }
}

fn profile_without_verified_email() -> HuggingFaceProfile {
    HuggingFaceProfile {
        sub: "user-1".to_owned(),
        name: String::new(),
        preferred_username: "ada".to_owned(),
        profile: "https://huggingface.co/ada".to_owned(),
        picture: "https://cdn.example.com/ada.png".to_owned(),
        website: None,
        email: Some("ada@example.com".to_owned()),
        email_verified: None,
        is_pro: false,
        can_pay: None,
        orgs: Some(vec![HuggingFaceOrg {
            sub: "org-1".to_owned(),
            name: "OpenAuth".to_owned(),
            picture: "https://cdn.example.com/org.png".to_owned(),
            preferred_username: "openauth".to_owned(),
            is_enterprise: HuggingFaceOrgEnterprise::Bool(false),
            can_pay: None,
            role_in_org: Some(HuggingFaceRole::Read),
            pending_sso: None,
            missing_mfa: None,
            resource_groups: Some(vec![HuggingFaceResourceGroup {
                sub: "resource-1".to_owned(),
                name: "Production".to_owned(),
                role: HuggingFaceRole::Write,
            }]),
        }]),
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
