#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use std::pin::Pin;
use std::sync::Arc;

use openauth_oauth::oauth2::{ClientId, OAuth2Tokens, OAuthProviderContract, ProviderOptions};
use openauth_social_providers::advanced::salesforce::{
    salesforce, SalesforceAuthorizationUrlRequest, SalesforceEnvironment, SalesforceOptions,
    SalesforcePhotos, SalesforceProfile, SalesforceUserInfo,
    SALESFORCE_PRODUCTION_AUTHORIZATION_ENDPOINT, SALESFORCE_PRODUCTION_TOKEN_ENDPOINT,
    SALESFORCE_PRODUCTION_USERINFO_ENDPOINT, SALESFORCE_SANDBOX_AUTHORIZATION_ENDPOINT,
    SALESFORCE_SANDBOX_TOKEN_ENDPOINT, SALESFORCE_SANDBOX_USERINFO_ENDPOINT,
};

#[test]
fn salesforce_provider_exposes_upstream_metadata_and_production_endpoints() {
    let provider = salesforce(salesforce_options());

    assert_eq!(provider.id(), "salesforce");
    assert_eq!(provider.name(), "Salesforce");
    assert_eq!(
        provider.authorization_endpoint(),
        SALESFORCE_PRODUCTION_AUTHORIZATION_ENDPOINT
    );
    assert_eq!(
        provider.token_endpoint(),
        SALESFORCE_PRODUCTION_TOKEN_ENDPOINT
    );
    assert_eq!(
        provider.userinfo_endpoint(),
        SALESFORCE_PRODUCTION_USERINFO_ENDPOINT
    );
}

#[test]
fn salesforce_sandbox_environment_uses_test_salesforce_endpoints() {
    let provider = salesforce(SalesforceOptions {
        environment: SalesforceEnvironment::Sandbox,
        ..salesforce_options()
    });

    assert_eq!(
        provider.authorization_endpoint(),
        SALESFORCE_SANDBOX_AUTHORIZATION_ENDPOINT
    );
    assert_eq!(provider.token_endpoint(), SALESFORCE_SANDBOX_TOKEN_ENDPOINT);
    assert_eq!(
        provider.userinfo_endpoint(),
        SALESFORCE_SANDBOX_USERINFO_ENDPOINT
    );
}

#[test]
fn salesforce_login_url_overrides_all_oauth_endpoints() {
    let provider = salesforce(SalesforceOptions {
        login_url: Some("acme.my.salesforce.com".to_owned()),
        ..salesforce_options()
    });

    assert_eq!(
        provider.authorization_endpoint(),
        "https://acme.my.salesforce.com/services/oauth2/authorize"
    );
    assert_eq!(
        provider.token_endpoint(),
        "https://acme.my.salesforce.com/services/oauth2/token"
    );
    assert_eq!(
        provider.userinfo_endpoint(),
        "https://acme.my.salesforce.com/services/oauth2/userinfo"
    );
}

#[test]
fn salesforce_authorization_url_uses_default_scopes_custom_scopes_and_pkce(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = salesforce_options();
    options.oauth.scope = vec!["refresh_token".to_owned()];
    let provider = salesforce(options);

    let url = provider.create_authorization_url(SalesforceAuthorizationUrlRequest {
        state: "state-1".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["api".to_owned()],
    })?;

    assert_eq!(
        url.as_str().split('?').next(),
        Some(SALESFORCE_PRODUCTION_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("openid email profile refresh_token api".to_owned())
    );
    assert_eq!(
        query_value(&url, "client_id"),
        Some("salesforce-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-1".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/auth/callback".to_owned())
    );
    assert_eq!(
        query_value(&url, "code_challenge_method"),
        Some("S256".to_owned())
    );
    assert!(query_value(&url, "code_challenge").is_some());
    Ok(())
}

#[test]
fn salesforce_authorization_url_can_disable_default_scopes_and_override_redirect(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = salesforce(SalesforceOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("salesforce-client")),
            client_secret: Some("salesforce-secret".to_owned()),
            redirect_uri: Some("https://auth.example.com/salesforce/callback".to_owned()),
            disable_default_scope: true,
            scope: vec!["refresh_token".to_owned()],
            ..ProviderOptions::default()
        },
        ..SalesforceOptions::default()
    });

    let url = provider.create_authorization_url(SalesforceAuthorizationUrlRequest {
        state: "state-2".to_owned(),
        redirect_uri: "https://app.example.com/auth/callback".to_owned(),
        code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
        scopes: vec!["api".to_owned()],
    })?;

    assert_eq!(
        query_value(&url, "scope"),
        Some("refresh_token api".to_owned())
    );
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://auth.example.com/salesforce/callback".to_owned())
    );
    Ok(())
}

#[test]
fn salesforce_authorization_url_requires_client_id_and_code_verifier() {
    let provider = salesforce(SalesforceOptions::default());
    let error = provider
        .create_authorization_url(SalesforceAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            scopes: Vec::new(),
        })
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "missing OAuth provider option `client_id`"
    );

    let provider = salesforce(SalesforceOptions {
        oauth: ProviderOptions {
            client_id: Some(ClientId::from("salesforce-client")),
            client_secret: Some("salesforce-secret".to_owned()),
            ..ProviderOptions::default()
        },
        ..SalesforceOptions::default()
    });
    let error = provider
        .create_authorization_url(SalesforceAuthorizationUrlRequest {
            state: "state-1".to_owned(),
            redirect_uri: "https://app.example.com/auth/callback".to_owned(),
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
fn salesforce_authorization_code_request_matches_upstream_form_contract(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = salesforce(salesforce_options());

    let request = provider.create_authorization_code_request(
        "auth-code",
        Some("01234567890123456789012345678901234567890123456789"),
        "https://app.example.com/auth/callback",
    )?;

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
    assert_eq!(request.form_value("client_id"), Some("salesforce-client"));
    assert_eq!(
        request.form_value("client_secret"),
        Some("salesforce-secret")
    );
    Ok(())
}

#[test]
fn salesforce_authorization_code_request_requires_code_verifier() {
    let provider = salesforce(salesforce_options());

    let error = provider
        .create_authorization_code_request(
            "auth-code",
            None::<String>,
            "https://app.example.com/auth/callback",
        )
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "missing OAuth provider option `code_verifier`"
    );
}

#[test]
fn salesforce_refresh_request_uses_provider_credentials() -> Result<(), Box<dyn std::error::Error>>
{
    let provider = salesforce(salesforce_options());

    let request = provider.create_refresh_access_token_request("refresh-token")?;

    assert_eq!(request.form_value("grant_type"), Some("refresh_token"));
    assert_eq!(request.form_value("refresh_token"), Some("refresh-token"));
    assert_eq!(request.form_value("client_id"), Some("salesforce-client"));
    assert_eq!(
        request.form_value("client_secret"),
        Some("salesforce-secret")
    );
    Ok(())
}

#[test]
fn salesforce_profile_deserializes_and_maps_to_user_defaults(
) -> Result<(), Box<dyn std::error::Error>> {
    let profile: SalesforceProfile = serde_json::from_value(serde_json::json!({
        "sub": "https://login.salesforce.com/id/org-1/user-1",
        "user_id": "user-1",
        "organization_id": "org-1",
        "preferred_username": "ada@example.com",
        "email": "ada@example.com",
        "name": "Ada Lovelace",
        "given_name": "Ada",
        "family_name": "Lovelace",
        "zoneinfo": "America/Monterrey",
        "photos": {
            "picture": "https://example.com/ada-picture.png",
            "thumbnail": "https://example.com/ada-thumb.png"
        }
    }))?;

    let user_info = salesforce(salesforce_options()).map_profile(profile);

    assert_eq!(user_info.user.id, "user-1");
    assert_eq!(user_info.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(user_info.user.email.as_deref(), Some("ada@example.com"));
    assert_eq!(
        user_info.user.image.as_deref(),
        Some("https://example.com/ada-picture.png")
    );
    assert!(!user_info.user.email_verified);
    assert_eq!(user_info.data.organization_id, "org-1");
    Ok(())
}

#[test]
fn salesforce_profile_image_falls_back_to_thumbnail() {
    let user_info = salesforce(salesforce_options()).map_profile(SalesforceProfile {
        photos: Some(SalesforcePhotos {
            picture: None,
            thumbnail: Some("https://example.com/ada-thumb.png".to_owned()),
        }),
        ..salesforce_profile()
    });

    assert_eq!(
        user_info.user.image.as_deref(),
        Some("https://example.com/ada-thumb.png")
    );
}

#[test]
fn salesforce_partial_mapper_overrides_selected_user_fields() {
    let provider = salesforce(SalesforceOptions {
        oauth: provider_options(),
        map_profile_to_user: Some(Arc::new(|profile| {
            let mut patch =
                openauth_social_providers::advanced::salesforce::SalesforceUserPatch::default();
            patch.id = Some(format!("salesforce:{}", profile.user_id));
            patch.email_verified = Some(true);
            patch.image = Some(None);
            patch
        })),
        ..SalesforceOptions::default()
    });

    let user_info = provider.map_profile(salesforce_profile());

    assert_eq!(user_info.user.id, "salesforce:user-1");
    assert!(user_info.user.email_verified);
    assert_eq!(user_info.user.image, None);
    assert_eq!(user_info.user.email.as_deref(), Some("ada@example.com"));
}

#[tokio::test]
async fn salesforce_custom_get_user_info_callback_is_used() -> Result<(), Box<dyn std::error::Error>>
{
    let provider = salesforce(SalesforceOptions {
        oauth: provider_options(),
        get_user_info: Some(Arc::new(|_tokens| {
            Box::pin(async {
                Ok(Some(SalesforceUserInfo {
                    user: openauth_oauth::oauth2::OAuth2UserInfo {
                        id: "custom-user".to_owned(),
                        name: Some("Custom".to_owned()),
                        email: None,
                        image: None,
                        email_verified: true,
                    },
                    data: salesforce_profile(),
                }))
            }) as Pin<Box<_>>
        })),
        ..SalesforceOptions::default()
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
async fn salesforce_custom_refresh_access_token_callback_is_used(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = salesforce(SalesforceOptions {
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
        ..SalesforceOptions::default()
    });

    let tokens = provider.refresh_access_token("refresh-1").await?;

    assert_eq!(tokens.access_token.as_deref(), Some("access-for-refresh-1"));
    assert_eq!(tokens.refresh_token.as_deref(), Some("refresh-1"));
    Ok(())
}

fn salesforce_options() -> SalesforceOptions {
    SalesforceOptions {
        oauth: provider_options(),
        ..SalesforceOptions::default()
    }
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("salesforce-client")),
        client_secret: Some("salesforce-secret".to_owned()),
        ..ProviderOptions::default()
    }
}

fn salesforce_profile() -> SalesforceProfile {
    SalesforceProfile {
        sub: "https://login.salesforce.com/id/org-1/user-1".to_owned(),
        user_id: "user-1".to_owned(),
        organization_id: "org-1".to_owned(),
        preferred_username: Some("ada@example.com".to_owned()),
        email: "ada@example.com".to_owned(),
        email_verified: Some(false),
        name: "Ada Lovelace".to_owned(),
        given_name: Some("Ada".to_owned()),
        family_name: Some("Lovelace".to_owned()),
        zoneinfo: Some("America/Monterrey".to_owned()),
        photos: Some(SalesforcePhotos {
            picture: Some("https://example.com/ada-picture.png".to_owned()),
            thumbnail: Some("https://example.com/ada-thumb.png".to_owned()),
        }),
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}
