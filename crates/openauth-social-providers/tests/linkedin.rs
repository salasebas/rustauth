#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::field_reassign_with_default,
    reason = "provider tests intentionally fail fast with contextual setup errors"
)]

use openauth_oauth::oauth2::{ClientId, ProviderOptions};
use openauth_social_providers::advanced::linkedin::{
    linkedin, LinkedInAuthorizationUrlRequest, LinkedInLocale, LinkedInProfile, LinkedInProvider,
    LINKEDIN_AUTHORIZATION_ENDPOINT, LINKEDIN_ID, LINKEDIN_NAME,
};

#[test]
fn linkedin_provider_exposes_upstream_metadata() {
    let provider = linkedin(provider_options());

    assert_eq!(provider.id(), LINKEDIN_ID);
    assert_eq!(provider.name(), LINKEDIN_NAME);
}

#[test]
fn linkedin_authorization_url_uses_upstream_default_scopes() {
    let provider = linkedin(ProviderOptions {
        scope: vec!["r_liteprofile".to_owned()],
        ..provider_options()
    });

    let url = provider
        .create_authorization_url(LinkedInAuthorizationUrlRequest {
            state: "state-token".to_owned(),
            redirect_uri: "https://app.example.com/callback/linkedin".to_owned(),
            scopes: vec!["w_member_social".to_owned()],
            login_hint: Some("ada@example.com".to_owned()),
        })
        .expect("authorization URL should build");

    assert_eq!(
        url.as_str().split('?').next(),
        Some(LINKEDIN_AUTHORIZATION_ENDPOINT)
    );
    assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
    assert_eq!(
        query_value(&url, "client_id"),
        Some("linkedin-client".to_owned())
    );
    assert_eq!(query_value(&url, "state"), Some("state-token".to_owned()));
    assert_eq!(
        query_value(&url, "redirect_uri"),
        Some("https://app.example.com/callback/linkedin".to_owned())
    );
    assert_eq!(
        query_value(&url, "scope"),
        Some("profile email openid r_liteprofile w_member_social".to_owned())
    );
    assert_eq!(
        query_value(&url, "login_hint"),
        Some("ada@example.com".to_owned())
    );
}

#[test]
fn linkedin_authorization_url_can_disable_default_scopes() {
    let provider = linkedin(ProviderOptions {
        disable_default_scope: true,
        scope: vec!["r_liteprofile".to_owned()],
        ..provider_options()
    });

    let url = provider
        .create_authorization_url(LinkedInAuthorizationUrlRequest {
            state: "state-token".to_owned(),
            redirect_uri: "https://app.example.com/callback/linkedin".to_owned(),
            scopes: vec!["w_member_social".to_owned()],
            login_hint: None,
        })
        .expect("authorization URL should build");

    assert_eq!(
        query_value(&url, "scope"),
        Some("r_liteprofile w_member_social".to_owned())
    );
}

#[test]
fn linkedin_authorization_code_request_matches_oauth_form_contract() {
    let provider = linkedin(ProviderOptions {
        client_secret: Some("linkedin-secret".to_owned()),
        ..provider_options()
    });

    let request = provider
        .authorization_code_request("auth-code", "https://app.example.com/callback/linkedin")
        .expect("authorization code request should build");

    assert_eq!(request.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(request.form_value("code"), Some("auth-code"));
    assert_eq!(
        request.form_value("redirect_uri"),
        Some("https://app.example.com/callback/linkedin")
    );
    assert_eq!(request.form_value("client_id"), Some("linkedin-client"));
    assert_eq!(request.form_value("client_secret"), Some("linkedin-secret"));
    assert_eq!(request.header("accept"), Some("application/json"));
}

#[test]
fn linkedin_profile_maps_optional_claims_to_normalized_user_info() {
    let profile = LinkedInProfile {
        sub: "linkedin-user-1".to_owned(),
        name: "Ada Lovelace".to_owned(),
        given_name: "Ada".to_owned(),
        family_name: "Lovelace".to_owned(),
        picture: Some("https://media.example.com/ada.jpg".to_owned()),
        locale: Some(LinkedInLocale {
            country: "US".to_owned(),
            language: "en".to_owned(),
        }),
        email: Some("ada@example.com".to_owned()),
        email_verified: Some(true),
    };

    let mapped = LinkedInProvider::user_info_from_profile(profile);

    assert_eq!(mapped.user.id, "linkedin-user-1");
    assert_eq!(mapped.user.name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(mapped.user.email.as_deref(), Some("ada@example.com"));
    assert!(mapped.user.email_verified);
    assert_eq!(
        mapped.user.image.as_deref(),
        Some("https://media.example.com/ada.jpg")
    );
    assert_eq!(
        mapped
            .data
            .locale
            .as_ref()
            .map(|locale| locale.country.as_str()),
        Some("US")
    );
}

#[test]
fn linkedin_profile_defaults_missing_email_verification_to_false() {
    let profile = LinkedInProfile {
        sub: "linkedin-user-2".to_owned(),
        name: "Grace Hopper".to_owned(),
        given_name: "Grace".to_owned(),
        family_name: "Hopper".to_owned(),
        picture: None,
        locale: None,
        email: None,
        email_verified: None,
    };

    let mapped = LinkedInProvider::user_info_from_profile(profile);

    assert_eq!(mapped.user.id, "linkedin-user-2");
    assert_eq!(mapped.user.email, None);
    assert_eq!(mapped.user.image, None);
    assert!(!mapped.user.email_verified);
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::from("linkedin-client")),
        ..ProviderOptions::default()
    }
}

fn query_value(url: &url::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(existing, _)| existing == key)
        .map(|(_, value)| value.into_owned())
}
