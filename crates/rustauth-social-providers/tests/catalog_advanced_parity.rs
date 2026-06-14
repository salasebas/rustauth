#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "parity tests intentionally fail fast with contextual setup errors"
)]

use std::collections::BTreeMap;

use rustauth_oauth::oauth2::{OAuthError, SocialAuthorizationUrlRequest, SocialOAuthProvider};
use rustauth_social_providers::advanced;
use rustauth_social_providers::providers::{
    apple, discord, google, microsoft, microsoft_entra_id, salesforce,
};
use rustauth_social_providers::{ProviderId, SocialProviderConfig};

const CODE_VERIFIER: &str = "01234567890123456789012345678901234567890123456789";

fn test_config() -> SocialProviderConfig {
    SocialProviderConfig::new("parity-client-id", "parity-client-secret")
}

fn authorization_url<P: SocialOAuthProvider>(provider: &P) -> url::Url {
    SocialOAuthProvider::create_authorization_url(
        provider,
        SocialAuthorizationUrlRequest {
            state: "parity-state".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            code_verifier: Some(CODE_VERIFIER.to_owned()),
            ..SocialAuthorizationUrlRequest::default()
        },
    )
    .expect("authorization URL should build")
}

fn query_params(url: &url::Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn assert_catalog_matches_advanced(
    provider_id: &str,
    catalog_url: url::Url,
    advanced_url: url::Url,
) {
    assert_eq!(
        catalog_url.as_str().split('?').next(),
        advanced_url.as_str().split('?').next(),
        "{provider_id} authorization endpoints should match"
    );
    assert_eq!(
        query_params(&catalog_url),
        query_params(&advanced_url),
        "{provider_id} authorization query params should match"
    );
}

#[test]
fn google_catalog_matches_advanced_defaults() -> Result<(), OAuthError> {
    let config = test_config();
    let catalog = google(config.clone())?;
    let advanced = advanced::google::google(advanced::google::GoogleOptions {
        oauth: config.into_provider_options(),
        ..Default::default()
    })?;

    assert_catalog_matches_advanced(
        "google",
        authorization_url(&catalog),
        authorization_url(&advanced),
    );
    Ok(())
}

#[test]
fn discord_catalog_matches_advanced_defaults() -> Result<(), OAuthError> {
    let config = test_config();
    let catalog = discord(config.clone())?;
    let advanced = advanced::discord::discord(advanced::discord::DiscordOptions {
        oauth: config.into_provider_options(),
        ..Default::default()
    })?;

    assert_catalog_matches_advanced(
        "discord",
        authorization_url(&catalog),
        authorization_url(&advanced),
    );
    Ok(())
}

#[test]
fn apple_catalog_matches_advanced_defaults() -> Result<(), OAuthError> {
    let config = test_config();
    let catalog = apple(config.clone())?;
    let advanced = advanced::apple::apple(advanced::apple::AppleOptions {
        oauth: config.into_provider_options(),
        ..Default::default()
    })?;

    assert_catalog_matches_advanced(
        "apple",
        authorization_url(&catalog),
        authorization_url(&advanced),
    );
    Ok(())
}

#[test]
fn microsoft_catalog_matches_advanced_defaults() -> Result<(), OAuthError> {
    let config = test_config();
    let catalog = microsoft(config.clone())?;
    let advanced = advanced::microsoft_entra_id::microsoft_entra_id(
        advanced::microsoft_entra_id::MicrosoftEntraIdOptions {
            oauth: config.into_provider_options(),
            ..Default::default()
        },
    )?;

    assert_catalog_matches_advanced(
        "microsoft",
        authorization_url(&catalog),
        authorization_url(&advanced),
    );
    Ok(())
}

#[test]
fn microsoft_alias_matches_microsoft_entra_id_factory() -> Result<(), OAuthError> {
    let config = test_config();
    let from_alias = microsoft(config.clone())?;
    let from_entra = microsoft_entra_id(config)?;

    assert_eq!(from_alias.id(), ProviderId::MICROSOFT.as_str());
    assert_catalog_matches_advanced(
        "microsoft",
        authorization_url(&from_alias),
        authorization_url(&from_entra),
    );
    Ok(())
}

#[test]
fn salesforce_catalog_matches_advanced_defaults() -> Result<(), OAuthError> {
    let config = test_config();
    let catalog = salesforce(config.clone())?;
    let advanced = advanced::salesforce::salesforce(advanced::salesforce::SalesforceOptions {
        oauth: config.into_provider_options(),
        ..Default::default()
    })?;

    assert_catalog_matches_advanced(
        "salesforce",
        authorization_url(&catalog),
        authorization_url(&advanced),
    );
    Ok(())
}
