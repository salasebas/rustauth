use openauth_oauth::oauth2::{
    ClientId, OAuthError, SocialAuthorizationUrlRequest, SocialOAuthProvider,
};
use openauth_social_providers::providers::{github, google};
use openauth_social_providers::{
    CognitoPoolConfig, ProviderId, SocialProviderConfig, SocialProviderConfigBuilder, PROVIDER_IDS,
};

#[test]
fn provider_ids_match_registry() {
    assert_eq!(ProviderId::GITHUB.as_str(), "github");
    assert_eq!(ProviderId::MICROSOFT.as_str(), "microsoft");
    assert_eq!(
        PROVIDER_IDS,
        &[
            ProviderId::APPLE.as_str(),
            ProviderId::ATLASSIAN.as_str(),
            ProviderId::COGNITO.as_str(),
            ProviderId::DISCORD.as_str(),
            ProviderId::FACEBOOK.as_str(),
            ProviderId::FIGMA.as_str(),
            ProviderId::GITHUB.as_str(),
            ProviderId::MICROSOFT.as_str(),
            ProviderId::GOOGLE.as_str(),
            ProviderId::HUGGINGFACE.as_str(),
            ProviderId::SLACK.as_str(),
            ProviderId::SPOTIFY.as_str(),
            ProviderId::TWITCH.as_str(),
            ProviderId::TWITTER.as_str(),
            ProviderId::DROPBOX.as_str(),
            ProviderId::KICK.as_str(),
            ProviderId::LINEAR.as_str(),
            ProviderId::LINKEDIN.as_str(),
            ProviderId::GITLAB.as_str(),
            ProviderId::TIKTOK.as_str(),
            ProviderId::REDDIT.as_str(),
            ProviderId::ROBLOX.as_str(),
            ProviderId::SALESFORCE.as_str(),
            ProviderId::VK.as_str(),
            ProviderId::ZOOM.as_str(),
            ProviderId::NOTION.as_str(),
            ProviderId::KAKAO.as_str(),
            ProviderId::NAVER.as_str(),
            ProviderId::LINE.as_str(),
            ProviderId::PAYBIN.as_str(),
            ProviderId::PAYPAL.as_str(),
            ProviderId::POLAR.as_str(),
            ProviderId::RAILWAY.as_str(),
            ProviderId::VERCEL.as_str(),
            ProviderId::WECHAT.as_str(),
        ]
    );
}

#[test]
fn providers_catalog_builds_authorization_urls() -> Result<(), Box<dyn std::error::Error>> {
    let config = SocialProviderConfig::new("client-id", "client-secret");

    let github_provider = github(config.clone());
    assert_eq!(
        SocialOAuthProvider::id(&github_provider),
        ProviderId::GITHUB.as_str()
    );
    let github_url = SocialOAuthProvider::create_authorization_url(
        &github_provider,
        SocialAuthorizationUrlRequest {
            state: "state".to_owned(),
            redirect_uri: "https://app.example.com/callback/github".to_owned(),
            ..SocialAuthorizationUrlRequest::default()
        },
    )?;
    assert_eq!(github_url.host_str(), Some("github.com"));

    let google_provider = google(config);
    assert_eq!(
        SocialOAuthProvider::id(&google_provider),
        ProviderId::GOOGLE.as_str()
    );
    let google_url = SocialOAuthProvider::create_authorization_url(
        &google_provider,
        SocialAuthorizationUrlRequest {
            state: "state".to_owned(),
            redirect_uri: "https://app.example.com/callback/google".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            ..SocialAuthorizationUrlRequest::default()
        },
    )?;
    assert_eq!(google_url.host_str(), Some("accounts.google.com"));

    Ok(())
}

#[test]
fn builder_wires_github_provider_with_extra_scopes() -> Result<(), OAuthError> {
    let provider = github(
        SocialProviderConfig::builder()
            .client_id("client-id")
            .client_secret("client-secret")
            .scope(["repo"])
            .build()?,
    );

    assert_eq!(
        SocialOAuthProvider::id(&provider),
        ProviderId::GITHUB.as_str()
    );
    let options = provider.provider_options();
    assert_eq!(
        options.client_id,
        Some(ClientId::Single("client-id".to_owned()))
    );
    assert_eq!(options.scope, vec!["repo".to_owned()]);
    Ok(())
}

#[test]
fn builder_matches_new_for_provider_options() -> Result<(), OAuthError> {
    let from_new = SocialProviderConfig::new("client-id", "client-secret").into_provider_options();
    let from_builder = SocialProviderConfig::builder()
        .client_id("client-id")
        .client_secret("client-secret")
        .build()?
        .into_provider_options();

    assert_eq!(from_new, from_builder);
    Ok(())
}

#[test]
fn builder_default_is_empty() {
    let builder = SocialProviderConfigBuilder::default();
    assert!(builder.build().is_err());
}

#[test]
fn cognito_pool_config_builds_provider() -> Result<(), Box<dyn std::error::Error>> {
    let provider = openauth_social_providers::providers::cognito(
        SocialProviderConfig::new("client-id", "client-secret"),
        CognitoPoolConfig::new(
            "example.auth.us-east-1.amazoncognito.com",
            "us-east-1",
            "pool-id",
        ),
    )?;

    assert_eq!(provider.id(), ProviderId::COGNITO.as_str());
    Ok(())
}
