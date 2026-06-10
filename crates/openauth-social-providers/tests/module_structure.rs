use openauth_oauth::oauth2::{
    ClientId, OAuth2Tokens, ProviderOptions, SocialAuthorizationUrlRequest, SocialOAuthProvider,
};
use openauth_social_providers::advanced::{
    apple::AppleProvider, atlassian::AtlassianProvider, cognito::CognitoProvider,
    discord::DiscordProvider, dropbox::DropboxProvider, facebook::FacebookProvider, figma::figma,
    figma::FigmaProvider, github::github, github::GitHubProvider, gitlab::GitlabProvider,
    google::google, google::GoogleOptions, google::GoogleProvider,
    huggingface::HuggingFaceProvider, kakao::KakaoProvider, kick::KickProvider, line::LineProvider,
    linear::LinearProvider, linkedin::LinkedInProvider,
    microsoft_entra_id::MicrosoftEntraIdProvider, naver::NaverProvider, notion::NotionProvider,
    paybin::PaybinProvider, paypal::PayPalProvider, polar::PolarProvider, railway::railway,
    railway::RailwayProvider, reddit::RedditProvider, roblox::RobloxProvider,
    salesforce::SalesforceProvider, slack::SlackProvider, spotify::SpotifyProvider,
    tiktok::TiktokProvider, twitch::TwitchProvider, twitter::TwitterProvider,
    vercel::VercelProvider, vk::VkProvider, wechat::WeChatProvider, zoom::ZoomProvider,
};
use openauth_social_providers::providers::{github as app_github, google as app_google};
use openauth_social_providers::{ProviderId, SocialProviderConfig, PROVIDER_IDS};

#[test]
fn social_provider_registry_contains_upstream_provider_names() {
    assert_eq!(
        PROVIDER_IDS,
        &[
            "apple",
            "atlassian",
            "cognito",
            "discord",
            "facebook",
            "figma",
            "github",
            "microsoft",
            "google",
            "huggingface",
            "slack",
            "spotify",
            "twitch",
            "twitter",
            "dropbox",
            "kick",
            "linear",
            "linkedin",
            "gitlab",
            "tiktok",
            "reddit",
            "roblox",
            "salesforce",
            "vk",
            "zoom",
            "notion",
            "kakao",
            "naver",
            "line",
            "paybin",
            "paypal",
            "polar",
            "railway",
            "vercel",
            "wechat",
        ]
    );
}

#[test]
fn all_provider_types_implement_social_oauth_runtime_trait() {
    fn assert_provider<T: SocialOAuthProvider>() {}

    assert_provider::<AppleProvider>();
    assert_provider::<AtlassianProvider>();
    assert_provider::<CognitoProvider>();
    assert_provider::<DiscordProvider>();
    assert_provider::<DropboxProvider>();
    assert_provider::<FacebookProvider>();
    assert_provider::<FigmaProvider>();
    assert_provider::<GitHubProvider>();
    assert_provider::<GitlabProvider>();
    assert_provider::<GoogleProvider>();
    assert_provider::<HuggingFaceProvider>();
    assert_provider::<KakaoProvider>();
    assert_provider::<KickProvider>();
    assert_provider::<LineProvider>();
    assert_provider::<LinearProvider>();
    assert_provider::<LinkedInProvider>();
    assert_provider::<MicrosoftEntraIdProvider>();
    assert_provider::<NaverProvider>();
    assert_provider::<NotionProvider>();
    assert_provider::<PaybinProvider>();
    assert_provider::<PayPalProvider>();
    assert_provider::<PolarProvider>();
    assert_provider::<RailwayProvider>();
    assert_provider::<RedditProvider>();
    assert_provider::<RobloxProvider>();
    assert_provider::<SalesforceProvider>();
    assert_provider::<SlackProvider>();
    assert_provider::<SpotifyProvider>();
    assert_provider::<TiktokProvider>();
    assert_provider::<TwitchProvider>();
    assert_provider::<TwitterProvider>();
    assert_provider::<VercelProvider>();
    assert_provider::<VkProvider>();
    assert_provider::<WeChatProvider>();
    assert_provider::<ZoomProvider>();
}

#[test]
fn app_catalog_builds_runtime_providers() -> Result<(), Box<dyn std::error::Error>> {
    let config = SocialProviderConfig::new("client-id", "client-secret");
    let github = app_github(config.clone());
    let google = app_google(config);

    assert_eq!(
        SocialOAuthProvider::id(&github),
        ProviderId::GITHUB.as_str()
    );
    assert_eq!(
        SocialOAuthProvider::id(&google),
        ProviderId::GOOGLE.as_str()
    );
    Ok(())
}

#[test]
fn github_runtime_wrapper_exposes_metadata_and_authorization_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = github(provider_options());

    assert_eq!(SocialOAuthProvider::id(&provider), "github");
    assert_eq!(SocialOAuthProvider::name(&provider), "GitHub");
    assert_eq!(
        provider.provider_options().client_id,
        Some(ClientId::Single("client-id".to_owned()))
    );

    let url = SocialOAuthProvider::create_authorization_url(
        &provider,
        SocialAuthorizationUrlRequest {
            state: "state".to_owned(),
            redirect_uri: "https://app.example.com/callback/github".to_owned(),
            ..SocialAuthorizationUrlRequest::default()
        },
    )?;

    assert_eq!(url.host_str(), Some("github.com"));
    assert!(url.as_str().contains("client_id=client-id"));
    Ok(())
}

#[test]
fn google_runtime_wrapper_exposes_metadata_and_authorization_url(
) -> Result<(), Box<dyn std::error::Error>> {
    let provider = google(GoogleOptions {
        oauth: provider_options(),
        ..GoogleOptions::default()
    });

    assert_eq!(SocialOAuthProvider::id(&provider), "google");
    assert_eq!(SocialOAuthProvider::name(&provider), "Google");
    assert_eq!(
        provider.provider_options().client_id,
        Some(ClientId::Single("client-id".to_owned()))
    );

    let url = SocialOAuthProvider::create_authorization_url(
        &provider,
        SocialAuthorizationUrlRequest {
            state: "state".to_owned(),
            redirect_uri: "https://app.example.com/callback/google".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            ..SocialAuthorizationUrlRequest::default()
        },
    )?;

    assert_eq!(url.host_str(), Some("accounts.google.com"));
    assert!(url.as_str().contains("client_id=client-id"));
    Ok(())
}

#[tokio::test]
async fn figma_and_railway_runtime_wrappers_return_none_without_access_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let figma = figma(provider_options());
    let railway = railway(provider_options());

    let figma_user =
        SocialOAuthProvider::get_user_info(&figma, OAuth2Tokens::default(), None).await?;
    let railway_user =
        SocialOAuthProvider::get_user_info(&railway, OAuth2Tokens::default(), None).await?;

    assert_eq!(figma_user, None);
    assert_eq!(railway_user, None);
    Ok(())
}

fn provider_options() -> ProviderOptions {
    ProviderOptions {
        client_id: Some(ClientId::Single("client-id".to_owned())),
        client_secret: Some("client-secret".to_owned()),
        ..ProviderOptions::default()
    }
}
