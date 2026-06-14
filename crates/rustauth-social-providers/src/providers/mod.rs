//! Application-facing social provider catalog.
//!
//! Each factory accepts [`SocialProviderConfig`] and returns a provider ready to
//! register with `RustAuthOptions::social_provider`.
//!
//! Catalog factories wire **client credentials only**. Provider-specific
//! authorization parameters (Google `hd`, Microsoft `tenant_id`, and similar)
//! require [`crate::advanced`] or extended [`SocialProviderConfig`] options.

use rustauth_oauth::oauth2::OAuthError;

use crate::apple::{apple as build_apple, AppleOptions, AppleProvider};
use crate::atlassian::{atlassian as build_atlassian, AtlassianOptions, AtlassianProvider};
use crate::cognito::{cognito as build_cognito, CognitoProvider};
use crate::config::{CognitoPoolConfig, SocialProviderConfig};
use crate::discord::{discord as build_discord, DiscordOptions, DiscordProvider};
use crate::dropbox::{dropbox as build_dropbox, DropboxProvider, DropboxProviderOptions};
use crate::facebook::{facebook as build_facebook, FacebookOptions, FacebookProvider};
use crate::figma::{figma as build_figma, FigmaProvider};
use crate::github::{github as build_github, GitHubProvider};
use crate::gitlab::{gitlab as build_gitlab, GitlabOptions, GitlabProvider};
use crate::google::{google as build_google, GoogleOptions, GoogleProvider};
use crate::huggingface::{
    huggingface as build_huggingface, HuggingFaceOptions, HuggingFaceProvider,
};
use crate::kakao::{kakao as build_kakao, KakaoProvider};
use crate::kick::{kick as build_kick, KickProvider};
use crate::line::{line as build_line, LineOptions, LineProvider};
use crate::linear::{linear as build_linear, LinearOptions, LinearProvider};
use crate::linkedin::{linkedin as build_linkedin, LinkedInProvider};
use crate::microsoft_entra_id::{
    microsoft_entra_id as build_microsoft_entra_id, MicrosoftEntraIdOptions,
    MicrosoftEntraIdProvider,
};
use crate::naver::{naver as build_naver, NaverProvider};
use crate::notion::{notion as build_notion, NotionProvider};
use crate::paybin::{paybin as build_paybin, PaybinOptions, PaybinProvider};
use crate::paypal::{paypal as build_paypal, PayPalOptions, PayPalProvider};
use crate::polar::{polar as build_polar, PolarOptions, PolarProvider};
use crate::railway::{railway as build_railway, RailwayProvider};
use crate::reddit::{reddit as build_reddit, RedditOptions, RedditProvider};
use crate::roblox::{roblox as build_roblox, RobloxOptions, RobloxProvider};
use crate::salesforce::{salesforce as build_salesforce, SalesforceOptions, SalesforceProvider};
use crate::slack::{slack as build_slack, SlackOptions, SlackProvider};
use crate::spotify::{spotify as build_spotify, SpotifyProvider};
use crate::tiktok::{tiktok as build_tiktok, TiktokProvider};
use crate::twitch::{twitch as build_twitch, TwitchOptions, TwitchProvider};
use crate::twitter::{twitter as build_twitter, TwitterOptions, TwitterProvider};
use crate::vercel::{vercel as build_vercel, VercelOptions, VercelProvider};
use crate::vk::{vk as build_vk, VkOptions, VkProvider};
use crate::wechat::{wechat as build_wechat, WeChatProvider};
use crate::zoom::{zoom as build_zoom, ZoomOptions, ZoomProvider};

fn oauth_options(config: SocialProviderConfig) -> rustauth_oauth::oauth2::ProviderOptions {
    config.into_provider_options()
}

pub fn apple(config: SocialProviderConfig) -> Result<AppleProvider, OAuthError> {
    build_apple(AppleOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn atlassian(config: SocialProviderConfig) -> Result<AtlassianProvider, OAuthError> {
    build_atlassian(AtlassianOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn cognito(
    config: SocialProviderConfig,
    pool: CognitoPoolConfig,
) -> Result<CognitoProvider, OAuthError> {
    build_cognito(pool.into_cognito_options(config))
}

pub fn discord(config: SocialProviderConfig) -> Result<DiscordProvider, OAuthError> {
    build_discord(DiscordOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn dropbox(config: SocialProviderConfig) -> Result<DropboxProvider, OAuthError> {
    build_dropbox(DropboxProviderOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn facebook(config: SocialProviderConfig) -> Result<FacebookProvider, OAuthError> {
    build_facebook(FacebookOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn figma(config: SocialProviderConfig) -> Result<FigmaProvider, OAuthError> {
    build_figma(oauth_options(config))
}

pub fn github(config: SocialProviderConfig) -> Result<GitHubProvider, OAuthError> {
    build_github(oauth_options(config))
}

pub fn gitlab(config: SocialProviderConfig) -> Result<GitlabProvider, OAuthError> {
    build_gitlab(GitlabOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn google(config: SocialProviderConfig) -> Result<GoogleProvider, OAuthError> {
    build_google(GoogleOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn huggingface(config: SocialProviderConfig) -> Result<HuggingFaceProvider, OAuthError> {
    build_huggingface(HuggingFaceOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn kakao(config: SocialProviderConfig) -> Result<KakaoProvider, OAuthError> {
    build_kakao(oauth_options(config))
}

pub fn kick(config: SocialProviderConfig) -> Result<KickProvider, OAuthError> {
    build_kick(oauth_options(config))
}

pub fn line(config: SocialProviderConfig) -> Result<LineProvider, OAuthError> {
    build_line(LineOptions {
        oauth: oauth_options(config),
    })
}

pub fn linear(config: SocialProviderConfig) -> Result<LinearProvider, OAuthError> {
    build_linear(LinearOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn linkedin(config: SocialProviderConfig) -> Result<LinkedInProvider, OAuthError> {
    build_linkedin(oauth_options(config))
}

pub fn microsoft_entra_id(
    config: SocialProviderConfig,
) -> Result<MicrosoftEntraIdProvider, OAuthError> {
    build_microsoft_entra_id(MicrosoftEntraIdOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

/// Alias for [`microsoft_entra_id`] matching [`ProviderId::MICROSOFT`].
pub fn microsoft(config: SocialProviderConfig) -> Result<MicrosoftEntraIdProvider, OAuthError> {
    microsoft_entra_id(config)
}

pub fn naver(config: SocialProviderConfig) -> Result<NaverProvider, OAuthError> {
    build_naver(oauth_options(config))
}

pub fn notion(config: SocialProviderConfig) -> Result<NotionProvider, OAuthError> {
    build_notion(oauth_options(config))
}

pub fn paybin(config: SocialProviderConfig) -> Result<PaybinProvider, OAuthError> {
    build_paybin(PaybinOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn paypal(config: SocialProviderConfig) -> Result<PayPalProvider, OAuthError> {
    build_paypal(PayPalOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn polar(config: SocialProviderConfig) -> Result<PolarProvider, OAuthError> {
    build_polar(PolarOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn railway(config: SocialProviderConfig) -> Result<RailwayProvider, OAuthError> {
    build_railway(oauth_options(config))
}

pub fn reddit(config: SocialProviderConfig) -> Result<RedditProvider, OAuthError> {
    build_reddit(RedditOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn roblox(config: SocialProviderConfig) -> Result<RobloxProvider, OAuthError> {
    build_roblox(RobloxOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn salesforce(config: SocialProviderConfig) -> Result<SalesforceProvider, OAuthError> {
    build_salesforce(SalesforceOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn slack(config: SocialProviderConfig) -> Result<SlackProvider, OAuthError> {
    build_slack(SlackOptions {
        oauth: oauth_options(config),
    })
}

pub fn spotify(config: SocialProviderConfig) -> Result<SpotifyProvider, OAuthError> {
    build_spotify(oauth_options(config))
}

pub fn tiktok(config: SocialProviderConfig) -> Result<TiktokProvider, OAuthError> {
    build_tiktok(oauth_options(config))
}

pub fn twitch(config: SocialProviderConfig) -> Result<TwitchProvider, OAuthError> {
    build_twitch(TwitchOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn twitter(config: SocialProviderConfig) -> Result<TwitterProvider, OAuthError> {
    build_twitter(TwitterOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn vercel(config: SocialProviderConfig) -> Result<VercelProvider, OAuthError> {
    build_vercel(VercelOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn vk(config: SocialProviderConfig) -> Result<VkProvider, OAuthError> {
    build_vk(VkOptions {
        oauth: oauth_options(config),
    })
}

pub fn wechat(config: SocialProviderConfig) -> Result<WeChatProvider, OAuthError> {
    build_wechat(oauth_options(config))
}

pub fn zoom(config: SocialProviderConfig) -> Result<ZoomProvider, OAuthError> {
    build_zoom(ZoomOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}
