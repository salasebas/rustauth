//! Application-facing social provider catalog.
//!
//! Each factory accepts [`SocialProviderConfig`] and returns a provider ready to
//! register with `OpenAuthOptions::social_provider`.

use openauth_oauth::oauth2::OAuthError;

use crate::apple::{apple as build_apple, AppleOptions, AppleProvider};
use crate::atlassian::{atlassian as build_atlassian, AtlassianOptions, AtlassianProvider};
use crate::cognito::{cognito as build_cognito, CognitoProvider};
use crate::config::{CognitoPoolConfig, SocialProviderConfig};
use crate::discord::{discord as build_discord, DiscordOptions, DiscordProvider};
use crate::dropbox::{DropboxProvider, DropboxProviderOptions};
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

fn oauth_options(config: SocialProviderConfig) -> openauth_oauth::oauth2::ProviderOptions {
    config.into_provider_options()
}

pub fn apple(config: SocialProviderConfig) -> AppleProvider {
    build_apple(AppleOptions {
        provider: oauth_options(config),
        ..Default::default()
    })
}

pub fn atlassian(config: SocialProviderConfig) -> AtlassianProvider {
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

pub fn discord(config: SocialProviderConfig) -> DiscordProvider {
    build_discord(DiscordOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn dropbox(config: SocialProviderConfig) -> DropboxProvider {
    DropboxProvider::new(DropboxProviderOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn facebook(config: SocialProviderConfig) -> FacebookProvider {
    build_facebook(FacebookOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn figma(config: SocialProviderConfig) -> FigmaProvider {
    build_figma(oauth_options(config))
}

pub fn github(config: SocialProviderConfig) -> GitHubProvider {
    build_github(oauth_options(config))
}

pub fn gitlab(config: SocialProviderConfig) -> GitlabProvider {
    build_gitlab(GitlabOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn google(config: SocialProviderConfig) -> GoogleProvider {
    build_google(GoogleOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn huggingface(config: SocialProviderConfig) -> HuggingFaceProvider {
    build_huggingface(HuggingFaceOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn kakao(config: SocialProviderConfig) -> KakaoProvider {
    build_kakao(oauth_options(config))
}

pub fn kick(config: SocialProviderConfig) -> KickProvider {
    build_kick(oauth_options(config))
}

pub fn line(config: SocialProviderConfig) -> LineProvider {
    build_line(LineOptions {
        oauth: oauth_options(config),
    })
}

pub fn linear(config: SocialProviderConfig) -> LinearProvider {
    build_linear(LinearOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn linkedin(config: SocialProviderConfig) -> LinkedInProvider {
    build_linkedin(oauth_options(config))
}

pub fn microsoft_entra_id(config: SocialProviderConfig) -> MicrosoftEntraIdProvider {
    build_microsoft_entra_id(MicrosoftEntraIdOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn naver(config: SocialProviderConfig) -> NaverProvider {
    build_naver(oauth_options(config))
}

pub fn notion(config: SocialProviderConfig) -> NotionProvider {
    build_notion(oauth_options(config))
}

pub fn paybin(config: SocialProviderConfig) -> PaybinProvider {
    build_paybin(PaybinOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn paypal(config: SocialProviderConfig) -> PayPalProvider {
    build_paypal(PayPalOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn polar(config: SocialProviderConfig) -> PolarProvider {
    build_polar(PolarOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn railway(config: SocialProviderConfig) -> RailwayProvider {
    build_railway(oauth_options(config))
}

pub fn reddit(config: SocialProviderConfig) -> RedditProvider {
    build_reddit(RedditOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn roblox(config: SocialProviderConfig) -> RobloxProvider {
    build_roblox(RobloxOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn salesforce(config: SocialProviderConfig) -> SalesforceProvider {
    build_salesforce(SalesforceOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn slack(config: SocialProviderConfig) -> SlackProvider {
    build_slack(SlackOptions {
        oauth: oauth_options(config),
    })
}

pub fn spotify(config: SocialProviderConfig) -> SpotifyProvider {
    build_spotify(oauth_options(config))
}

pub fn tiktok(config: SocialProviderConfig) -> TiktokProvider {
    build_tiktok(oauth_options(config))
}

pub fn twitch(config: SocialProviderConfig) -> TwitchProvider {
    build_twitch(TwitchOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn twitter(config: SocialProviderConfig) -> TwitterProvider {
    build_twitter(TwitterOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn vercel(config: SocialProviderConfig) -> VercelProvider {
    build_vercel(VercelOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}

pub fn vk(config: SocialProviderConfig) -> VkProvider {
    build_vk(VkOptions {
        oauth: oauth_options(config),
    })
}

pub fn wechat(config: SocialProviderConfig) -> WeChatProvider {
    build_wechat(oauth_options(config))
}

pub fn zoom(config: SocialProviderConfig) -> ZoomProvider {
    build_zoom(ZoomOptions {
        oauth: oauth_options(config),
        ..Default::default()
    })
}
