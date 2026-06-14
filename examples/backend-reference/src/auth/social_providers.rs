//! Social OAuth providers: one example per distinct public setup API.
//!
//! RustAuth exposes three layers for social sign-in:
//!
//! 1. **Catalog** — `rustauth::social_providers::providers::*` with [`SocialProviderConfig`]
//! 2. **Shared config builder** — [`SocialProviderConfig::builder()`] and [`SocialProviderConfig::from_env`]
//! 3. **Provider-specific options** — `rustauth::social_providers::advanced::*`
//!
//! Amazon Cognito also requires [`CognitoPoolConfig`] as a second argument.

use std::env;

use rustauth::options::RustAuthOptions;
use rustauth::social_providers::advanced;
use rustauth::social_providers::providers;
use rustauth::social_providers::{CognitoPoolConfig, SocialProviderConfig};

use crate::config::AppConfig;
use crate::error::{AppError, AppResult};

/// Documented setup patterns for introspection and copy-paste reference.
pub const SOCIAL_SETUP_PATTERNS: &[&str] = &[
    "catalog-new: providers::github(SocialProviderConfig::new(id, secret))",
    "config-builder: SocialProviderConfig::builder().client_id(...).build()?",
    "config-from-env: SocialProviderConfig::from_env(\"GITHUB\")?",
    "cognito-pool: providers::cognito(config, CognitoPoolConfig::new(domain, region, pool_id))",
    "google-options: advanced::google::{GoogleOptions, GoogleAccessType, GoogleDisplay}",
    "apple-options: advanced::apple::AppleOptions { app_bundle_identifier, audience }",
    "microsoft-options: advanced::microsoft_entra_id::MicrosoftEntraIdOptions { tenant_id, .. }",
    "salesforce-options: advanced::salesforce::{SalesforceOptions, SalesforceEnvironment}",
    "wechat-options: advanced::wechat::{WeChatProviderOptions, WeChatLang}",
    "paypal-options: advanced::paypal::{PayPalOptions, PayPalEnvironment}",
    "discord-options: advanced::discord::{DiscordOptions, DiscordPrompt}",
    "facebook-options: advanced::facebook::FacebookOptions { fields, config_id, .. }",
    "gitlab-options: advanced::gitlab::GitlabOptions { issuer, .. }",
    "dropbox-options: advanced::dropbox::{DropboxProviderOptions, DropboxAccessType}",
    "zoom-options: advanced::zoom::ZoomOptions { pkce, .. }",
    "reddit-options: advanced::reddit::RedditOptions { duration, .. }",
    "roblox-options: advanced::roblox::{RobloxOptions, RobloxPrompt}",
    "twitch-options: advanced::twitch::TwitchOptions { claims, .. }",
    "paybin-options: advanced::paybin::PaybinOptions { issuer, .. }",
    "catalog-standard: figma, kick, kakao, line, linkedin, naver, notion, polar, railway, slack, tiktok, twitter, vercel, vk, atlassian, linear, huggingface",
    "config-builder: spotify via SocialProviderConfig::builder()",
];

/// Register every distinct social-provider setup pattern on the options builder.
pub fn apply_social_providers(
    mut options: RustAuthOptions,
    config: &AppConfig,
) -> AppResult<RustAuthOptions> {
    options = register_catalog_standard(options)?;
    options = register_config_builder_example(options)?;
    options = register_cognito(options, config)?;
    options = register_provider_specific(options)?;
    Ok(options)
}

/// Pattern 1 — catalog factories with `SocialProviderConfig::new`.
fn register_catalog_standard(options: RustAuthOptions) -> AppResult<RustAuthOptions> {
    let mut options = options;
    options = push(options, providers::github(oauth_config("GITHUB")?))?;
    options = push(options, providers::linkedin(oauth_config("LINKEDIN")?))?;
    options = push(
        options,
        providers::tiktok(oauth_config_with_client_key("TIKTOK")?),
    )?;
    options = push(options, providers::kick(oauth_config("KICK")?))?;
    options = push(options, providers::notion(oauth_config("NOTION")?))?;
    options = push(options, providers::figma(oauth_config("FIGMA")?))?;
    options = push(options, providers::railway(oauth_config("RAILWAY")?))?;
    options = push(options, providers::kakao(oauth_config("KAKAO")?))?;
    options = push(options, providers::naver(oauth_config("NAVER")?))?;
    options = push(options, providers::vk(oauth_config("VK")?))?;
    options = push(
        options,
        providers::huggingface(oauth_config("HUGGINGFACE")?),
    )?;
    options = push(options, providers::polar(oauth_config("POLAR")?))?;
    options = push(options, providers::atlassian(oauth_config("ATLASSIAN")?))?;
    options = push(options, providers::linear(oauth_config("LINEAR")?))?;
    options = push(options, providers::vercel(oauth_config("VERCEL")?))?;
    options = push(options, providers::twitter(oauth_config("TWITTER")?))?;
    options = push(options, providers::slack(oauth_config("SLACK")?))?;
    options = push(options, providers::line(oauth_config("LINE")?))?;
    Ok(options)
}

/// Pattern 2 — staged credentials via `SocialProviderConfig::builder()`.
fn register_config_builder_example(options: RustAuthOptions) -> AppResult<RustAuthOptions> {
    let base = oauth_config("SPOTIFY")?;
    let config = SocialProviderConfig::builder()
        .client_id(base.client_id())
        .client_secret(base.client_secret())
        .scope(["user-read-email", "user-read-private"])
        .build()
        .map_err(map_oauth_error)?;

    push(options, providers::spotify(config))
}

/// Pattern 3 — Cognito pool metadata as a second argument.
fn register_cognito(options: RustAuthOptions, config: &AppConfig) -> AppResult<RustAuthOptions> {
    let pool = CognitoPoolConfig::new(
        env_or("COGNITO_DOMAIN", &config.cognito_domain),
        env_or("COGNITO_REGION", &config.cognito_region),
        env_or("COGNITO_USER_POOL_ID", &config.cognito_user_pool_id),
    );
    push(options, providers::cognito(oauth_config("COGNITO")?, pool))
}

/// Pattern 4 — provider-specific option structs under `advanced`.
fn register_provider_specific(options: RustAuthOptions) -> AppResult<RustAuthOptions> {
    use advanced::apple::AppleOptions;
    use advanced::discord::{DiscordOptions, DiscordPrompt};
    use advanced::dropbox::{DropboxAccessType, DropboxProviderOptions};
    use advanced::facebook::FacebookOptions;
    use advanced::gitlab::GitlabOptions;
    use advanced::google::{GoogleAccessType, GoogleDisplay, GoogleOptions};
    use advanced::microsoft_entra_id::MicrosoftEntraIdOptions;
    use advanced::paybin::PaybinOptions;
    use advanced::paypal::{PayPalEnvironment, PayPalOptions};
    use advanced::reddit::RedditOptions;
    use advanced::roblox::{RobloxOptions, RobloxPrompt};
    use advanced::salesforce::{SalesforceEnvironment, SalesforceOptions};
    use advanced::twitch::TwitchOptions;
    use advanced::wechat::{WeChatLang, WeChatProviderOptions};
    use advanced::zoom::ZoomOptions;

    let mut options = options;

    options = push(
        options,
        advanced::google::google(GoogleOptions {
            oauth: oauth_config("GOOGLE")?.into_provider_options(),
            access_type: Some(GoogleAccessType::Offline),
            display: Some(GoogleDisplay::Page),
            hd: env::var("GOOGLE_HD").ok(),
        }),
    )?;

    options = push(
        options,
        advanced::apple::apple(AppleOptions {
            oauth: oauth_config("APPLE")?.into_provider_options(),
            app_bundle_identifier: env::var("APPLE_APP_BUNDLE_ID").ok(),
            audience: env::var("APPLE_AUDIENCE")
                .map(|value| vec![value])
                .unwrap_or_default(),
        }),
    )?;

    options = push(
        options,
        advanced::microsoft_entra_id::microsoft_entra_id(MicrosoftEntraIdOptions {
            oauth: oauth_config("MICROSOFT")?.into_provider_options(),
            tenant_id: env::var("MICROSOFT_TENANT_ID").ok(),
            ..MicrosoftEntraIdOptions::default()
        }),
    )?;

    options = push(
        options,
        advanced::salesforce::salesforce(SalesforceOptions {
            oauth: oauth_config("SALESFORCE")?.into_provider_options(),
            environment: SalesforceEnvironment::Sandbox,
            ..SalesforceOptions::default()
        }),
    )?;

    options = push(
        options,
        advanced::wechat::WeChatProvider::new(WeChatProviderOptions {
            oauth: oauth_config("WECHAT")?.into_provider_options(),
            lang: Some(WeChatLang::En),
        }),
    )?;

    options = push(
        options,
        advanced::paypal::paypal(PayPalOptions {
            oauth: oauth_config("PAYPAL")?.into_provider_options(),
            environment: PayPalEnvironment::Sandbox,
            ..PayPalOptions::default()
        }),
    )?;

    options = push(
        options,
        advanced::discord::discord(DiscordOptions {
            oauth: oauth_config("DISCORD")?.into_provider_options(),
            prompt: DiscordPrompt::Consent,
            permissions: None,
        }),
    )?;

    options = push(
        options,
        advanced::facebook::facebook(FacebookOptions {
            oauth: oauth_config("FACEBOOK")?.into_provider_options(),
            fields: vec!["email".to_owned(), "name".to_owned()],
            config_id: env::var("FACEBOOK_CONFIG_ID").ok(),
            ..FacebookOptions::default()
        }),
    )?;

    options = push(
        options,
        advanced::gitlab::gitlab(GitlabOptions {
            oauth: oauth_config("GITLAB")?.into_provider_options(),
            issuer: env::var("GITLAB_ISSUER").ok(),
        }),
    )?;

    options = push(
        options,
        advanced::dropbox::DropboxProvider::new(DropboxProviderOptions {
            oauth: oauth_config("DROPBOX")?.into_provider_options(),
            access_type: Some(DropboxAccessType::Offline),
        }),
    )?;

    options = push(
        options,
        advanced::zoom::zoom(ZoomOptions {
            oauth: oauth_config("ZOOM")?.into_provider_options(),
            pkce: true,
        }),
    )?;

    options = push(
        options,
        advanced::reddit::reddit(RedditOptions {
            oauth: oauth_config("REDDIT")?.into_provider_options(),
            duration: Some("permanent".to_owned()),
        }),
    )?;

    options = push(
        options,
        advanced::roblox::roblox(RobloxOptions {
            oauth: oauth_config("ROBLOX")?.into_provider_options(),
            prompt: RobloxPrompt::Login,
        }),
    )?;

    options = push(
        options,
        advanced::twitch::twitch(TwitchOptions {
            oauth: oauth_config("TWITCH")?.into_provider_options(),
            claims: vec!["user:read:email".to_owned()],
            ..TwitchOptions::default()
        }),
    )?;

    options = push(
        options,
        advanced::paybin::paybin(PaybinOptions {
            oauth: oauth_config("PAYBIN")?.into_provider_options(),
            issuer: env::var("PAYBIN_ISSUER").ok(),
        }),
    )?;

    Ok(options)
}

fn push<P>(
    options: RustAuthOptions,
    provider: Result<P, rustauth::oauth::oauth2::OAuthError>,
) -> AppResult<RustAuthOptions>
where
    P: rustauth::oauth::oauth2::SocialOAuthProvider + 'static,
{
    Ok(options.social_provider(provider.map_err(map_oauth_error)?))
}

fn oauth_config(prefix: &str) -> AppResult<SocialProviderConfig> {
    SocialProviderConfig::from_env(prefix)
        .or_else(|_| oauth_config_stub(prefix))
        .map_err(map_oauth_error)
}

fn oauth_config_with_client_key(prefix: &str) -> AppResult<SocialProviderConfig> {
    SocialProviderConfig::from_env_with_keys(prefix, &["CLIENT_KEY"])
        .or_else(|_| oauth_config_stub_with_client_key(prefix))
        .map_err(map_oauth_error)
}

fn oauth_config_stub(
    prefix: &str,
) -> Result<SocialProviderConfig, rustauth::oauth::oauth2::OAuthError> {
    SocialProviderConfig::builder()
        .client_id(format!("stub-{prefix}-client-id"))
        .client_secret(format!("stub-{prefix}-client-secret"))
        .build()
}

fn oauth_config_stub_with_client_key(
    prefix: &str,
) -> Result<SocialProviderConfig, rustauth::oauth::oauth2::OAuthError> {
    SocialProviderConfig::builder()
        .client_id(format!("stub-{prefix}-client-id"))
        .client_secret(format!("stub-{prefix}-client-secret"))
        .client_key(format!("stub-{prefix}-client-key"))
        .build()
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn map_oauth_error(error: rustauth::oauth::oauth2::OAuthError) -> AppError {
    AppError::Config(error.to_string())
}
