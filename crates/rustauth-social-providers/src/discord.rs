//! Discord OAuth provider.

use std::collections::BTreeMap;

use rustauth_oauth::oauth2::ClientAuthentication;
use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://discord.com/api/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://discord.com/api/oauth2/token";
const USER_INFO_ENDPOINT: &str = "https://discord.com/api/users/@me";
const DEFAULT_SCOPES: &[&str] = &["identify", "email"];

/// Discord authorization prompt behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DiscordPrompt {
    /// Do not show Discord's consent prompt unless Discord requires it.
    #[default]
    None,
    /// Ask Discord to show the consent prompt.
    Consent,
}

impl DiscordPrompt {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Consent => "consent",
        }
    }
}

/// Discord-specific OAuth options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscordOptions {
    /// Shared OAuth provider options.
    pub oauth: ProviderOptions,
    /// Discord prompt parameter. Better Auth defaults this to `none`.
    pub prompt: DiscordPrompt,
    /// Discord bot permissions. Only sent when the final scope list contains `bot`.
    pub permissions: Option<u64>,
}

/// Input used to create a Discord authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscordAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// Discord user profile returned by `GET /users/@me`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DiscordProfile {
    pub id: String,
    pub username: String,
    pub discriminator: String,
    pub global_name: Option<String>,
    pub avatar: Option<String>,
    pub bot: Option<bool>,
    pub system: Option<bool>,
    #[serde(default)]
    pub mfa_enabled: bool,
    pub banner: Option<String>,
    pub accent_color: Option<u64>,
    pub locale: Option<String>,
    #[serde(default)]
    pub verified: bool,
    pub email: Option<String>,
    #[serde(default)]
    pub flags: u64,
    #[serde(default)]
    pub premium_type: u64,
    #[serde(default)]
    pub public_flags: u64,
    pub display_name: Option<String>,
    pub avatar_decoration: Option<String>,
    pub banner_color: Option<String>,
    pub image_url: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Discord user info mapped into RustAuth's normalized OAuth user shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscordUserInfo {
    pub user: OAuth2UserInfo,
    pub data: DiscordProfile,
}

/// Discord OAuth provider.
#[derive(Debug, Clone)]
pub struct DiscordProvider {
    client: OAuth2Client,
    prompt: DiscordPrompt,
    permissions: Option<u64>,
}

#[allow(deprecated)]
pub fn discord(options: DiscordOptions) -> Result<DiscordProvider, OAuthError> {
    DiscordProvider::new(options)
}

pub fn map_discord_user_info(profile: DiscordProfile) -> DiscordUserInfo {
    DiscordProvider::map_profile(profile)
}

impl DiscordProvider {
    #[deprecated(note = "use advanced::discord::discord() instead")]
    pub fn new(options: DiscordOptions) -> Result<Self, OAuthError> {
        let prompt = options.prompt;
        let permissions = options.permissions;
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("discord", options.oauth)
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?
            .scope_joiner("+")
            .authentication(ClientAuthentication::Post);
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
            prompt,
            permissions,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn discord_options(&self) -> DiscordOptions {
        DiscordOptions {
            oauth: self.options(),
            prompt: self.prompt,
            permissions: self.permissions,
        }
    }

    pub fn create_authorization_url(
        &self,
        request: DiscordAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let request_scopes = request.scopes;
        let mut scopes = if !self.client.options().disable_default_scope {
            DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        } else {
            Vec::new()
        };
        scopes.extend(self.client.options().scope.iter().cloned());
        scopes.extend(request_scopes.iter().cloned());

        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?
            .prompt(self.prompt.as_str())
            .scopes(request_scopes);
        if scopes.iter().any(|scope| scope == "bot") {
            if let Some(permissions) = self.permissions {
                url = url.param("permissions", permissions.to_string());
            }
        }
        url.build()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.exchange_code(code, redirect_uri)?.send().await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token)?.send().await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<DiscordUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(USER_INFO_ENDPOINT)
            .header("authorization", format!("Bearer {access_token}"))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }
        let profile = match response.json::<DiscordProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(Self::map_profile(profile)))
    }

    pub fn map_profile(mut profile: DiscordProfile) -> DiscordUserInfo {
        let image_url = discord_avatar_url(&profile);
        profile.image_url = Some(image_url.clone());
        let name = profile
            .global_name
            .clone()
            .or_else(|| (!profile.username.is_empty()).then(|| profile.username.clone()));

        DiscordUserInfo {
            user: OAuth2UserInfo {
                id: profile.id.clone(),
                name,
                email: profile.email.clone(),
                email_verified: profile.verified,
                image: Some(image_url),
            },
            data: profile,
        }
    }
}

impl ProviderIdentity for DiscordProvider {
    fn id(&self) -> &str {
        "discord"
    }

    fn name(&self) -> &str {
        "Discord"
    }
}

fn discord_avatar_url(profile: &DiscordProfile) -> String {
    match profile.avatar.as_deref() {
        Some(avatar) => {
            let format = if avatar.starts_with("a_") {
                "gif"
            } else {
                "png"
            };
            format!(
                "https://cdn.discordapp.com/avatars/{}/{}.{}",
                profile.id, avatar, format
            )
        }
        None => {
            let default_avatar_number = if profile.discriminator == "0" {
                discord_snowflake_timestamp(&profile.id) % 6
            } else {
                profile.discriminator.parse::<u64>().unwrap_or_default() % 5
            };
            format!("https://cdn.discordapp.com/embed/avatars/{default_avatar_number}.png")
        }
    }
}

fn discord_snowflake_timestamp(id: &str) -> u64 {
    id.parse::<u64>().unwrap_or_default() >> 22
}
