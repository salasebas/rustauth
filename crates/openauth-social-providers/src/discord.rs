//! Discord OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    create_authorization_url, refresh_access_token, validate_authorization_code,
    AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthProviderContract, OAuthProviderMetadata,
    ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

const AUTHORIZATION_ENDPOINT: &str = "https://discord.com/api/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://discord.com/api/oauth2/token";
const USER_INFO_ENDPOINT: &str = "https://discord.com/api/users/@me";

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

/// Discord user info mapped into OpenAuth's normalized OAuth user shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscordUserInfo {
    pub user: OAuth2UserInfo,
    pub data: DiscordProfile,
}

/// Discord OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscordProvider {
    options: DiscordOptions,
    metadata: OAuthProviderMetadata,
}

pub fn discord(options: DiscordOptions) -> DiscordProvider {
    DiscordProvider::new(options)
}

pub fn map_discord_user_info(profile: DiscordProfile) -> DiscordUserInfo {
    DiscordProvider::map_profile(profile)
}

impl DiscordProvider {
    pub fn new(options: DiscordOptions) -> Self {
        Self {
            options,
            metadata: OAuthProviderMetadata::new("discord", "Discord"),
        }
    }

    pub fn options(&self) -> &DiscordOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        request: DiscordAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let scopes = self.authorization_scopes(request.scopes);
        let mut additional_params = BTreeMap::new();
        if scopes.iter().any(|scope| scope == "bot") {
            if let Some(permissions) = self.options.permissions {
                additional_params.insert("permissions".to_owned(), permissions.to_string());
            }
        }

        create_authorization_url(AuthorizationUrlRequest {
            id: self.id().to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            scopes,
            prompt: Some(self.options.prompt.as_str().to_owned()),
            additional_params,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
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

    fn authorization_scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            vec!["identify".to_owned(), "email".to_owned()]
        };
        scopes.extend(request_scopes);
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes
    }
}

impl Default for DiscordProvider {
    fn default() -> Self {
        Self::new(DiscordOptions::default())
    }
}

impl OAuthProviderContract for DiscordProvider {
    fn id(&self) -> &str {
        self.metadata.id()
    }

    fn name(&self) -> &str {
        self.metadata.name()
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
