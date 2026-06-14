//! Roblox OAuth provider.

use std::collections::BTreeMap;

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/authorize";
const TOKEN_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/token";
const USER_INFO_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/userinfo";

pub const ROBLOX_ID: &str = "roblox";
pub const ROBLOX_NAME: &str = "Roblox";
pub const ROBLOX_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const ROBLOX_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const ROBLOX_USER_INFO_ENDPOINT: &str = USER_INFO_ENDPOINT;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RobloxPrompt {
    None,
    Consent,
    Login,
    SelectAccount,
    #[default]
    SelectAccountConsent,
}

impl RobloxPrompt {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Consent => "consent",
            Self::Login => "login",
            Self::SelectAccount => "select_account",
            Self::SelectAccountConsent => "select_account consent",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RobloxOptions {
    pub oauth: ProviderOptions,
    pub prompt: RobloxPrompt,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RobloxAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RobloxProfile {
    pub sub: String,
    pub preferred_username: String,
    pub nickname: String,
    pub name: String,
    pub created_at: i64,
    pub profile: String,
    pub picture: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RobloxUserInfo {
    pub user: OAuth2UserInfo,
    pub data: RobloxProfile,
}

#[derive(Debug, Clone)]
pub struct RobloxProvider {
    client: OAuth2Client,
    prompt: RobloxPrompt,
}

#[allow(deprecated)]
pub fn roblox(options: RobloxOptions) -> Result<RobloxProvider, OAuthError> {
    RobloxProvider::new(options)
}

impl RobloxProvider {
    #[deprecated(note = "use advanced::roblox::roblox() instead")]
    pub fn new(options: RobloxOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("roblox", options.oauth)
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?
            .scope_joiner("+");
        if !disable_default_scope {
            builder = builder.default_scopes(["openid", "profile"]);
        }
        Ok(Self {
            client: builder.build()?,
            prompt: options.prompt,
        })
    }

    pub fn options(&self) -> RobloxOptions {
        RobloxOptions {
            oauth: self.client.options().clone(),
            prompt: self.prompt,
        }
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn user_info_endpoint(&self) -> &str {
        USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: RobloxAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.client
            .authorization_url(request.state, request.redirect_uri)?
            .scopes(request.scopes)
            .prompt(self.prompt.as_str())
            .build()
    }

    pub fn create_authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .exchange_code(code, redirect_uri)?
            .into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.exchange_code(code, redirect_uri)?.send().await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .refresh_token(refresh_token)?
            .into_form_request()
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
    ) -> Result<Option<RobloxUserInfo>, OAuthError> {
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

        let profile = match response.json::<RobloxProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(Self::map_profile(profile)))
    }

    pub fn map_profile(profile: RobloxProfile) -> RobloxUserInfo {
        let name = if profile.nickname.is_empty() {
            profile.preferred_username.clone()
        } else {
            profile.nickname.clone()
        };

        RobloxUserInfo {
            user: OAuth2UserInfo {
                id: profile.sub.clone(),
                name: Some(name),
                email: Some(profile.preferred_username.clone()),
                image: Some(profile.picture.clone()),
                email_verified: false,
            },
            data: profile,
        }
    }

    pub fn id(&self) -> &str {
        ROBLOX_ID
    }

    pub fn name(&self) -> &str {
        ROBLOX_NAME
    }
}

impl ProviderIdentity for RobloxProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}
