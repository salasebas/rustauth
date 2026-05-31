//! Roblox OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract, OAuthProviderMetadata,
    ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const ROBLOX_ID: &str = "roblox";
pub const ROBLOX_NAME: &str = "Roblox";
pub const ROBLOX_AUTHORIZATION_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/authorize";
pub const ROBLOX_TOKEN_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/token";
pub const ROBLOX_USER_INFO_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/userinfo";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobloxProvider {
    options: RobloxOptions,
    metadata: OAuthProviderMetadata,
}

pub fn roblox(options: RobloxOptions) -> RobloxProvider {
    RobloxProvider::new(options)
}

impl RobloxProvider {
    pub fn new(options: RobloxOptions) -> Self {
        Self {
            options,
            metadata: OAuthProviderMetadata::new(ROBLOX_ID, ROBLOX_NAME),
        }
    }

    pub fn options(&self) -> &RobloxOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        ROBLOX_TOKEN_ENDPOINT
    }

    pub fn user_info_endpoint(&self) -> &str {
        ROBLOX_USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: RobloxAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: ROBLOX_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: ROBLOX_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            scopes: self.authorization_scopes(request.scopes),
            prompt: Some(self.options.prompt.as_str().to_owned()),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn create_authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: ROBLOX_TOKEN_ENDPOINT.to_owned(),
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

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token.into(),
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Post,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: ROBLOX_TOKEN_ENDPOINT.to_owned(),
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
    ) -> Result<Option<RobloxUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let response = match crate::http::shared_client()
            .get(ROBLOX_USER_INFO_ENDPOINT)
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

    fn authorization_scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            vec!["openid".to_owned(), "profile".to_owned()]
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl Default for RobloxProvider {
    fn default() -> Self {
        Self::new(RobloxOptions::default())
    }
}

impl OAuthProviderContract for RobloxProvider {
    fn id(&self) -> &str {
        self.metadata.id()
    }

    fn name(&self) -> &str {
        self.metadata.name()
    }
}
