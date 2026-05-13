//! Twitch OpenID Connect social provider.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const TWITCH_ID: &str = "twitch";
pub const TWITCH_NAME: &str = "Twitch";
pub const TWITCH_AUTHORIZATION_ENDPOINT: &str = "https://id.twitch.tv/oauth2/authorize";
pub const TWITCH_TOKEN_ENDPOINT: &str = "https://id.twitch.tv/oauth2/token";
pub const TWITCH_DEFAULT_SCOPES: &[&str] = &["user:read:email", "openid"];
pub const TWITCH_DEFAULT_CLAIMS: &[&str] =
    &["email", "email_verified", "preferred_username", "picture"];

/// Twitch provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwitchOptions {
    pub oauth: ProviderOptions,
    pub claims: Vec<String>,
}

/// Input used to create a Twitch authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwitchAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// Twitch ID token profile claims.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TwitchProfile {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub preferred_username: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub picture: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl TwitchProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.sub.clone(),
            name: Some(self.preferred_username.clone()),
            email: Some(self.email.clone()),
            image: Some(self.picture.clone()),
            email_verified: self.email_verified,
        }
    }
}

/// A normalized OpenAuth user and the raw Twitch claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwitchUserInfo {
    pub user: OAuth2UserInfo,
    pub data: TwitchProfile,
}

/// Twitch OAuth/OIDC provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwitchProvider {
    options: TwitchOptions,
}

pub fn twitch(options: TwitchOptions) -> TwitchProvider {
    TwitchProvider::new(options)
}

impl TwitchProvider {
    pub fn new(options: TwitchOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &TwitchOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        TWITCH_TOKEN_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: TwitchAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: TWITCH_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: TWITCH_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            scopes: self.scopes(request.scopes),
            claims: self.claims(),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn authorization_code_request(
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
            token_endpoint: TWITCH_TOKEN_ENDPOINT.to_owned(),
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
            token_endpoint: TWITCH_TOKEN_ENDPOINT.to_owned(),
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
    ) -> Result<Option<TwitchUserInfo>, OAuthError> {
        let Some(id_token) = token.id_token.as_deref() else {
            return Ok(None);
        };
        let profile = decode_jwt_payload::<TwitchProfile>(id_token)?;
        Ok(Some(TwitchUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }))
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            TWITCH_DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }

    fn claims(&self) -> Vec<String> {
        if self.options.claims.is_empty() {
            TWITCH_DEFAULT_CLAIMS
                .iter()
                .map(|claim| (*claim).to_owned())
                .collect()
        } else {
            self.options.claims.clone()
        }
    }
}

impl OAuthProviderContract for TwitchProvider {
    fn id(&self) -> &str {
        TWITCH_ID
    }

    fn name(&self) -> &str {
        TWITCH_NAME
    }
}

fn decode_jwt_payload<T>(token: &str) -> Result<T, OAuthError>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| OAuthError::TokenVerification("missing jwt payload".to_owned()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| OAuthError::TokenVerification(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| OAuthError::InvalidResponse(error.to_string()))
}
