//! Slack social OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    create_authorization_url, refresh_access_token, validate_authorization_code,
    AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const SLACK_ID: &str = "slack";
pub const SLACK_NAME: &str = "Slack";
pub const SLACK_AUTHORIZATION_ENDPOINT: &str = "https://slack.com/openid/connect/authorize";
pub const SLACK_TOKEN_ENDPOINT: &str = "https://slack.com/api/openid.connect.token";
pub const SLACK_USER_INFO_ENDPOINT: &str = "https://slack.com/api/openid.connect.userInfo";

/// Slack-specific OAuth options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlackOptions {
    pub oauth: ProviderOptions,
}

/// Input used to create a Slack authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlackAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// Slack OpenID Connect profile returned by `openid.connect.userInfo`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SlackProfile {
    pub ok: Option<bool>,
    pub sub: String,
    #[serde(rename = "https://slack.com/user_id")]
    pub user_id: Option<String>,
    #[serde(rename = "https://slack.com/team_id")]
    pub team_id: Option<String>,
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    pub date_email_verified: Option<i64>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub locale: Option<String>,
    #[serde(rename = "https://slack.com/team_name")]
    pub team_name: Option<String>,
    #[serde(rename = "https://slack.com/team_domain")]
    pub team_domain: Option<String>,
    #[serde(rename = "https://slack.com/user_image_24")]
    pub user_image_24: Option<String>,
    #[serde(rename = "https://slack.com/user_image_32")]
    pub user_image_32: Option<String>,
    #[serde(rename = "https://slack.com/user_image_48")]
    pub user_image_48: Option<String>,
    #[serde(rename = "https://slack.com/user_image_72")]
    pub user_image_72: Option<String>,
    #[serde(rename = "https://slack.com/user_image_192")]
    pub user_image_192: Option<String>,
    #[serde(rename = "https://slack.com/user_image_512")]
    pub user_image_512: Option<String>,
    #[serde(rename = "https://slack.com/team_image_34")]
    pub team_image_34: Option<String>,
    #[serde(rename = "https://slack.com/team_image_44")]
    pub team_image_44: Option<String>,
    #[serde(rename = "https://slack.com/team_image_68")]
    pub team_image_68: Option<String>,
    #[serde(rename = "https://slack.com/team_image_88")]
    pub team_image_88: Option<String>,
    #[serde(rename = "https://slack.com/team_image_102")]
    pub team_image_102: Option<String>,
    #[serde(rename = "https://slack.com/team_image_132")]
    pub team_image_132: Option<String>,
    #[serde(rename = "https://slack.com/team_image_230")]
    pub team_image_230: Option<String>,
    #[serde(rename = "https://slack.com/team_image_default")]
    pub team_image_default: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// User info plus raw Slack profile data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlackUserInfo {
    pub user: OAuth2UserInfo,
    pub data: SlackProfile,
}

/// Slack OAuth provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlackProvider {
    options: SlackOptions,
}

pub fn slack(options: SlackOptions) -> SlackProvider {
    SlackProvider::new(options)
}

impl SlackProvider {
    pub fn new(options: SlackOptions) -> Self {
        Self { options }
    }

    pub fn id(&self) -> &str {
        SLACK_ID
    }

    pub fn name(&self) -> &str {
        SLACK_NAME
    }

    pub fn options(&self) -> &SlackOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        request: SlackAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: SLACK_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: SLACK_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            scopes: self.authorization_scopes(request.scopes),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: SLACK_TOKEN_ENDPOINT.to_owned(),
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
            token_endpoint: SLACK_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: ProviderOptions {
                    client_id: self.options.oauth.client_id.clone(),
                    client_key: self.options.oauth.client_key.clone(),
                    client_secret: self.options.oauth.client_secret.clone(),
                    ..ProviderOptions::default()
                },
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<SlackUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(SLACK_USER_INFO_ENDPOINT)
            .bearer_auth(access_token)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }
        let profile = match response.json::<SlackProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(SlackUserInfo {
            user: Self::map_profile_to_user_info(&profile),
            data: profile,
        }))
    }

    pub fn map_profile_to_user_info(profile: &SlackProfile) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: profile
                .user_id
                .clone()
                .unwrap_or_else(|| profile.sub.clone()),
            name: profile.name.clone(),
            email: profile.email.clone(),
            email_verified: profile.email_verified,
            image: profile
                .picture
                .clone()
                .or_else(|| profile.user_image_512.clone()),
        }
    }

    fn authorization_scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            ["openid", "profile", "email"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl OAuthProviderContract for SlackProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}
