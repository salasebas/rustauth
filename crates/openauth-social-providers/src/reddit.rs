//! Reddit social OAuth provider.

use std::collections::BTreeMap;

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

pub const REDDIT_ID: &str = "reddit";
pub const REDDIT_NAME: &str = "Reddit";
pub const REDDIT_AUTHORIZATION_ENDPOINT: &str = "https://www.reddit.com/api/v1/authorize";
pub const REDDIT_TOKEN_ENDPOINT: &str = "https://www.reddit.com/api/v1/access_token";
pub const REDDIT_USERINFO_ENDPOINT: &str = "https://oauth.reddit.com/api/v1/me";
pub const REDDIT_DEFAULT_SCOPE: &str = "identity";
const USER_AGENT: &str = "better-auth";

/// Reddit provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedditOptions {
    pub oauth: ProviderOptions,
    pub duration: Option<String>,
}

/// Input for creating a Reddit authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedditAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// Reddit profile returned by `GET /api/v1/me`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RedditProfile {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub icon_img: Option<String>,
    #[serde(default)]
    pub has_verified_email: bool,
    #[serde(default)]
    pub oauth_client_id: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// User info plus raw Reddit profile data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RedditUserInfo {
    pub user: OAuth2UserInfo,
    pub data: RedditProfile,
}

/// Reddit OAuth provider.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedditProvider {
    options: RedditOptions,
}

pub fn reddit(options: RedditOptions) -> RedditProvider {
    RedditProvider::new(options)
}

impl RedditProvider {
    pub fn new(options: RedditOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &RedditOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        REDDIT_TOKEN_ENDPOINT
    }

    pub fn userinfo_endpoint(&self) -> &str {
        REDDIT_USERINFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: RedditAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: REDDIT_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: REDDIT_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            scopes: self.scopes(request.scopes),
            duration: self.options.duration.clone(),
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
            authentication: ClientAuthentication::Basic,
            headers: reddit_token_headers(),
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: REDDIT_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Basic,
                headers: reddit_token_headers(),
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
            authentication: ClientAuthentication::Basic,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: REDDIT_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Basic,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<RedditUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(REDDIT_USERINFO_ENDPOINT)
            .bearer_auth(access_token)
            .header("User-Agent", USER_AGENT)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };

        if !response.status().is_success() {
            return Ok(None);
        }

        let profile = match response.json::<RedditProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(Self::map_profile(profile)))
    }

    pub fn map_profile(profile: RedditProfile) -> RedditUserInfo {
        let image = profile
            .icon_img
            .as_deref()
            .and_then(|image| image.split('?').next())
            .map(str::to_owned);

        RedditUserInfo {
            user: OAuth2UserInfo {
                id: profile.id.clone(),
                name: Some(profile.name.clone()),
                email: Some(profile.oauth_client_id.clone()),
                email_verified: profile.has_verified_email,
                image,
            },
            data: profile,
        }
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = Vec::new();
        if !self.options.oauth.disable_default_scope {
            scopes.push(REDDIT_DEFAULT_SCOPE.to_owned());
        }
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl OAuthProviderContract for RedditProvider {
    fn id(&self) -> &str {
        REDDIT_ID
    }

    fn name(&self) -> &str {
        REDDIT_NAME
    }
}

fn reddit_token_headers() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("accept".to_owned(), "text/plain".to_owned()),
        ("user-agent".to_owned(), USER_AGENT.to_owned()),
    ])
}
