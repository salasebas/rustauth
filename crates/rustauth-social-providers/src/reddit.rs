//! Reddit social OAuth provider.

use std::collections::BTreeMap;

use rustauth_oauth::oauth2::{
    ClientAuthentication, ExchangeCodeBuilder, OAuth2Client, OAuth2Tokens, OAuth2UserInfo,
    OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://www.reddit.com/api/v1/authorize";
const TOKEN_ENDPOINT: &str = "https://www.reddit.com/api/v1/access_token";
const USERINFO_ENDPOINT: &str = "https://oauth.reddit.com/api/v1/me";
const DEFAULT_SCOPE: &str = "identity";
const USER_AGENT: &str = "better-auth";

pub const REDDIT_ID: &str = "reddit";
pub const REDDIT_NAME: &str = "Reddit";
pub const REDDIT_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const REDDIT_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const REDDIT_USERINFO_ENDPOINT: &str = USERINFO_ENDPOINT;
pub const REDDIT_DEFAULT_SCOPE: &str = DEFAULT_SCOPE;

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
#[derive(Debug, Clone)]
pub struct RedditProvider {
    client: OAuth2Client,
    duration: Option<String>,
}

#[allow(deprecated)]
pub fn reddit(options: RedditOptions) -> Result<RedditProvider, OAuthError> {
    RedditProvider::new(options)
}

impl RedditProvider {
    #[deprecated(note = "use advanced::reddit::reddit() instead")]
    pub fn new(options: RedditOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("reddit", options.oauth)
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?
            .authentication(ClientAuthentication::Basic);
        if !disable_default_scope {
            builder = builder.default_scope(DEFAULT_SCOPE);
        }
        Ok(Self {
            client: builder.build()?,
            duration: options.duration,
        })
    }

    pub fn options(&self) -> RedditOptions {
        RedditOptions {
            oauth: self.client.options().clone(),
            duration: self.duration.clone(),
        }
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn userinfo_endpoint(&self) -> &str {
        USERINFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: RedditAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?
            .scopes(request.scopes);
        if let Some(duration) = &self.duration {
            url = url.duration(duration.clone());
        }
        url.build()
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        apply_reddit_token_headers(self.client.exchange_code(code, redirect_uri)?)
            .into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        apply_reddit_token_headers(self.client.exchange_code(code, redirect_uri)?)
            .send()
            .await
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
    ) -> Result<Option<RedditUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(USERINFO_ENDPOINT)
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

    pub fn id(&self) -> &str {
        REDDIT_ID
    }

    pub fn name(&self) -> &str {
        REDDIT_NAME
    }
}

impl ProviderIdentity for RedditProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

fn apply_reddit_token_headers<'a>(
    mut exchange: ExchangeCodeBuilder<'a>,
) -> ExchangeCodeBuilder<'a> {
    for (key, value) in reddit_token_headers() {
        exchange = exchange.header(key, value);
    }
    exchange
}

fn reddit_token_headers() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("accept".to_owned(), "text/plain".to_owned()),
        ("user-agent".to_owned(), USER_AGENT.to_owned()),
    ])
}
