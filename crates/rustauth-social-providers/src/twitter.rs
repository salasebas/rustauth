//! Twitter/X social OAuth provider.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_oauth::oauth2::{
    ClientAuthentication, OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest,
    ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://x.com/i/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://api.x.com/2/oauth2/token";
const PROFILE_ENDPOINT: &str = "https://api.x.com/2/users/me?user.fields=profile_image_url";
const EMAIL_ENDPOINT: &str = "https://api.x.com/2/users/me?user.fields=confirmed_email";
const DEFAULT_SCOPES: &[&str] = &["users.read", "tweet.read", "offline.access", "users.email"];

pub const TWITTER_ID: &str = "twitter";
pub const TWITTER_NAME: &str = "Twitter";
pub const TWITTER_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const TWITTER_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const TWITTER_PROFILE_ENDPOINT: &str = PROFILE_ENDPOINT;
pub const TWITTER_EMAIL_ENDPOINT: &str = EMAIL_ENDPOINT;
pub const TWITTER_DEFAULT_SCOPES: &[&str] = DEFAULT_SCOPES;

pub type TwitterUserInfoFuture =
    Pin<Box<dyn Future<Output = Result<Option<TwitterUserInfo>, OAuthError>> + Send>>;
pub type TwitterRefreshFuture =
    Pin<Box<dyn Future<Output = Result<OAuth2Tokens, OAuthError>> + Send>>;
pub type TwitterGetUserInfo = Arc<dyn Fn(OAuth2Tokens) -> TwitterUserInfoFuture + Send + Sync>;
pub type TwitterRefreshAccessToken = Arc<dyn Fn(String) -> TwitterRefreshFuture + Send + Sync>;
pub type TwitterProfileMapper = Arc<dyn Fn(&TwitterProfile) -> TwitterUserPatch + Send + Sync>;

/// Twitter profile returned by `GET /2/users/me`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TwitterProfile {
    pub data: TwitterProfileData,
    #[serde(default)]
    pub includes: Option<TwitterIncludes>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Twitter profile `data` payload.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TwitterProfileData {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub entities: Option<TwitterEntities>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub profile_image_url: Option<String>,
    #[serde(default)]
    pub protected: Option<bool>,
    #[serde(default)]
    pub pinned_tweet_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Twitter entity metadata for profile URLs and descriptions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TwitterEntities {
    #[serde(default)]
    pub url: Option<TwitterUrlEntity>,
    #[serde(default)]
    pub description: Option<TwitterDescriptionEntities>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Twitter URL entities.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TwitterUrlEntity {
    #[serde(default)]
    pub urls: Vec<TwitterExpandedUrl>,
}

/// Twitter expanded URL metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwitterExpandedUrl {
    pub start: u64,
    pub end: u64,
    pub url: String,
    pub expanded_url: String,
    pub display_url: String,
}

/// Twitter description entity metadata.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TwitterDescriptionEntities {
    #[serde(default)]
    pub hashtags: Vec<TwitterHashtag>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Twitter hashtag metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwitterHashtag {
    pub start: u64,
    pub end: u64,
    pub tag: String,
}

/// Twitter included expanded resources.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TwitterIncludes {
    #[serde(default)]
    pub tweets: Option<Vec<TwitterIncludedTweet>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Included tweet payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwitterIncludedTweet {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TwitterEmailResponse {
    data: TwitterEmailData,
}

#[derive(Debug, Clone, Deserialize)]
struct TwitterEmailData {
    confirmed_email: Option<String>,
}

/// Partial user override returned by `map_profile_to_user`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwitterUserPatch {
    pub id: Option<String>,
    pub name: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub image: Option<Option<String>>,
    pub email_verified: Option<bool>,
}

impl TwitterUserPatch {
    fn apply_to(self, user: &mut OAuth2UserInfo) {
        if let Some(id) = self.id {
            user.id = id;
        }
        if let Some(name) = self.name {
            user.name = name;
        }
        if let Some(email) = self.email {
            user.email = email;
        }
        if let Some(image) = self.image {
            user.image = image;
        }
        if let Some(email_verified) = self.email_verified {
            user.email_verified = email_verified;
        }
    }
}

/// User info plus raw Twitter profile data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TwitterUserInfo {
    pub user: OAuth2UserInfo,
    pub data: TwitterProfile,
}

/// Inputs required to build the Twitter authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwitterAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

/// Inputs required to exchange a Twitter authorization code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TwitterValidateAuthorizationCodeRequest {
    pub code: String,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
}

/// Configuration for Twitter as a Better Auth-compatible social provider.
#[derive(Clone, Default)]
pub struct TwitterOptions {
    pub oauth: ProviderOptions,
    pub get_user_info: Option<TwitterGetUserInfo>,
    pub map_profile_to_user: Option<TwitterProfileMapper>,
    pub refresh_access_token: Option<TwitterRefreshAccessToken>,
}

impl From<ProviderOptions> for TwitterOptions {
    fn from(oauth: ProviderOptions) -> Self {
        Self {
            oauth,
            get_user_info: None,
            map_profile_to_user: None,
            refresh_access_token: None,
        }
    }
}

/// Twitter OAuth provider.
#[derive(Clone)]
pub struct TwitterProvider {
    client: OAuth2Client,
    options: TwitterOptions,
}

impl TwitterProvider {
    #[deprecated(note = "use advanced::twitter::twitter() instead")]
    pub fn new(options: impl Into<TwitterOptions>) -> Result<Self, OAuthError> {
        let options = options.into();
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("twitter", options.oauth.clone())
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?
            .authentication(ClientAuthentication::Basic);
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
            options,
        })
    }

    pub fn options(&self) -> &TwitterOptions {
        &self.options
    }

    pub fn provider_options(&self) -> &ProviderOptions {
        self.client.options()
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn profile_endpoint(&self) -> &str {
        PROFILE_ENDPOINT
    }

    pub fn email_endpoint(&self) -> &str {
        EMAIL_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        input: TwitterAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(input.state, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        url.scopes(input.scopes).build()
    }

    pub fn create_authorization_code_request(
        &self,
        input: TwitterValidateAuthorizationCodeRequest,
    ) -> Result<OAuthFormRequest, OAuthError> {
        let mut exchange = self.client.exchange_code(input.code, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        input: TwitterValidateAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut exchange = self.client.exchange_code(input.code, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.send().await
    }

    pub fn create_refresh_access_token_request(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .refresh_token(refresh_token_value)?
            .into_form_request()
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let refresh_token_value = refresh_token_value.into();
        if let Some(refresh_access_token) = &self.options.refresh_access_token {
            return refresh_access_token(refresh_token_value).await;
        }

        self.client.refresh_token(refresh_token_value)?.send().await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<TwitterUserInfo>, OAuthError> {
        if let Some(get_user_info) = &self.options.get_user_info {
            return get_user_info(token.clone()).await;
        }

        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let client = crate::http::shared_client();
        let Some(profile) = fetch_twitter_profile(&client, access_token).await else {
            return Ok(None);
        };
        let confirmed_email = fetch_twitter_confirmed_email(&client, access_token).await;

        Ok(Some(self.map_profile(profile, confirmed_email)))
    }

    pub fn user_info_from_profile(
        mut profile: TwitterProfile,
        confirmed_email: Option<String>,
    ) -> TwitterUserInfo {
        let email_verified = confirmed_email.is_some();
        if let Some(email) = confirmed_email {
            profile.data.email = Some(email);
        }

        TwitterUserInfo {
            user: OAuth2UserInfo {
                id: profile.data.id.clone(),
                name: Some(profile.data.name.clone()),
                email: profile
                    .data
                    .email
                    .clone()
                    .filter(|email| !email.is_empty())
                    .or_else(|| {
                        (!profile.data.username.is_empty()).then(|| profile.data.username.clone())
                    }),
                image: profile.data.profile_image_url.clone(),
                email_verified,
            },
            data: profile,
        }
    }

    pub fn map_profile(
        &self,
        profile: TwitterProfile,
        confirmed_email: Option<String>,
    ) -> TwitterUserInfo {
        let mut user_info = Self::user_info_from_profile(profile, confirmed_email);
        if let Some(map_profile_to_user) = &self.options.map_profile_to_user {
            map_profile_to_user(&user_info.data).apply_to(&mut user_info.user);
        }
        user_info
    }

    pub fn id(&self) -> &str {
        TWITTER_ID
    }

    pub fn name(&self) -> &str {
        TWITTER_NAME
    }
}

impl ProviderIdentity for TwitterProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

#[allow(deprecated)]
pub fn twitter(options: impl Into<TwitterOptions>) -> Result<TwitterProvider, OAuthError> {
    TwitterProvider::new(options)
}

async fn fetch_twitter_profile(
    client: &reqwest::Client,
    access_token: &str,
) -> Option<TwitterProfile> {
    client
        .get(PROFILE_ENDPOINT)
        .bearer_auth(access_token)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json::<TwitterProfile>()
        .await
        .ok()
}

async fn fetch_twitter_confirmed_email(
    client: &reqwest::Client,
    access_token: &str,
) -> Option<String> {
    client
        .get(EMAIL_ENDPOINT)
        .bearer_auth(access_token)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json::<TwitterEmailResponse>()
        .await
        .ok()?
        .data
        .confirmed_email
}
