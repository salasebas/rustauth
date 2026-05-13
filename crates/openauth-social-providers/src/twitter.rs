//! Twitter/X social OAuth provider.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_oauth::oauth2::{
    create_authorization_code_request, create_authorization_url,
    create_refresh_access_token_request, refresh_access_token, validate_authorization_code,
    AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract,
    ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const TWITTER_ID: &str = "twitter";
pub const TWITTER_NAME: &str = "Twitter";
pub const TWITTER_AUTHORIZATION_ENDPOINT: &str = "https://x.com/i/oauth2/authorize";
pub const TWITTER_TOKEN_ENDPOINT: &str = "https://api.x.com/2/oauth2/token";
pub const TWITTER_PROFILE_ENDPOINT: &str =
    "https://api.x.com/2/users/me?user.fields=profile_image_url";
pub const TWITTER_EMAIL_ENDPOINT: &str = "https://api.x.com/2/users/me?user.fields=confirmed_email";
pub const TWITTER_DEFAULT_SCOPES: &[&str] =
    &["users.read", "tweet.read", "offline.access", "users.email"];

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
#[derive(Clone, Default)]
pub struct TwitterProvider {
    options: TwitterOptions,
}

impl TwitterProvider {
    pub fn new(options: impl Into<TwitterOptions>) -> Self {
        Self {
            options: options.into(),
        }
    }

    pub fn options(&self) -> &TwitterOptions {
        &self.options
    }

    pub fn provider_options(&self) -> &ProviderOptions {
        &self.options.oauth
    }

    pub fn token_endpoint(&self) -> &str {
        TWITTER_TOKEN_ENDPOINT
    }

    pub fn profile_endpoint(&self) -> &str {
        TWITTER_PROFILE_ENDPOINT
    }

    pub fn email_endpoint(&self) -> &str {
        TWITTER_EMAIL_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        input: TwitterAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: self.id().to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: TWITTER_AUTHORIZATION_ENDPOINT.to_owned(),
            scopes: self.authorization_scopes(input.scopes),
            state: input.state,
            code_verifier: input.code_verifier,
            redirect_uri: input.redirect_uri,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn create_authorization_code_request(
        &self,
        input: TwitterValidateAuthorizationCodeRequest,
    ) -> Result<OAuthFormRequest, OAuthError> {
        create_authorization_code_request(AuthorizationCodeRequest {
            code: input.code,
            code_verifier: input.code_verifier,
            redirect_uri: input.redirect_uri,
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Basic,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        input: TwitterValidateAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: TWITTER_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: input.code,
                code_verifier: input.code_verifier,
                redirect_uri: input.redirect_uri,
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Basic,
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub fn create_refresh_access_token_request(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        create_refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token_value.into(),
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Basic,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let refresh_token_value = refresh_token_value.into();
        if let Some(refresh_access_token) = &self.options.refresh_access_token {
            return refresh_access_token(refresh_token_value).await;
        }

        refresh_access_token(ClientTokenRequest {
            token_endpoint: TWITTER_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token_value,
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
    ) -> Result<Option<TwitterUserInfo>, OAuthError> {
        if let Some(get_user_info) = &self.options.get_user_info {
            return get_user_info(token.clone()).await;
        }

        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let client = reqwest::Client::new();
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

    fn authorization_scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = Vec::new();
        if !self.options.oauth.disable_default_scope {
            scopes.extend(
                TWITTER_DEFAULT_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_owned()),
            );
        }
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl OAuthProviderContract for TwitterProvider {
    fn id(&self) -> &str {
        TWITTER_ID
    }

    fn name(&self) -> &str {
        TWITTER_NAME
    }
}

pub fn twitter(options: impl Into<TwitterOptions>) -> TwitterProvider {
    TwitterProvider::new(options)
}

async fn fetch_twitter_profile(
    client: &reqwest::Client,
    access_token: &str,
) -> Option<TwitterProfile> {
    client
        .get(TWITTER_PROFILE_ENDPOINT)
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
        .get(TWITTER_EMAIL_ENDPOINT)
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
