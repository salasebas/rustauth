//! TikTok social OAuth provider.

use rustauth_oauth::oauth2::{
    create_authorization_code_request, create_refresh_access_token_request,
    exchange_authorization_code, refresh_access_token_at, validate_authorization_url_invariants,
    AuthorizationCodeRequest, ClientAuthentication, ClientId, OAuth2Client, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://www.tiktok.com/v2/auth/authorize";
const TOKEN_ENDPOINT: &str = "https://open.tiktokapis.com/v2/oauth/token/";
const USERINFO_ENDPOINT: &str = "https://open.tiktokapis.com/v2/user/info/";
const DEFAULT_SCOPE: &str = "user.info.profile";

const USERINFO_FIELDS: &[&str] = &["open_id", "avatar_large_url", "display_name", "username"];

pub const TIKTOK_ID: &str = "tiktok";
pub const TIKTOK_NAME: &str = "TikTok";
pub const TIKTOK_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const TIKTOK_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const TIKTOK_USERINFO_ENDPOINT: &str = USERINFO_ENDPOINT;
pub const TIKTOK_DEFAULT_SCOPE: &str = DEFAULT_SCOPE;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TiktokProfile {
    pub data: TiktokProfileData,
    #[serde(default)]
    pub error: Option<TiktokError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TiktokProfileData {
    pub user: TiktokUser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TiktokUser {
    pub open_id: String,
    #[serde(default)]
    pub union_id: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub avatar_url_100: Option<String>,
    pub avatar_large_url: String,
    pub display_name: String,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub bio_description: Option<String>,
    #[serde(default)]
    pub profile_deep_link: Option<String>,
    #[serde(default)]
    pub is_verified: Option<bool>,
    #[serde(default)]
    pub follower_count: Option<u64>,
    #[serde(default)]
    pub following_count: Option<u64>,
    #[serde(default)]
    pub likes_count: Option<u64>,
    #[serde(default)]
    pub video_count: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TiktokError {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub log_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TiktokAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TiktokValidateAuthorizationCodeRequest {
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TiktokUserInfo {
    pub user: OAuth2UserInfo,
    pub data: TiktokProfile,
}

#[derive(Debug, Clone)]
pub struct TiktokProvider {
    client: OAuth2Client,
    token_options: ProviderOptions,
    http_client: reqwest::Client,
}

#[allow(deprecated)]
pub fn tiktok(options: ProviderOptions) -> Result<TiktokProvider, OAuthError> {
    TiktokProvider::new(options)
}

impl TiktokProvider {
    #[deprecated(note = "use advanced::tiktok::tiktok() instead")]
    pub fn new(options: ProviderOptions) -> Result<Self, OAuthError> {
        Self::ensure_token_credentials(&options)?;
        let token_options = options.clone();
        let build_options = Self::oauth_for_client(options)?;
        let disable_default_scope = token_options.disable_default_scope;
        let mut builder = OAuth2Client::builder("tiktok", build_options)
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?
            .scope_joiner(",");
        if !disable_default_scope {
            builder = builder.default_scope(DEFAULT_SCOPE);
        }
        Ok(Self {
            client: builder.build()?,
            token_options,
            http_client: crate::http::shared_client(),
        })
    }

    pub fn id(&self) -> &str {
        TIKTOK_ID
    }

    pub fn name(&self) -> &str {
        TIKTOK_NAME
    }

    pub fn options(&self) -> ProviderOptions {
        self.token_options.clone()
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn userinfo_endpoint(&self) -> &str {
        USERINFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: TiktokAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        validate_authorization_url_invariants(
            &request.state,
            self.token_options.redirect_uri.as_deref(),
            &request.redirect_uri,
        )?;
        let client_key = self.client_key()?;
        let redirect_uri = self
            .token_options
            .redirect_uri
            .as_deref()
            .unwrap_or(&request.redirect_uri);
        let scopes = self.scopes(request.scopes);
        let mut url = Url::parse(AUTHORIZATION_ENDPOINT)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("scope", &scopes.join(","));
            query.append_pair("response_type", "code");
            query.append_pair("client_key", client_key);
            query.append_pair("redirect_uri", redirect_uri);
            query.append_pair("state", &request.state);
        }
        Ok(url)
    }

    pub fn authorization_code_request(
        &self,
        request: TiktokValidateAuthorizationCodeRequest,
    ) -> Result<OAuthFormRequest, OAuthError> {
        Self::ensure_token_credentials(&self.token_options)?;
        create_authorization_code_request(self.authorization_code_exchange(request)?)
    }

    pub async fn validate_authorization_code(
        &self,
        request: TiktokValidateAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        Self::ensure_token_credentials(&self.token_options)?;
        exchange_authorization_code(
            self.client.token_endpoint().as_str(),
            self.authorization_code_exchange(request)?,
            self.client.http(),
        )
        .await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        Self::ensure_token_credentials(&self.token_options)?;
        create_refresh_access_token_request(self.refresh_exchange(refresh_token)?)
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        Self::ensure_token_credentials(&self.token_options)?;
        refresh_access_token_at(
            self.client.token_endpoint().as_str(),
            self.refresh_exchange(refresh_token)?,
            self.client.http(),
        )
        .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<TiktokUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = self
            .http_client
            .get(USERINFO_ENDPOINT)
            .query(&[("fields", USERINFO_FIELDS.join(","))])
            .bearer_auth(access_token)
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }

        let profile = match response.json::<TiktokProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(Self::user_info_from_profile(profile)))
    }

    pub fn user_info_from_profile(profile: TiktokProfile) -> TiktokUserInfo {
        let user = Self::map_profile_to_user_info(&profile);
        TiktokUserInfo {
            user,
            data: profile,
        }
    }

    pub fn map_profile_to_user_info(profile: &TiktokProfile) -> OAuth2UserInfo {
        let user = &profile.data.user;
        OAuth2UserInfo {
            id: user.open_id.clone(),
            name: Some(non_empty_or(&user.display_name, &user.username).to_owned()),
            email: Some(
                user.email
                    .as_deref()
                    .filter(|email| !email.is_empty())
                    .unwrap_or(&user.username)
                    .to_owned(),
            ),
            image: Some(user.avatar_large_url.clone()),
            email_verified: false,
        }
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.token_options.disable_default_scope {
            Vec::new()
        } else {
            vec![DEFAULT_SCOPE.to_owned()]
        };
        scopes.extend(self.token_options.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }

    fn client_key(&self) -> Result<&str, OAuthError> {
        self.token_options
            .client_key
            .as_deref()
            .filter(|client_key| !client_key.is_empty())
            .ok_or(OAuthError::MissingOption("client_key"))
    }

    fn ensure_token_credentials(options: &ProviderOptions) -> Result<(), OAuthError> {
        if options
            .client_key
            .as_deref()
            .filter(|client_key| !client_key.is_empty())
            .is_none()
        {
            return Err(OAuthError::MissingOption("client_key"));
        }
        if options
            .client_secret_str()
            .filter(|client_secret| !client_secret.is_empty())
            .is_none()
        {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }

    fn oauth_for_client(mut options: ProviderOptions) -> Result<ProviderOptions, OAuthError> {
        if options.client_id.is_none() {
            let client_key = options
                .client_key
                .as_deref()
                .filter(|client_key| !client_key.is_empty())
                .ok_or(OAuthError::MissingOption("client_key"))?;
            options.client_id = Some(ClientId::from(client_key));
        }
        Ok(options)
    }

    fn authorization_code_exchange(
        &self,
        request: TiktokValidateAuthorizationCodeRequest,
    ) -> Result<AuthorizationCodeRequest, OAuthError> {
        Ok(AuthorizationCodeRequest::try_new(
            request.code,
            request.redirect_uri,
            self.token_options.clone(),
        )?
        .authentication(ClientAuthentication::Post))
    }

    fn refresh_exchange(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<RefreshAccessTokenRequest, OAuthError> {
        Ok(
            RefreshAccessTokenRequest::try_new(refresh_token, self.token_options.clone())?
                .authentication(ClientAuthentication::Post)
                .extra_param("client_key", self.client_key()?),
        )
    }
}

impl ProviderIdentity for TiktokProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

fn non_empty_or<'a>(candidate: &'a str, fallback: &'a str) -> &'a str {
    if candidate.is_empty() {
        fallback
    } else {
        candidate
    }
}
