//! TikTok social OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    authorization_code_request, refresh_access_token, refresh_access_token_request,
    validate_authorization_code, AuthorizationCodeRequest, ClientAuthentication,
    ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest,
    OAuthProviderContract, ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

pub const TIKTOK_ID: &str = "tiktok";
pub const TIKTOK_NAME: &str = "TikTok";
pub const TIKTOK_AUTHORIZATION_ENDPOINT: &str = "https://www.tiktok.com/v2/auth/authorize";
pub const TIKTOK_TOKEN_ENDPOINT: &str = "https://open.tiktokapis.com/v2/oauth/token/";
pub const TIKTOK_USERINFO_ENDPOINT: &str = "https://open.tiktokapis.com/v2/user/info/";
pub const TIKTOK_DEFAULT_SCOPE: &str = "user.info.profile";

const TIKTOK_USERINFO_FIELDS: &[&str] =
    &["open_id", "avatar_large_url", "display_name", "username"];

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
    options: ProviderOptions,
    http_client: reqwest::Client,
}

pub fn tiktok(options: ProviderOptions) -> TiktokProvider {
    TiktokProvider::new(options)
}

impl TiktokProvider {
    pub fn new(options: ProviderOptions) -> Self {
        Self {
            options,
            http_client: crate::http::shared_client(),
        }
    }

    pub fn id(&self) -> &str {
        TIKTOK_ID
    }

    pub fn name(&self) -> &str {
        TIKTOK_NAME
    }

    pub fn options(&self) -> &ProviderOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        TIKTOK_TOKEN_ENDPOINT
    }

    pub fn userinfo_endpoint(&self) -> &str {
        TIKTOK_USERINFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: TiktokAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let client_key = self.client_key()?;
        let redirect_uri = self
            .options
            .redirect_uri
            .as_deref()
            .unwrap_or(&request.redirect_uri);
        let scopes = self.scopes(request.scopes);
        let mut url = Url::parse(TIKTOK_AUTHORIZATION_ENDPOINT)?;
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
        self.ensure_token_credentials()?;
        authorization_code_request(AuthorizationCodeRequest {
            code: request.code,
            redirect_uri: request.redirect_uri,
            options: self.options.clone(),
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        request: TiktokValidateAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.ensure_token_credentials()?;
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: TIKTOK_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: request.code,
                redirect_uri: request.redirect_uri,
                options: self.options.clone(),
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
        self.ensure_token_credentials()?;
        refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token.into(),
            options: self.options.clone(),
            authentication: ClientAuthentication::Post,
            extra_params: self.refresh_extra_params()?,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.ensure_token_credentials()?;
        refresh_access_token(ClientTokenRequest {
            token_endpoint: TIKTOK_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.clone(),
                authentication: ClientAuthentication::Post,
                extra_params: self.refresh_extra_params()?,
                ..RefreshAccessTokenRequest::default()
            },
        })
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
            .get(TIKTOK_USERINFO_ENDPOINT)
            .query(&[("fields", TIKTOK_USERINFO_FIELDS.join(","))])
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
        let mut scopes = if self.options.disable_default_scope {
            Vec::new()
        } else {
            vec![TIKTOK_DEFAULT_SCOPE.to_owned()]
        };
        scopes.extend(self.options.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }

    fn client_key(&self) -> Result<&str, OAuthError> {
        self.options
            .client_key
            .as_deref()
            .filter(|client_key| !client_key.is_empty())
            .ok_or(OAuthError::MissingOption("client_key"))
    }

    fn ensure_token_credentials(&self) -> Result<(), OAuthError> {
        self.client_key()?;
        if self
            .options
            .client_secret
            .as_deref()
            .filter(|client_secret| !client_secret.is_empty())
            .is_none()
        {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }

    fn refresh_extra_params(&self) -> Result<BTreeMap<String, String>, OAuthError> {
        Ok(BTreeMap::from([(
            "client_key".to_owned(),
            self.client_key()?.to_owned(),
        )]))
    }
}

impl OAuthProviderContract for TiktokProvider {
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
