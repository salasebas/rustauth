//! Naver social OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

pub const NAVER_ID: &str = "naver";
pub const NAVER_NAME: &str = "Naver";
pub const NAVER_AUTHORIZATION_ENDPOINT: &str = "https://nid.naver.com/oauth2.0/authorize";
pub const NAVER_TOKEN_ENDPOINT: &str = "https://nid.naver.com/oauth2.0/token";
pub const NAVER_USER_INFO_ENDPOINT: &str = "https://openapi.naver.com/v1/nid/me";

const DEFAULT_SCOPES: &[&str] = &["profile", "email"];

/// Naver provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NaverProviderOptions {
    pub oauth: ProviderOptions,
}

/// Input used to create a Naver authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NaverAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

/// Naver profile payload nested under the upstream `response` field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NaverProfileResponse {
    pub id: String,
    #[serde(default)]
    pub nickname: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub gender: String,
    #[serde(default)]
    pub age: String,
    #[serde(default)]
    pub birthday: String,
    #[serde(default)]
    pub birthyear: String,
    #[serde(default)]
    pub profile_image: String,
    #[serde(default)]
    pub mobile: String,
}

/// Naver profile returned by `/v1/nid/me`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NaverProfile {
    pub resultcode: String,
    pub message: String,
    pub response: Option<NaverProfileResponse>,
}

/// User info plus raw Naver profile data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NaverUserInfo {
    pub user: OAuth2UserInfo,
    pub data: NaverProfile,
}

/// Naver OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaverProvider {
    options: NaverProviderOptions,
}

pub fn naver(oauth: ProviderOptions) -> NaverProvider {
    NaverProvider::new(NaverProviderOptions { oauth })
}

impl NaverProvider {
    pub fn new(options: NaverProviderOptions) -> Self {
        Self { options }
    }

    pub fn id(&self) -> &str {
        NAVER_ID
    }

    pub fn name(&self) -> &str {
        NAVER_NAME
    }

    pub fn options(&self) -> &NaverProviderOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        NAVER_TOKEN_ENDPOINT
    }

    pub fn user_info_endpoint(&self) -> &str {
        NAVER_USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: NaverAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: NAVER_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: NAVER_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes: self.scopes(request.scopes),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.oauth.clone(),
            code_verifier: code_verifier.map(Into::into),
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: NAVER_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                code_verifier: code_verifier.map(Into::into),
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
            extra_params: self.refresh_extra_params(),
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: NAVER_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                extra_params: self.refresh_extra_params(),
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<NaverUserInfo>, OAuthError> {
        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(NAVER_USER_INFO_ENDPOINT)
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
        let profile = match response.json::<NaverProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Self::map_profile(profile))
    }

    pub fn map_profile(profile: NaverProfile) -> Option<NaverUserInfo> {
        if profile.resultcode != "00" {
            return None;
        }
        let response = profile.response.as_ref()?;
        let user = Self::map_profile_to_user_info(response);
        Some(NaverUserInfo {
            user,
            data: profile,
        })
    }

    pub fn map_profile_to_user_info(profile: &NaverProfileResponse) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: profile.id.clone(),
            name: Some(profile_name(profile)),
            email: optional_string(&profile.email),
            image: optional_string(&profile.profile_image),
            email_verified: false,
        }
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }

    fn refresh_extra_params(&self) -> BTreeMap<String, String> {
        self.options
            .oauth
            .client_key
            .as_ref()
            .map(|client_key| BTreeMap::from([("client_key".to_owned(), client_key.clone())]))
            .unwrap_or_default()
    }
}

impl Default for NaverProvider {
    fn default() -> Self {
        Self::new(NaverProviderOptions::default())
    }
}

impl OAuthProviderContract for NaverProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

fn profile_name(profile: &NaverProfileResponse) -> String {
    if !profile.name.is_empty() {
        profile.name.clone()
    } else {
        profile.nickname.clone()
    }
}

fn optional_string(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}
