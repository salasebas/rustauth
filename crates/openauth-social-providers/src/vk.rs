//! VK social OAuth provider.

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

pub const VK_ID: &str = "vk";
pub const VK_NAME: &str = "VK";
pub const VK_AUTHORIZATION_ENDPOINT: &str = "https://id.vk.com/authorize";
pub const VK_TOKEN_ENDPOINT: &str = "https://id.vk.com/oauth2/auth";
pub const VK_USER_INFO_ENDPOINT: &str = "https://id.vk.com/oauth2/user_info";

const DEFAULT_SCOPES: &[&str] = &["email", "phone"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VkOptions {
    pub oauth: ProviderOptions,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VkAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VkProfile {
    pub user: VkProfileUser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VkProfileUser {
    pub user_id: String,
    pub first_name: String,
    pub last_name: String,
    pub email: Option<String>,
    pub phone: Option<i64>,
    pub avatar: Option<String>,
    pub sex: Option<i64>,
    pub verified: Option<bool>,
    pub birthday: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VkUserInfo {
    pub user: OAuth2UserInfo,
    pub data: VkProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VkProvider {
    options: VkOptions,
}

pub fn vk(options: VkOptions) -> VkProvider {
    VkProvider::new(options)
}

impl VkProvider {
    pub fn new(options: VkOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &VkOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        VK_TOKEN_ENDPOINT
    }

    pub fn user_info_endpoint(&self) -> &str {
        VK_USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: VkAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: VK_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: VK_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes: self.authorization_scopes(request.scopes),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn create_authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
        device_id: Option<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.oauth.clone(),
            code_verifier,
            device_id,
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
        device_id: Option<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: VK_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                code_verifier,
                device_id,
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
            token_endpoint: VK_TOKEN_ENDPOINT.to_owned(),
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
    ) -> Result<Option<VkUserInfo>, OAuthError> {
        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };
        let Some(client_id) = self.primary_client_id() else {
            return Ok(None);
        };

        let response = crate::http::shared_client()
            .post(VK_USER_INFO_ENDPOINT)
            .header("content-type", "application/x-www-form-urlencoded")
            .form(&[("access_token", access_token), ("client_id", client_id)])
            .send()
            .await;

        let Ok(response) = response else {
            return Ok(None);
        };
        let Ok(response) = response.error_for_status() else {
            return Ok(None);
        };
        let Ok(profile) = response.json::<VkProfile>().await else {
            return Ok(None);
        };

        Ok(Self::user_info_from_profile(profile))
    }

    pub fn user_info_from_profile(profile: VkProfile) -> Option<VkUserInfo> {
        let email = profile.user.email.clone()?;
        let name = format!("{} {}", profile.user.first_name, profile.user.last_name);
        let user = OAuth2UserInfo {
            id: profile.user.user_id.clone(),
            name: Some(name),
            email: Some(email),
            image: profile.user.avatar.clone(),
            email_verified: false,
        };

        Some(VkUserInfo {
            user,
            data: profile,
        })
    }

    fn authorization_scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = Vec::new();
        if !self.options.oauth.disable_default_scope {
            scopes.extend(DEFAULT_SCOPES.iter().map(|scope| (*scope).to_owned()));
        }
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

    fn primary_client_id(&self) -> Option<&str> {
        match self.options.oauth.client_id.as_ref()? {
            openauth_oauth::oauth2::ClientId::Single(value) if !value.is_empty() => Some(value),
            openauth_oauth::oauth2::ClientId::Single(_) => None,
            openauth_oauth::oauth2::ClientId::Multiple(values) => values
                .first()
                .map(String::as_str)
                .filter(|value| !value.is_empty()),
        }
    }
}

impl Default for VkProvider {
    fn default() -> Self {
        Self::new(VkOptions::default())
    }
}

impl OAuthProviderContract for VkProvider {
    fn id(&self) -> &str {
        VK_ID
    }

    fn name(&self) -> &str {
        VK_NAME
    }
}
