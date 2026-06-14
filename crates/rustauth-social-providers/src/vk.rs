//! VK social OAuth provider.

use rustauth_oauth::oauth2::{
    get_primary_client_id, OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthFormRequest, ProviderOptions, RefreshTokenBuilder,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://id.vk.com/authorize";
const TOKEN_ENDPOINT: &str = "https://id.vk.com/oauth2/auth";
const USER_INFO_ENDPOINT: &str = "https://id.vk.com/oauth2/user_info";
const DEFAULT_SCOPES: &[&str] = &["email", "phone"];

pub const VK_ID: &str = "vk";
pub const VK_NAME: &str = "VK";
pub const VK_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const VK_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const VK_USER_INFO_ENDPOINT: &str = USER_INFO_ENDPOINT;

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

#[derive(Debug, Clone)]
pub struct VkProvider {
    client: OAuth2Client,
}

#[allow(deprecated)]
pub fn vk(options: VkOptions) -> Result<VkProvider, OAuthError> {
    VkProvider::new(options)
}

impl VkProvider {
    #[deprecated(note = "use advanced::vk::vk() instead")]
    pub fn new(options: VkOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("vk", options.oauth)
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
        })
    }

    pub fn options(&self) -> VkOptions {
        VkOptions {
            oauth: self.client.options().clone(),
        }
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn user_info_endpoint(&self) -> &str {
        USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: VkAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?
            .scopes(request.scopes);
        if let Some(code_verifier) = request.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        url.build()
    }

    pub fn create_authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
        device_id: Option<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        if let Some(device_id) = device_id {
            exchange = exchange.device_id(device_id);
        }
        exchange.into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
        device_id: Option<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        if let Some(device_id) = device_id {
            exchange = exchange.device_id(device_id);
        }
        exchange.send().await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.refresh_with_extra_params(refresh_token)?
            .into_form_request()
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.refresh_with_extra_params(refresh_token)?.send().await
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
            .post(USER_INFO_ENDPOINT)
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

    pub fn id(&self) -> &str {
        VK_ID
    }

    pub fn name(&self) -> &str {
        VK_NAME
    }

    fn primary_client_id(&self) -> Option<&str> {
        get_primary_client_id(&self.client.options().client_id)
    }

    fn refresh_with_extra_params(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<RefreshTokenBuilder<'_>, OAuthError> {
        let mut refresh = self.client.refresh_token(refresh_token)?;
        if let Some(client_key) = self
            .client
            .options()
            .client_key
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            refresh = refresh.extra_param("client_key", client_key);
        }
        Ok(refresh)
    }
}

impl ProviderIdentity for VkProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}
