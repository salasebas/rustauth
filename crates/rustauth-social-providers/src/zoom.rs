//! Zoom OAuth provider.

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::http::ProviderHttpClient;
use crate::runtime::ProviderIdentity;

pub const ZOOM_ID: &str = "zoom";
pub const ZOOM_NAME: &str = "Zoom";
pub const ZOOM_AUTHORIZATION_ENDPOINT: &str = "https://zoom.us/oauth/authorize";
pub const ZOOM_TOKEN_ENDPOINT: &str = "https://zoom.us/oauth/token";
pub const ZOOM_USER_INFO_ENDPOINT: &str = "https://api.zoom.us/v2/users/me";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoomOptions {
    pub oauth: ProviderOptions,
    pub pkce: bool,
}

impl Default for ZoomOptions {
    fn default() -> Self {
        Self {
            oauth: ProviderOptions::default(),
            pkce: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoomAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoomAuthorizationCodeRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoomPhoneNumber {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(default)]
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ZoomCustomAttribute {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ZoomProfile {
    pub account_id: Option<String>,
    pub account_number: Option<u64>,
    pub cluster: Option<String>,
    pub cms_user_id: Option<String>,
    pub company: Option<String>,
    pub cost_center: Option<String>,
    pub created_at: Option<String>,
    pub custom_attributes: Vec<ZoomCustomAttribute>,
    pub dept: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub employee_unique_id: Option<String>,
    pub first_name: Option<String>,
    pub group_ids: Vec<String>,
    pub id: String,
    pub im_group_ids: Vec<String>,
    pub jid: Option<String>,
    pub job_title: Option<String>,
    pub language: Option<String>,
    pub last_client_version: Option<String>,
    pub last_login_time: Option<String>,
    pub last_name: Option<String>,
    pub location: Option<String>,
    pub login_types: Vec<i64>,
    pub manager: Option<String>,
    pub personal_meeting_url: Option<String>,
    pub phone_numbers: Vec<ZoomPhoneNumber>,
    pub pic_url: Option<String>,
    pub plan_united_type: Option<String>,
    pub pmi: Option<u64>,
    pub pronouns: Option<String>,
    pub pronouns_option: Option<i64>,
    pub role_id: Option<String>,
    pub role_name: Option<String>,
    pub status: Option<String>,
    pub timezone: Option<String>,
    pub use_pmi: Option<bool>,
    pub user_created_at: Option<String>,
    pub vanity_url: Option<String>,
    pub verified: i64,
    pub zoom_one_type: Option<i64>,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZoomUserInfo {
    pub user: OAuth2UserInfo,
    pub data: ZoomProfile,
}

#[derive(Debug, Clone)]
pub struct ZoomProvider {
    client: OAuth2Client,
    pkce: bool,
    user_info_endpoint: String,
    http_client: ProviderHttpClient,
}

#[allow(deprecated)]
pub fn zoom(options: ZoomOptions) -> Result<ZoomProvider, OAuthError> {
    ZoomProvider::new(options)
}

impl ZoomProvider {
    #[deprecated(note = "use advanced::zoom::zoom() instead")]
    pub fn new(options: ZoomOptions) -> Result<Self, OAuthError> {
        let pkce = options.pkce;
        Ok(Self {
            client: OAuth2Client::builder(ZOOM_ID, options.oauth)
                .authorization_endpoint(ZOOM_AUTHORIZATION_ENDPOINT)?
                .token_endpoint(ZOOM_TOKEN_ENDPOINT)?
                .build()?,
            pkce,
            user_info_endpoint: ZOOM_USER_INFO_ENDPOINT.to_owned(),
            http_client: ProviderHttpClient::shared(),
        })
    }

    pub fn new_with_user_info_endpoint(
        options: ZoomOptions,
        user_info_endpoint: impl Into<String>,
    ) -> Result<Self, OAuthError> {
        #[allow(deprecated)]
        let mut provider = Self::new(options)?;
        provider.user_info_endpoint = user_info_endpoint.into();
        Ok(provider)
    }

    /// Overrides the HTTP client used for userinfo requests. Use
    /// [`ProviderHttpClient::permissive`] in tests to reach local fixtures.
    pub fn with_http_client(mut self, http_client: ProviderHttpClient) -> Self {
        self.http_client = http_client;
        self
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn token_endpoint(&self) -> &str {
        ZOOM_TOKEN_ENDPOINT
    }

    pub fn user_info_endpoint(&self) -> &str {
        &self.user_info_endpoint
    }

    pub fn create_authorization_url(
        &self,
        request: ZoomAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let code_verifier = if self.pkce {
            Some(
                request
                    .code_verifier
                    .filter(|value| !value.is_empty())
                    .ok_or(OAuthError::MissingOption("code_verifier"))?,
            )
        } else {
            None
        };

        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            url = url.code_verifier(code_verifier);
        }
        url.build()
    }

    pub async fn validate_authorization_code(
        &self,
        request: ZoomAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let code_verifier = self.resolve_authorization_code_verifier(request.code_verifier)?;
        let mut exchange = self
            .client
            .exchange_code(request.code, request.redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.send().await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut refresh = self.client.refresh_token(refresh_token)?;
        if let Some(client_key) = self.client.options().client_key.clone() {
            refresh = refresh.extra_param("client_key", client_key);
        }
        refresh.send().await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<ZoomUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let response = match self
            .http_client
            .get(&self.user_info_endpoint)?
            .header("authorization", format!("Bearer {access_token}"))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };

        if !response.status().is_success() {
            return Ok(None);
        }

        let profile = match response.json::<ZoomProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };

        Ok(Some(Self::map_profile(profile)))
    }

    pub fn map_profile(profile: ZoomProfile) -> ZoomUserInfo {
        let user = Self::map_profile_to_user_info(&profile);
        ZoomUserInfo {
            user,
            data: profile,
        }
    }

    pub fn map_profile_to_user_info(profile: &ZoomProfile) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: profile.id.clone(),
            name: profile.display_name.clone(),
            email: profile.email.clone(),
            image: profile.pic_url.clone(),
            email_verified: profile.verified != 0,
        }
    }

    fn resolve_authorization_code_verifier(
        &self,
        code_verifier: Option<String>,
    ) -> Result<Option<String>, OAuthError> {
        if !self.pkce {
            return Ok(code_verifier);
        }

        code_verifier
            .filter(|value| !value.is_empty())
            .ok_or(OAuthError::MissingOption("code_verifier"))
            .map(Some)
    }
}

impl ProviderIdentity for ZoomProvider {
    fn id(&self) -> &str {
        ZOOM_ID
    }

    fn name(&self) -> &str {
        ZOOM_NAME
    }
}
