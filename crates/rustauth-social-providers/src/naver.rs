//! Naver social OAuth provider.

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

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
#[derive(Debug, Clone)]
pub struct NaverProvider {
    client: OAuth2Client,
}

#[allow(deprecated)]
pub fn naver(oauth: ProviderOptions) -> Result<NaverProvider, OAuthError> {
    NaverProvider::new(NaverProviderOptions { oauth })
}

impl NaverProvider {
    #[deprecated(note = "use advanced::naver::naver() instead")]
    pub fn new(options: NaverProviderOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder(NAVER_ID, options.oauth)
            .authorization_endpoint(NAVER_AUTHORIZATION_ENDPOINT)?
            .token_endpoint(NAVER_TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
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
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?;
        if let Some(code_verifier) = request.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        url.scopes(request.scopes).build()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
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
}

impl ProviderIdentity for NaverProvider {
    fn id(&self) -> &str {
        NAVER_ID
    }

    fn name(&self) -> &str {
        NAVER_NAME
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
