//! LinkedIn OpenID Connect social provider.

use rustauth_oauth::oauth2::ClientAuthentication;
use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

pub const LINKEDIN_ID: &str = "linkedin";
pub const LINKEDIN_NAME: &str = "Linkedin";
pub const LINKEDIN_AUTHORIZATION_ENDPOINT: &str = "https://www.linkedin.com/oauth/v2/authorization";
pub const LINKEDIN_TOKEN_ENDPOINT: &str = "https://www.linkedin.com/oauth/v2/accessToken";
pub const LINKEDIN_USERINFO_ENDPOINT: &str = "https://api.linkedin.com/v2/userinfo";
pub const LINKEDIN_DEFAULT_SCOPES: &[&str] = &["profile", "email", "openid"];

/// LinkedIn locale claim returned by the OpenID Connect userinfo endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInLocale {
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub language: String,
}

/// LinkedIn OpenID Connect profile returned by `/v2/userinfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInProfile {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub given_name: String,
    #[serde(default)]
    pub family_name: String,
    #[serde(default)]
    pub picture: Option<String>,
    #[serde(default)]
    pub locale: Option<LinkedInLocale>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
}

/// Input used to create a LinkedIn authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkedInAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

/// A normalized RustAuth user and the raw LinkedIn profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInUserInfo {
    pub user: OAuth2UserInfo,
    pub data: LinkedInProfile,
}

/// LinkedIn OAuth/OIDC provider.
#[derive(Debug, Clone)]
pub struct LinkedInProvider {
    client: OAuth2Client,
}

#[allow(deprecated)]
pub fn linkedin(options: ProviderOptions) -> Result<LinkedInProvider, OAuthError> {
    LinkedInProvider::new(options)
}

impl LinkedInProvider {
    #[deprecated(note = "use advanced::linkedin::linkedin() instead")]
    pub fn new(options: ProviderOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.disable_default_scope;
        let mut builder = OAuth2Client::builder(LINKEDIN_ID, options)
            .authorization_endpoint(LINKEDIN_AUTHORIZATION_ENDPOINT)?
            .token_endpoint(LINKEDIN_TOKEN_ENDPOINT)?
            .authentication(ClientAuthentication::Post);
        if !disable_default_scope {
            builder = builder.default_scopes(LINKEDIN_DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn authorization_endpoint(&self) -> &str {
        LINKEDIN_AUTHORIZATION_ENDPOINT
    }

    pub fn token_endpoint(&self) -> &str {
        LINKEDIN_TOKEN_ENDPOINT
    }

    pub fn userinfo_endpoint(&self) -> &str {
        LINKEDIN_USERINFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: LinkedInAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?
            .scopes(request.scopes);
        if let Some(login_hint) = request.login_hint {
            url = url.login_hint(login_hint);
        }
        url.build()
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .exchange_code(code, redirect_uri)?
            .into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.exchange_code(code, redirect_uri)?.send().await
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

    pub async fn get_user_info(&self, token: &OAuth2Tokens) -> Option<LinkedInUserInfo> {
        let access_token = token.access_token.as_deref()?;
        let profile = crate::http::shared_client()
            .get(LINKEDIN_USERINFO_ENDPOINT)
            .bearer_auth(access_token)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json::<LinkedInProfile>()
            .await
            .ok()?;

        Some(Self::user_info_from_profile(profile))
    }

    pub fn user_info_from_profile(profile: LinkedInProfile) -> LinkedInUserInfo {
        let user = Self::map_profile_to_user_info(&profile);
        LinkedInUserInfo {
            user,
            data: profile,
        }
    }

    pub fn map_profile_to_user_info(profile: &LinkedInProfile) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: profile.sub.clone(),
            name: (!profile.name.is_empty()).then(|| profile.name.clone()),
            email: profile.email.clone(),
            image: profile.picture.clone(),
            email_verified: profile.email_verified.unwrap_or(false),
        }
    }
}

impl ProviderIdentity for LinkedInProvider {
    fn id(&self) -> &str {
        LINKEDIN_ID
    }

    fn name(&self) -> &str {
        LINKEDIN_NAME
    }
}
