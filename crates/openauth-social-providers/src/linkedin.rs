//! LinkedIn OpenID Connect social provider.

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

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

/// A normalized OpenAuth user and the raw LinkedIn profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInUserInfo {
    pub user: OAuth2UserInfo,
    pub data: LinkedInProfile,
}

/// LinkedIn OAuth/OIDC provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInProvider {
    options: ProviderOptions,
}

pub fn linkedin(options: ProviderOptions) -> LinkedInProvider {
    LinkedInProvider::new(options)
}

impl LinkedInProvider {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }

    pub fn id(&self) -> &str {
        LINKEDIN_ID
    }

    pub fn name(&self) -> &str {
        LINKEDIN_NAME
    }

    pub fn options(&self) -> &ProviderOptions {
        &self.options
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
        create_authorization_url(AuthorizationUrlRequest {
            id: LINKEDIN_ID.to_owned(),
            options: self.options.clone(),
            authorization_endpoint: LINKEDIN_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            scopes: self.scopes(request.scopes),
            login_hint: request.login_hint,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.clone(),
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: LINKEDIN_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
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
        refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token.into(),
            options: self.options.clone(),
            authentication: ClientAuthentication::Post,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: LINKEDIN_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.clone(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
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

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.disable_default_scope {
            Vec::new()
        } else {
            LINKEDIN_DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        };
        scopes.extend(self.options.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl Default for LinkedInProvider {
    fn default() -> Self {
        Self::new(ProviderOptions::default())
    }
}

impl OAuthProviderContract for LinkedInProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}
