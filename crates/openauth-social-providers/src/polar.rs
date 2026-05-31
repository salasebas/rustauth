//! Polar social OAuth provider.

use std::collections::BTreeMap;
use std::sync::Arc;

use openauth_oauth::oauth2::{
    create_authorization_url, refresh_access_token, validate_authorization_code,
    AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const POLAR_ID: &str = "polar";
pub const POLAR_NAME: &str = "Polar";
pub const POLAR_AUTHORIZATION_ENDPOINT: &str = "https://polar.sh/oauth2/authorize";
pub const POLAR_TOKEN_ENDPOINT: &str = "https://api.polar.sh/v1/oauth2/token";
pub const POLAR_USERINFO_ENDPOINT: &str = "https://api.polar.sh/v1/oauth2/userinfo";
pub const POLAR_DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];

type UserMapper = Arc<dyn Fn(&PolarProfile) -> OAuth2UserInfo + Send + Sync>;

/// Polar public profile settings payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolarProfileSettings {
    #[serde(default)]
    pub profile_settings_enabled: Option<bool>,
    #[serde(default)]
    pub profile_settings_public_name: Option<String>,
    #[serde(default)]
    pub profile_settings_public_avatar: Option<String>,
    #[serde(default)]
    pub profile_settings_public_bio: Option<String>,
    #[serde(default)]
    pub profile_settings_public_location: Option<String>,
    #[serde(default)]
    pub profile_settings_public_website: Option<String>,
    #[serde(default)]
    pub profile_settings_public_twitter: Option<String>,
    #[serde(default)]
    pub profile_settings_public_github: Option<String>,
    #[serde(default)]
    pub profile_settings_public_email: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Polar profile returned by `/v1/oauth2/userinfo`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolarProfile {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub avatar_url: String,
    #[serde(default)]
    pub github_username: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub public_name: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub profile_settings: Option<PolarProfileSettings>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Polar OAuth provider configuration.
#[derive(Clone, Default)]
pub struct PolarOptions {
    pub oauth: ProviderOptions,
    pub map_profile_to_user: Option<UserMapper>,
}

/// Input used to create a Polar authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolarAuthorizationUrlRequest {
    pub state: String,
    pub scopes: Vec<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
}

/// A normalized OpenAuth user and the raw Polar profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolarUserInfo {
    pub user: OAuth2UserInfo,
    pub data: PolarProfile,
}

/// Polar OAuth provider.
#[derive(Clone, Default)]
pub struct PolarProvider {
    options: PolarOptions,
}

pub fn polar(options: PolarOptions) -> PolarProvider {
    PolarProvider::new(options)
}

impl PolarProvider {
    pub fn new(options: PolarOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &PolarOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        request: PolarAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: POLAR_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: POLAR_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes: self.authorization_scopes(request.scopes),
            prompt: self.options.oauth.prompt.clone(),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: POLAR_TOKEN_ENDPOINT.to_owned(),
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

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: POLAR_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token_value.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<PolarUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(POLAR_USERINFO_ENDPOINT)
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

        let profile = match response.json::<PolarProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(self.map_user_info(profile)))
    }

    pub fn map_profile(profile: PolarProfile) -> PolarUserInfo {
        let name = profile
            .public_name
            .clone()
            .filter(|name| !name.is_empty())
            .or_else(|| Some(profile.username.clone()))
            .unwrap_or_default();
        let user = OAuth2UserInfo {
            id: profile.id.clone(),
            name: Some(name),
            email: (!profile.email.is_empty()).then(|| profile.email.clone()),
            image: (!profile.avatar_url.is_empty()).then(|| profile.avatar_url.clone()),
            email_verified: profile.email_verified.unwrap_or(false),
        };

        PolarUserInfo {
            user,
            data: profile,
        }
    }

    pub fn map_user_info(&self, profile: PolarProfile) -> PolarUserInfo {
        if let Some(mapper) = &self.options.map_profile_to_user {
            let user = mapper(&profile);
            return PolarUserInfo {
                user,
                data: profile,
            };
        }

        Self::map_profile(profile)
    }

    fn authorization_scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            POLAR_DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl OAuthProviderContract for PolarProvider {
    fn id(&self) -> &str {
        POLAR_ID
    }

    fn name(&self) -> &str {
        POLAR_NAME
    }
}
