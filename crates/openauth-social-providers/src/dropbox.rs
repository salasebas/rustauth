//! Dropbox social OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    create_authorization_url, refresh_access_token, validate_authorization_code,
    AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

const AUTHORIZATION_ENDPOINT: &str = "https://www.dropbox.com/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://api.dropboxapi.com/oauth2/token";
const USER_INFO_ENDPOINT: &str = "https://api.dropboxapi.com/2/users/get_current_account";
const DEFAULT_SCOPE: &str = "account_info.read";

/// Dropbox token access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropboxAccessType {
    Offline,
    Online,
    Legacy,
}

impl DropboxAccessType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Online => "online",
            Self::Legacy => "legacy",
        }
    }
}

/// Dropbox provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropboxProviderOptions {
    pub oauth: ProviderOptions,
    pub access_type: Option<DropboxAccessType>,
}

/// Input for creating a Dropbox authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropboxAuthorizationUrlRequest {
    pub state: String,
    pub scopes: Vec<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
}

/// Dropbox profile name payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DropboxName {
    #[serde(default)]
    pub given_name: String,
    #[serde(default)]
    pub surname: String,
    #[serde(default)]
    pub familiar_name: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub abbreviated_name: String,
}

/// Dropbox current account profile payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DropboxProfile {
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub name: DropboxName,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub profile_photo_url: Option<String>,
}

/// User info plus raw Dropbox profile data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DropboxUserInfo {
    pub user: OAuth2UserInfo,
    pub data: DropboxProfile,
}

/// Dropbox OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropboxProvider {
    options: DropboxProviderOptions,
}

impl DropboxProvider {
    pub fn new(options: DropboxProviderOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &DropboxProviderOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        request: DropboxAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut scopes = Vec::new();
        if !self.options.oauth.disable_default_scope {
            scopes.push(DEFAULT_SCOPE.to_owned());
        }
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request.scopes);

        let mut additional_params = BTreeMap::new();
        if let Some(access_type) = self.options.access_type {
            additional_params.insert(
                "token_access_type".to_owned(),
                access_type.as_str().to_owned(),
            );
        }

        create_authorization_url(AuthorizationUrlRequest {
            id: self.id().to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes,
            additional_params,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                code_verifier,
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(&self, token: &OAuth2Tokens) -> Option<DropboxUserInfo> {
        let access_token = token.access_token.as_deref()?;
        let profile = crate::http::shared_client()
            .post(USER_INFO_ENDPOINT)
            .bearer_auth(access_token)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json::<DropboxProfile>()
            .await
            .ok()?;

        Some(Self::user_info_from_profile(profile))
    }

    pub fn user_info_from_profile(profile: DropboxProfile) -> DropboxUserInfo {
        let user = Self::map_profile_to_user_info(&profile);
        DropboxUserInfo {
            user,
            data: profile,
        }
    }

    pub fn map_profile_to_user_info(profile: &DropboxProfile) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: profile.account_id.clone(),
            name: (!profile.name.display_name.is_empty())
                .then(|| profile.name.display_name.clone()),
            email: (!profile.email.is_empty()).then(|| profile.email.clone()),
            email_verified: profile.email_verified,
            image: profile.profile_photo_url.clone(),
        }
    }
}

impl Default for DropboxProvider {
    fn default() -> Self {
        Self::new(DropboxProviderOptions::default())
    }
}

impl OAuthProviderContract for DropboxProvider {
    fn id(&self) -> &str {
        "dropbox"
    }

    fn name(&self) -> &str {
        "Dropbox"
    }
}
