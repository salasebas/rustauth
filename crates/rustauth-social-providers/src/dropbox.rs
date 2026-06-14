//! Dropbox social OAuth provider.

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

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
#[derive(Debug, Clone)]
pub struct DropboxProvider {
    client: OAuth2Client,
    access_type: Option<DropboxAccessType>,
}

pub fn dropbox(opts: DropboxProviderOptions) -> Result<DropboxProvider, OAuthError> {
    #[allow(deprecated)]
    DropboxProvider::new(opts)
}

impl DropboxProvider {
    #[deprecated(note = "use advanced::dropbox::dropbox() instead")]
    pub fn new(options: DropboxProviderOptions) -> Result<Self, OAuthError> {
        let access_type = options.access_type;
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("dropbox", options.oauth)
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scope(DEFAULT_SCOPE);
        }
        Ok(Self {
            client: builder.build()?,
            access_type,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn create_authorization_url(
        &self,
        request: DropboxAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?;
        if let Some(code_verifier) = request.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        let url = url.scopes(request.scopes);
        let url = if let Some(access_type) = self.access_type {
            url.param("token_access_type", access_type.as_str())
        } else {
            url
        };
        url.build()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
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
        self.client.refresh_token(refresh_token)?.send().await
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

impl ProviderIdentity for DropboxProvider {
    fn id(&self) -> &str {
        "dropbox"
    }

    fn name(&self) -> &str {
        "Dropbox"
    }
}
