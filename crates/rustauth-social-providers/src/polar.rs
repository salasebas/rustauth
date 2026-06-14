//! Polar social OAuth provider.

use std::sync::Arc;

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

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
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
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
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
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

/// A normalized RustAuth user and the raw Polar profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolarUserInfo {
    pub user: OAuth2UserInfo,
    pub data: PolarProfile,
}

/// Polar OAuth provider.
#[derive(Clone)]
pub struct PolarProvider {
    client: OAuth2Client,
    map_profile_to_user: Option<UserMapper>,
}

#[allow(deprecated)]
pub fn polar(options: PolarOptions) -> Result<PolarProvider, OAuthError> {
    PolarProvider::new(options)
}

impl PolarProvider {
    #[deprecated(note = "use advanced::polar::polar() instead")]
    pub fn new(options: PolarOptions) -> Result<Self, OAuthError> {
        let PolarOptions {
            oauth,
            map_profile_to_user,
        } = options;
        let disable_default_scope = oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder(POLAR_ID, oauth)
            .authorization_endpoint(POLAR_AUTHORIZATION_ENDPOINT)?
            .token_endpoint(POLAR_TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scopes(POLAR_DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
            map_profile_to_user,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn create_authorization_url(
        &self,
        request: PolarAuthorizationUrlRequest,
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
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token_value)?.send().await
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
        if let Some(mapper) = &self.map_profile_to_user {
            let user = mapper(&profile);
            return PolarUserInfo {
                user,
                data: profile,
            };
        }

        Self::map_profile(profile)
    }
}

impl ProviderIdentity for PolarProvider {
    fn id(&self) -> &str {
        POLAR_ID
    }

    fn name(&self) -> &str {
        POLAR_NAME
    }
}
