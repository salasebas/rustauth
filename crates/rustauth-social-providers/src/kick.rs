//! Kick social OAuth provider.

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

pub const KICK_ID: &str = "kick";
pub const KICK_NAME: &str = "Kick";
pub const KICK_AUTHORIZATION_ENDPOINT: &str = "https://id.kick.com/oauth/authorize";
pub const KICK_TOKEN_ENDPOINT: &str = "https://id.kick.com/oauth/token";
pub const KICK_USER_INFO_ENDPOINT: &str = "https://api.kick.com/public/v1/users";
const DEFAULT_SCOPES: &[&str] = &["user:read"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KickProfile {
    pub user_id: String,
    pub name: String,
    pub email: String,
    pub profile_picture: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KickUserInfo {
    pub user: OAuth2UserInfo,
    pub data: KickProfile,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KickAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KickProvider {
    client: OAuth2Client,
}

impl KickProvider {
    #[deprecated(note = "use advanced::kick::kick() instead")]
    pub fn new(options: ProviderOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.disable_default_scope;
        let mut builder = OAuth2Client::builder("kick", options)
            .authorization_endpoint(KICK_AUTHORIZATION_ENDPOINT)?
            .token_endpoint(KICK_TOKEN_ENDPOINT)?;
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
        self.client.token_endpoint().as_str()
    }

    pub fn user_info_endpoint(&self) -> &str {
        KICK_USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        input: KickAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(input.state, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        url.scopes(input.scopes).build()
    }

    pub fn create_authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.into_form_request()
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .refresh_token(refresh_token_value)?
            .into_form_request()
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
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token_value)?.send().await
    }

    pub async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<KickUserInfo>, OAuthError> {
        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };
        let response = crate::http::shared_client()
            .get(KICK_USER_INFO_ENDPOINT)
            .bearer_auth(access_token)
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }

        let response = match response.json::<KickUserInfoResponse>().await {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        Ok(Self::map_profiles_to_user_info(response.data))
    }

    pub fn map_profile_to_user_info(profile: &KickProfile) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: profile.user_id.clone(),
            name: Some(profile.name.clone()),
            email: Some(profile.email.clone()),
            image: Some(profile.profile_picture.clone()),
            email_verified: false,
        }
    }

    pub fn map_profiles_to_user_info(profiles: Vec<KickProfile>) -> Option<KickUserInfo> {
        profiles.into_iter().next().map(|profile| KickUserInfo {
            user: Self::map_profile_to_user_info(&profile),
            data: profile,
        })
    }

    pub fn id(&self) -> &str {
        KICK_ID
    }

    pub fn name(&self) -> &str {
        KICK_NAME
    }
}

impl ProviderIdentity for KickProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

#[allow(deprecated)]
pub fn kick(options: ProviderOptions) -> Result<KickProvider, OAuthError> {
    KickProvider::new(options)
}

#[derive(Debug, Deserialize)]
struct KickUserInfoResponse {
    data: Vec<KickProfile>,
}
