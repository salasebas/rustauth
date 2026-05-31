//! Kick social OAuth provider.

use openauth_oauth::oauth2::{
    create_authorization_code_request, create_authorization_url,
    create_refresh_access_token_request, refresh_access_token, validate_authorization_code,
    AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract,
    ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

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
    options: ProviderOptions,
}

impl KickProvider {
    pub fn new(options: ProviderOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &ProviderOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        KICK_TOKEN_ENDPOINT
    }

    pub fn user_info_endpoint(&self) -> &str {
        KICK_USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        input: KickAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut scopes = Vec::new();
        if !self.options.disable_default_scope {
            scopes.extend(DEFAULT_SCOPES.iter().map(|scope| (*scope).to_owned()));
        }
        scopes.extend(self.options.scope.iter().cloned());
        scopes.extend(input.scopes);

        create_authorization_url(AuthorizationUrlRequest {
            id: self.id().to_owned(),
            options: self.options.clone(),
            authorization_endpoint: KICK_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: input.redirect_uri,
            state: input.state,
            code_verifier: input.code_verifier,
            scopes,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn create_authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        create_authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.clone(),
            code_verifier,
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        create_refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token_value.into(),
            options: self.options.clone(),
            authentication: ClientAuthentication::Post,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: KICK_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.clone(),
                code_verifier,
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
            token_endpoint: KICK_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token_value.into(),
                options: self.options.clone(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
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
}

impl OAuthProviderContract for KickProvider {
    fn id(&self) -> &str {
        KICK_ID
    }

    fn name(&self) -> &str {
        KICK_NAME
    }
}

pub fn kick(options: ProviderOptions) -> KickProvider {
    KickProvider::new(options)
}

#[derive(Debug, Deserialize)]
struct KickUserInfoResponse {
    data: Vec<KickProfile>,
}
