//! Spotify social OAuth provider.

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthFormRequest, OAuthProviderContract, OAuthProviderMetadata, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

pub const SPOTIFY_ID: &str = "spotify";
pub const SPOTIFY_NAME: &str = "Spotify";
pub const SPOTIFY_AUTHORIZATION_ENDPOINT: &str = "https://accounts.spotify.com/authorize";
pub const SPOTIFY_TOKEN_ENDPOINT: &str = "https://accounts.spotify.com/api/token";
pub const SPOTIFY_USER_INFO_ENDPOINT: &str = "https://api.spotify.com/v1/me";
pub const SPOTIFY_DEFAULT_SCOPE: &str = "user-read-email";

/// Input used to create a Spotify authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpotifyAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_verifier: Option<String>,
}

/// Spotify profile image payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpotifyImage {
    pub url: String,
}

/// Spotify user profile payload returned by `GET /v1/me`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpotifyProfile {
    pub id: String,
    pub display_name: String,
    pub email: String,
    #[serde(default)]
    pub images: Vec<SpotifyImage>,
}

/// User info plus raw Spotify profile data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpotifyUserInfo {
    pub user: OAuth2UserInfo,
    pub data: SpotifyProfile,
}

/// Spotify OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpotifyProvider {
    options: ProviderOptions,
    metadata: OAuthProviderMetadata,
}

pub fn spotify(options: ProviderOptions) -> SpotifyProvider {
    SpotifyProvider::new(options)
}

impl SpotifyProvider {
    pub fn new(options: ProviderOptions) -> Self {
        Self {
            options,
            metadata: OAuthProviderMetadata::new(SPOTIFY_ID, SPOTIFY_NAME),
        }
    }

    pub fn options(&self) -> &ProviderOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        SPOTIFY_TOKEN_ENDPOINT
    }

    pub fn user_info_endpoint(&self) -> &str {
        SPOTIFY_USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: SpotifyAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: self.id().to_owned(),
            options: self.options.clone(),
            authorization_endpoint: SPOTIFY_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes: self.scopes(request.scopes),
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
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: SPOTIFY_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                code_verifier,
                redirect_uri: redirect_uri.into(),
                options: self.options.clone(),
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
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: SPOTIFY_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.clone(),
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<SpotifyUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(SPOTIFY_USER_INFO_ENDPOINT)
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

        let profile = match response.json::<SpotifyProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(Self::user_info_from_profile(profile)))
    }

    pub fn user_info_from_profile(profile: SpotifyProfile) -> SpotifyUserInfo {
        SpotifyUserInfo {
            user: OAuth2UserInfo {
                id: profile.id.clone(),
                name: Some(profile.display_name.clone()),
                email: Some(profile.email.clone()),
                image: profile.images.first().map(|image| image.url.clone()),
                email_verified: false,
            },
            data: profile,
        }
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = Vec::new();
        if !self.options.disable_default_scope {
            scopes.push(SPOTIFY_DEFAULT_SCOPE.to_owned());
        }
        scopes.extend(self.options.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl Default for SpotifyProvider {
    fn default() -> Self {
        Self::new(ProviderOptions::default())
    }
}

impl OAuthProviderContract for SpotifyProvider {
    fn id(&self) -> &str {
        self.metadata.id()
    }

    fn name(&self) -> &str {
        self.metadata.name()
    }
}
