//! Spotify social OAuth provider.

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

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
#[derive(Debug, Clone)]
pub struct SpotifyProvider {
    client: OAuth2Client,
}

#[allow(deprecated)]
pub fn spotify(options: ProviderOptions) -> Result<SpotifyProvider, OAuthError> {
    SpotifyProvider::new(options)
}

impl SpotifyProvider {
    #[deprecated(note = "use advanced::spotify::spotify() instead")]
    pub fn new(options: ProviderOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.disable_default_scope;
        let mut builder = OAuth2Client::builder(SPOTIFY_ID, options)
            .authorization_endpoint(SPOTIFY_AUTHORIZATION_ENDPOINT)?
            .token_endpoint(SPOTIFY_TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scope(SPOTIFY_DEFAULT_SCOPE);
        }
        Ok(Self {
            client: builder.build()?,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
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
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?
            .scopes(request.scopes);
        if let Some(code_verifier) = request.code_verifier {
            url = url.code_verifier(code_verifier);
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
        code_verifier: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.send().await
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
}

impl ProviderIdentity for SpotifyProvider {
    fn id(&self) -> &str {
        SPOTIFY_ID
    }

    fn name(&self) -> &str {
        SPOTIFY_NAME
    }
}
