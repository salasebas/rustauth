//! Figma social provider.

use rustauth_oauth::oauth2::{
    get_primary_client_id, ClientAuthentication, OAuth2Client, OAuth2Tokens, OAuth2UserInfo,
    OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://www.figma.com/oauth";
const TOKEN_ENDPOINT: &str = "https://api.figma.com/v1/oauth/token";
const USERINFO_ENDPOINT: &str = "https://api.figma.com/v1/me";
const DEFAULT_SCOPE: &str = "current_user:read";

pub const FIGMA_ID: &str = "figma";
pub const FIGMA_NAME: &str = "Figma";
pub const FIGMA_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const FIGMA_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const FIGMA_USERINFO_ENDPOINT: &str = USERINFO_ENDPOINT;
pub const FIGMA_DEFAULT_SCOPE: &str = DEFAULT_SCOPE;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FigmaProfile {
    pub id: String,
    pub email: String,
    pub handle: String,
    pub img_url: String,
}

impl FigmaProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.id.clone(),
            name: Some(self.handle.clone()),
            email: Some(self.email.clone()),
            image: Some(self.img_url.clone()),
            email_verified: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FigmaAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FigmaUserInfo {
    pub user: OAuth2UserInfo,
    pub data: FigmaProfile,
}

#[derive(Debug, Clone)]
pub struct FigmaProvider {
    client: OAuth2Client,
    http_client: reqwest::Client,
}

#[allow(deprecated)]
pub fn figma(options: ProviderOptions) -> Result<FigmaProvider, OAuthError> {
    FigmaProvider::new(options)
}

impl FigmaProvider {
    #[deprecated(note = "use advanced::figma::figma() instead")]
    pub fn new(options: ProviderOptions) -> Result<Self, OAuthError> {
        Self::ensure_client_credentials(&options)?;
        let disable_default_scope = options.disable_default_scope;
        let mut builder = OAuth2Client::builder("figma", options)
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?
            .authentication(ClientAuthentication::Basic);
        if !disable_default_scope {
            builder = builder.default_scope(DEFAULT_SCOPE);
        }
        Ok(Self {
            client: builder.build()?,
            http_client: crate::http::shared_client(),
        })
    }

    pub fn id(&self) -> &str {
        FIGMA_ID
    }

    pub fn name(&self) -> &str {
        FIGMA_NAME
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn userinfo_endpoint(&self) -> &str {
        USERINFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: FigmaAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        Self::ensure_client_credentials(self.client.options())?;
        let code_verifier = request
            .code_verifier
            .ok_or(OAuthError::MissingOption("code_verifier"))?;
        self.client
            .authorization_url(request.state, request.redirect_uri)?
            .code_verifier(code_verifier)
            .scopes(request.scopes)
            .build()
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        let code_verifier = code_verifier
            .map(Into::into)
            .ok_or(OAuthError::MissingOption("code_verifier"))?;
        self.client
            .exchange_code(code, redirect_uri)?
            .code_verifier(code_verifier)
            .into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let code_verifier = code_verifier
            .map(Into::into)
            .ok_or(OAuthError::MissingOption("code_verifier"))?;
        self.client
            .exchange_code(code, redirect_uri)?
            .code_verifier(code_verifier)
            .send()
            .await
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
    ) -> Result<Option<FigmaUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match self
            .http_client
            .get(USERINFO_ENDPOINT)
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
        let profile = match response.json::<FigmaProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };

        Ok(Some(FigmaUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }))
    }

    fn ensure_client_credentials(options: &ProviderOptions) -> Result<(), OAuthError> {
        if get_primary_client_id(&options.client_id).is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if options
            .client_secret_str()
            .filter(|secret| !secret.is_empty())
            .is_none()
        {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }
}

impl ProviderIdentity for FigmaProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}
