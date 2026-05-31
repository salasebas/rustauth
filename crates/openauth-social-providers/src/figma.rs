//! Figma social provider.

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token_request,
    validate_authorization_code, AuthorizationCodeRequest, AuthorizationUrlRequest,
    ClientAuthentication, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthFormRequest, OAuthProviderContract, ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

pub const FIGMA_ID: &str = "figma";
pub const FIGMA_NAME: &str = "Figma";
pub const FIGMA_AUTHORIZATION_ENDPOINT: &str = "https://www.figma.com/oauth";
pub const FIGMA_TOKEN_ENDPOINT: &str = "https://api.figma.com/v1/oauth/token";
pub const FIGMA_USERINFO_ENDPOINT: &str = "https://api.figma.com/v1/me";
pub const FIGMA_DEFAULT_SCOPE: &str = "current_user:read";

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
    options: ProviderOptions,
    http_client: reqwest::Client,
}

pub fn figma(options: ProviderOptions) -> FigmaProvider {
    FigmaProvider::new(options)
}

impl FigmaProvider {
    pub fn new(options: ProviderOptions) -> Self {
        Self {
            options,
            http_client: crate::http::shared_client(),
        }
    }

    pub fn id(&self) -> &str {
        FIGMA_ID
    }

    pub fn name(&self) -> &str {
        FIGMA_NAME
    }

    pub fn options(&self) -> &ProviderOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        FIGMA_TOKEN_ENDPOINT
    }

    pub fn userinfo_endpoint(&self) -> &str {
        FIGMA_USERINFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: FigmaAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.ensure_client_credentials()?;
        if request.code_verifier.is_none() {
            return Err(OAuthError::MissingOption("code_verifier"));
        }

        create_authorization_url(AuthorizationUrlRequest {
            id: FIGMA_ID.to_owned(),
            options: self.options.clone(),
            authorization_endpoint: FIGMA_AUTHORIZATION_ENDPOINT.to_owned(),
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
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.clone(),
            code_verifier: code_verifier.map(Into::into),
            authentication: ClientAuthentication::Basic,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: FIGMA_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.clone(),
                code_verifier: code_verifier.map(Into::into),
                authentication: ClientAuthentication::Basic,
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
            authentication: ClientAuthentication::Basic,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        openauth_oauth::oauth2::refresh_access_token(ClientTokenRequest {
            token_endpoint: FIGMA_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.clone(),
                authentication: ClientAuthentication::Basic,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
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
            .get(FIGMA_USERINFO_ENDPOINT)
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

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.disable_default_scope {
            Vec::new()
        } else {
            vec![FIGMA_DEFAULT_SCOPE.to_owned()]
        };
        scopes.extend(self.options.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }

    fn ensure_client_credentials(&self) -> Result<(), OAuthError> {
        if openauth_oauth::oauth2::get_primary_client_id(&self.options.client_id).is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if self
            .options
            .client_secret
            .as_deref()
            .unwrap_or("")
            .is_empty()
        {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }
}

impl OAuthProviderContract for FigmaProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}
