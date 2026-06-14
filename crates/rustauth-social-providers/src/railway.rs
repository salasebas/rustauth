//! Railway social provider.

use rustauth_oauth::oauth2::{
    ClientAuthentication, OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

pub const RAILWAY_ID: &str = "railway";
pub const RAILWAY_NAME: &str = "Railway";
pub const RAILWAY_AUTHORIZATION_ENDPOINT: &str = "https://backboard.railway.com/oauth/auth";
pub const RAILWAY_TOKEN_ENDPOINT: &str = "https://backboard.railway.com/oauth/token";
pub const RAILWAY_USERINFO_ENDPOINT: &str = "https://backboard.railway.com/oauth/me";
pub const RAILWAY_DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailwayProfile {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub picture: String,
}

impl RailwayProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.sub.clone(),
            name: Some(self.name.clone()),
            email: Some(self.email.clone()),
            image: Some(self.picture.clone()),
            email_verified: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailwayAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RailwayUserInfo {
    pub user: OAuth2UserInfo,
    pub data: RailwayProfile,
}

/// Railway OAuth provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RailwayProviderOptions {
    pub oauth: ProviderOptions,
}

#[derive(Debug, Clone)]
pub struct RailwayProvider {
    client: OAuth2Client,
    http_client: reqwest::Client,
}

#[allow(deprecated)]
pub fn railway(options: ProviderOptions) -> Result<RailwayProvider, OAuthError> {
    RailwayProvider::new(RailwayProviderOptions { oauth: options })
}

impl RailwayProvider {
    #[deprecated(note = "use advanced::railway::railway() instead")]
    pub fn new(options: RailwayProviderOptions) -> Result<Self, OAuthError> {
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder(RAILWAY_ID, options.oauth)
            .authorization_endpoint(RAILWAY_AUTHORIZATION_ENDPOINT)?
            .token_endpoint(RAILWAY_TOKEN_ENDPOINT)?
            .authentication(ClientAuthentication::Basic);
        if !disable_default_scope {
            builder = builder.default_scopes(RAILWAY_DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
            http_client: crate::http::shared_client(),
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn token_endpoint(&self) -> &str {
        RAILWAY_TOKEN_ENDPOINT
    }

    pub fn userinfo_endpoint(&self) -> &str {
        RAILWAY_USERINFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: RailwayAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.ensure_client_credentials()?;
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
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token)?.send().await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<RailwayUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match self
            .http_client
            .get(RAILWAY_USERINFO_ENDPOINT)
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
        let profile = match response.json::<RailwayProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };

        Ok(Some(RailwayUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }))
    }

    fn ensure_client_credentials(&self) -> Result<(), OAuthError> {
        if self.client.options().client_secret.is_none() {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }
}

impl ProviderIdentity for RailwayProvider {
    fn id(&self) -> &str {
        RAILWAY_ID
    }

    fn name(&self) -> &str {
        RAILWAY_NAME
    }
}
