use std::future::Future;
use std::pin::Pin;

use serde_json::Value;
use url::Url;

use super::authorization_url::AuthorizationUrlRequest;
use super::error::OAuthError;
use super::tokens::{OAuth2Tokens, OAuth2UserInfo, ProviderOptions};

/// Minimal OAuth provider metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProviderMetadata {
    id: String,
    name: String,
}

impl OAuthProviderMetadata {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Minimal public contract shared by OAuth provider implementations.
pub trait OAuthProviderContract {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
}

impl OAuthProviderContract for OAuthProviderMetadata {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

pub type SocialProviderFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, OAuthError>> + Send + 'a>>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocialAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

impl SocialAuthorizationUrlRequest {
    pub fn into_authorization_url_request(
        self,
        id: impl Into<String>,
        options: ProviderOptions,
        authorization_endpoint: impl Into<String>,
        scopes: Vec<String>,
    ) -> AuthorizationUrlRequest {
        AuthorizationUrlRequest {
            id: id.into(),
            options,
            authorization_endpoint: authorization_endpoint.into(),
            redirect_uri: self.redirect_uri,
            state: self.state,
            code_verifier: self.code_verifier,
            scopes,
            login_hint: self.login_hint,
            ..AuthorizationUrlRequest::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocialAuthorizationCodeRequest {
    pub code: String,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SocialIdTokenRequest {
    pub token: String,
    pub nonce: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub scopes: Vec<String>,
    pub provider_user: Option<Value>,
}

pub trait SocialOAuthProvider: Send + Sync + 'static {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn provider_options(&self) -> ProviderOptions;

    fn create_authorization_url(
        &self,
        input: SocialAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError>;

    fn validate_authorization_code(
        &self,
        input: SocialAuthorizationCodeRequest,
    ) -> SocialProviderFuture<'_, OAuth2Tokens>;

    fn get_user_info(
        &self,
        tokens: OAuth2Tokens,
        provider_user: Option<Value>,
    ) -> SocialProviderFuture<'_, Option<OAuth2UserInfo>>;

    fn verify_id_token(&self, _input: SocialIdTokenRequest) -> SocialProviderFuture<'_, bool> {
        Box::pin(async { Ok(false) })
    }

    fn refresh_access_token(
        &self,
        refresh_token: String,
    ) -> SocialProviderFuture<'_, OAuth2Tokens> {
        Box::pin(async move {
            Err(OAuthError::InvalidResponse(format!(
                "provider does not support refresh tokens for token `{refresh_token}`"
            )))
        })
    }

    fn revoke_token(&self, token: String) -> SocialProviderFuture<'_, ()> {
        Box::pin(async move {
            Err(OAuthError::InvalidResponse(format!(
                "provider does not support token revocation for token `{token}`"
            )))
        })
    }
}
