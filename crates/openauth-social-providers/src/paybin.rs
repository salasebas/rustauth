//! Paybin OpenID Connect social provider.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, get_primary_client_id,
    refresh_access_token, refresh_access_token_request, validate_authorization_code,
    AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract,
    ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const PAYBIN_ID: &str = "paybin";
pub const PAYBIN_NAME: &str = "Paybin";
pub const PAYBIN_DEFAULT_ISSUER: &str = "https://idp.paybin.io";
pub const PAYBIN_AUTHORIZATION_ENDPOINT: &str = "https://idp.paybin.io/oauth2/authorize";
pub const PAYBIN_TOKEN_ENDPOINT: &str = "https://idp.paybin.io/oauth2/token";
pub const PAYBIN_DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

/// Paybin ID token profile claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaybinProfile {
    pub sub: String,
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl PaybinProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.sub.clone(),
            name: Some(
                self.name
                    .clone()
                    .or_else(|| self.preferred_username.clone())
                    .unwrap_or_default(),
            ),
            email: Some(self.email.clone()),
            image: self.picture.clone(),
            email_verified: self.email_verified,
        }
    }
}

/// Paybin provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaybinOptions {
    pub oauth: ProviderOptions,
    pub issuer: Option<String>,
}

/// Input used to create a Paybin authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaybinAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

/// A normalized OpenAuth user and the raw Paybin claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaybinUserInfo {
    pub user: OAuth2UserInfo,
    pub data: PaybinProfile,
}

/// Paybin OAuth/OIDC provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaybinProvider {
    options: PaybinOptions,
    authorization_endpoint: String,
    token_endpoint: String,
}

pub fn paybin(options: PaybinOptions) -> PaybinProvider {
    PaybinProvider::new(options)
}

impl PaybinProvider {
    pub fn new(options: PaybinOptions) -> Self {
        let issuer = options
            .issuer
            .as_deref()
            .unwrap_or(PAYBIN_DEFAULT_ISSUER)
            .to_owned();
        Self {
            options,
            authorization_endpoint: format!("{issuer}/oauth2/authorize"),
            token_endpoint: format!("{issuer}/oauth2/token"),
        }
    }

    pub fn id(&self) -> &str {
        PAYBIN_ID
    }

    pub fn name(&self) -> &str {
        PAYBIN_NAME
    }

    pub fn options(&self) -> &PaybinOptions {
        &self.options
    }

    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    pub fn create_authorization_url(
        &self,
        request: PaybinAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.ensure_client_credentials()?;
        if request.code_verifier.is_none() {
            return Err(OAuthError::MissingOption("code_verifier"));
        }

        create_authorization_url(AuthorizationUrlRequest {
            id: PAYBIN_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes: self.scopes(request.scopes),
            prompt: self.options.oauth.prompt.clone(),
            login_hint: request.login_hint,
            response_mode: self.options.oauth.response_mode.clone(),
            ..AuthorizationUrlRequest::default()
        })
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

        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.oauth.clone(),
            code_verifier: Some(code_verifier),
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
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

        validate_authorization_code(ClientTokenRequest {
            token_endpoint: self.token_endpoint.clone(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                code_verifier: Some(code_verifier),
                authentication: ClientAuthentication::Post,
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
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Post,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: self.token_endpoint.clone(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token_value.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<PaybinUserInfo>, OAuthError> {
        let Some(id_token) = token.id_token.as_deref() else {
            return Ok(None);
        };
        let profile = decode_jwt_payload::<PaybinProfile>(id_token)?;
        Ok(Some(PaybinUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }))
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            PAYBIN_DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }

    fn ensure_client_credentials(&self) -> Result<(), OAuthError> {
        if get_primary_client_id(&self.options.oauth.client_id).is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if self
            .options
            .oauth
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

impl OAuthProviderContract for PaybinProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

fn decode_jwt_payload<T>(token: &str) -> Result<T, OAuthError>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| OAuthError::TokenVerification("missing jwt payload".to_owned()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| OAuthError::TokenVerification(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| OAuthError::InvalidResponse(error.to_string()))
}
