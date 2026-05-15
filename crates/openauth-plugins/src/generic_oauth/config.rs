use openauth_oauth::oauth2::{
    ClientAuthentication, ClientId, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type GenericOAuthTokenFuture =
    Pin<Box<dyn Future<Output = Result<OAuth2Tokens, OAuthError>> + Send>>;
pub type GenericOAuthGetToken =
    Arc<dyn Fn(GenericOAuthTokenRequest) -> GenericOAuthTokenFuture + Send + Sync>;
pub type GenericOAuthUserInfoFuture =
    Pin<Box<dyn Future<Output = Result<Option<OAuth2UserInfo>, OAuthError>> + Send>>;
pub type GenericOAuthGetUserInfo =
    Arc<dyn Fn(OAuth2Tokens) -> GenericOAuthUserInfoFuture + Send + Sync>;
pub type GenericOAuthMapProfileFuture =
    Pin<Box<dyn Future<Output = Result<OAuth2UserInfo, OAuthError>> + Send>>;
pub type GenericOAuthMapProfileToUser =
    Arc<dyn Fn(OAuth2UserInfo) -> GenericOAuthMapProfileFuture + Send + Sync>;
pub type GenericOAuthParams = BTreeMap<String, String>;
pub type GenericOAuthParamsFuture =
    Pin<Box<dyn Future<Output = Result<GenericOAuthParams, OAuthError>> + Send>>;
pub type GenericOAuthParamsCallback =
    Arc<dyn Fn(GenericOAuthParamsContext) -> GenericOAuthParamsFuture + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericOAuthFlow {
    SignIn,
    Link,
    Callback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericOAuthParamsContext {
    pub provider_id: String,
    pub flow: GenericOAuthFlow,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenericOAuthTokenRequest {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Clone, Default)]
pub struct GenericOAuthOptions {
    pub config: Vec<GenericOAuthConfig>,
}

impl std::fmt::Debug for GenericOAuthOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenericOAuthOptions")
            .field("config", &self.config)
            .finish()
    }
}

impl GenericOAuthOptions {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "config": self.config.iter().map(GenericOAuthConfig::public_json).collect::<Vec<_>>(),
        })
    }

    pub(crate) fn find(&self, provider_id: &str) -> Option<&GenericOAuthConfig> {
        self.config
            .iter()
            .find(|config| config.provider_id == provider_id)
    }
}

#[derive(Clone)]
pub struct GenericOAuthConfig {
    pub provider_id: String,
    pub discovery_url: Option<String>,
    pub issuer: Option<String>,
    pub require_issuer_validation: bool,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub user_info_url: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub prompt: Option<String>,
    pub pkce: bool,
    pub access_type: Option<String>,
    pub authorization_url_params: BTreeMap<String, String>,
    pub token_url_params: BTreeMap<String, String>,
    pub authorization_url_params_callback: Option<GenericOAuthParamsCallback>,
    pub token_url_params_callback: Option<GenericOAuthParamsCallback>,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub authentication: ClientAuthentication,
    pub discovery_headers: BTreeMap<String, String>,
    pub authorization_headers: BTreeMap<String, String>,
    pub override_user_info: bool,
    pub get_token: Option<GenericOAuthGetToken>,
    pub get_user_info: Option<GenericOAuthGetUserInfo>,
    pub map_profile_to_user: Option<GenericOAuthMapProfileToUser>,
}

impl std::fmt::Debug for GenericOAuthConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenericOAuthConfig")
            .field("provider_id", &self.provider_id)
            .field("discovery_url", &self.discovery_url)
            .field("issuer", &self.issuer)
            .field("require_issuer_validation", &self.require_issuer_validation)
            .field("authorization_url", &self.authorization_url)
            .field("token_url", &self.token_url)
            .field("user_info_url", &self.user_info_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("scopes", &self.scopes)
            .field("redirect_uri", &self.redirect_uri)
            .field("response_type", &self.response_type)
            .field("response_mode", &self.response_mode)
            .field("prompt", &self.prompt)
            .field("pkce", &self.pkce)
            .field("access_type", &self.access_type)
            .field("authorization_url_params", &self.authorization_url_params)
            .field("token_url_params", &self.token_url_params)
            .field(
                "authorization_url_params_callback",
                &self.authorization_url_params_callback.is_some(),
            )
            .field(
                "token_url_params_callback",
                &self.token_url_params_callback.is_some(),
            )
            .field("disable_implicit_sign_up", &self.disable_implicit_sign_up)
            .field("disable_sign_up", &self.disable_sign_up)
            .field("authentication", &self.authentication)
            .field("discovery_headers", &self.discovery_headers)
            .field("authorization_headers", &self.authorization_headers)
            .field("override_user_info", &self.override_user_info)
            .field("get_token", &self.get_token.is_some())
            .field("get_user_info", &self.get_user_info.is_some())
            .field("map_profile_to_user", &self.map_profile_to_user.is_some())
            .finish()
    }
}

impl GenericOAuthConfig {
    pub fn new(
        provider_id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<impl Into<String>>,
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            client_id: client_id.into(),
            client_secret: client_secret.map(Into::into),
            authorization_url: Some(authorization_url.into()),
            token_url: Some(token_url.into()),
            ..Self::default()
        }
    }

    pub fn discovery(
        provider_id: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<impl Into<String>>,
        discovery_url: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            client_id: client_id.into(),
            client_secret: client_secret.map(Into::into),
            discovery_url: Some(discovery_url.into()),
            ..Self::default()
        }
    }

    pub(crate) fn provider_options(&self) -> ProviderOptions {
        ProviderOptions {
            client_id: Some(ClientId::Single(self.client_id.clone())),
            client_secret: self.client_secret.clone(),
            scope: self.scopes.clone(),
            redirect_uri: self.redirect_uri.clone(),
            authorization_endpoint: self.authorization_url.clone(),
            disable_implicit_sign_up: self.disable_implicit_sign_up,
            disable_sign_up: self.disable_sign_up,
            prompt: self.prompt.clone(),
            response_mode: self.response_mode.clone(),
            override_user_info_on_sign_in: self.override_user_info,
            ..ProviderOptions::default()
        }
    }

    pub(crate) fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        if request_scopes.is_empty() {
            return self.scopes.clone();
        }
        let mut scopes = request_scopes;
        scopes.extend(self.scopes.clone());
        scopes
    }

    fn public_json(&self) -> Value {
        json!({
            "providerId": self.provider_id,
            "discoveryUrl": self.discovery_url,
            "issuer": self.issuer,
            "requireIssuerValidation": self.require_issuer_validation,
            "authorizationUrl": self.authorization_url,
            "tokenUrl": self.token_url,
            "userInfoUrl": self.user_info_url,
            "clientId": self.client_id,
            "scopes": self.scopes,
            "redirectURI": self.redirect_uri,
            "pkce": self.pkce,
            "disableImplicitSignUp": self.disable_implicit_sign_up,
            "disableSignUp": self.disable_sign_up,
            "overrideUserInfo": self.override_user_info,
        })
    }
}

impl Default for GenericOAuthConfig {
    fn default() -> Self {
        Self {
            provider_id: String::new(),
            discovery_url: None,
            issuer: None,
            require_issuer_validation: false,
            authorization_url: None,
            token_url: None,
            user_info_url: None,
            client_id: String::new(),
            client_secret: None,
            scopes: Vec::new(),
            redirect_uri: None,
            response_type: None,
            response_mode: None,
            prompt: None,
            pkce: false,
            access_type: None,
            authorization_url_params: BTreeMap::new(),
            token_url_params: BTreeMap::new(),
            authorization_url_params_callback: None,
            token_url_params_callback: None,
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            authentication: ClientAuthentication::Post,
            discovery_headers: BTreeMap::new(),
            authorization_headers: BTreeMap::new(),
            override_user_info: false,
            get_token: None,
            get_user_info: None,
            map_profile_to_user: None,
        }
    }
}
