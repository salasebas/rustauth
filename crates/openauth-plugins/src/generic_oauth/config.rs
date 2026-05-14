use openauth_oauth::oauth2::{ClientAuthentication, ClientId, ProviderOptions};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenericOAuthOptions {
    pub config: Vec<GenericOAuthConfig>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub authentication: ClientAuthentication,
    pub discovery_headers: BTreeMap<String, String>,
    pub authorization_headers: BTreeMap<String, String>,
    pub override_user_info: bool,
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
        let mut scopes = self.scopes.clone();
        scopes.extend(request_scopes);
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
            disable_implicit_sign_up: false,
            disable_sign_up: false,
            authentication: ClientAuthentication::Post,
            discovery_headers: BTreeMap::new(),
            authorization_headers: BTreeMap::new(),
            override_user_info: false,
        }
    }
}
