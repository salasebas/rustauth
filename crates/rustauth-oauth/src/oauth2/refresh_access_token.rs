use std::collections::BTreeMap;

use super::error::OAuthError;
use super::request::{
    apply_client_authentication, is_protected_oauth_param, ClientAuthentication, OAuthFormRequest,
};
use super::tokens::ProviderOptions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshAccessTokenRequest {
    pub refresh_token: String,
    pub options: ProviderOptions,
    pub authentication: ClientAuthentication,
    pub headers: BTreeMap<String, String>,
    pub extra_params: BTreeMap<String, String>,
    pub resource: Vec<String>,
}

impl Default for RefreshAccessTokenRequest {
    fn default() -> Self {
        Self {
            refresh_token: String::new(),
            options: ProviderOptions::default(),
            authentication: ClientAuthentication::Post,
            headers: BTreeMap::new(),
            extra_params: BTreeMap::new(),
            resource: Vec::new(),
        }
    }
}

impl RefreshAccessTokenRequest {
    pub fn try_new(
        refresh_token: impl Into<String>,
        options: ProviderOptions,
    ) -> Result<Self, OAuthError> {
        let refresh_token = refresh_token.into();
        if refresh_token.is_empty() {
            return Err(OAuthError::MissingTokenField("refresh_token"));
        }
        Ok(Self {
            refresh_token,
            options,
            ..Self::default()
        })
    }

    pub fn authentication(mut self, authentication: ClientAuthentication) -> Self {
        self.authentication = authentication;
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Adds a non-sensitive extension form field such as `scope`.
    ///
    /// This is an extension-only API: security-critical keys (`grant_type`,
    /// `refresh_token`, and client credential/authentication fields) and any
    /// field already set by the builder are ignored when the request is built,
    /// so a provider extension or caller-controlled value cannot replace
    /// validated flow invariants or authenticated client credentials.
    pub fn extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_params.insert(key.into(), value.into());
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource.push(resource.into());
        self
    }
}

pub fn create_refresh_access_token_request(
    input: RefreshAccessTokenRequest,
) -> Result<OAuthFormRequest, OAuthError> {
    validate_refresh_access_token_request(&input)?;
    let mut request = OAuthFormRequest::new();
    for (key, value) in input.headers {
        request.set_header(key, value);
    }
    request.set_body("grant_type", "refresh_token");
    request.set_body("refresh_token", input.refresh_token);
    if let Some(client_key) = &input.options.client_key {
        request.set_body("client_key", client_key);
    }
    apply_client_authentication(&mut request, &input.options, input.authentication, false)?;
    for resource in input.resource {
        request.push_body("resource", resource);
    }
    for (key, value) in input.extra_params {
        if is_protected_oauth_param(&key) || request.has_body(&key) {
            continue;
        }
        request.push_body(key, value);
    }
    Ok(request)
}

fn validate_refresh_access_token_request(
    input: &RefreshAccessTokenRequest,
) -> Result<(), OAuthError> {
    if input.refresh_token.is_empty() {
        return Err(OAuthError::MissingTokenField("refresh_token"));
    }
    Ok(())
}
