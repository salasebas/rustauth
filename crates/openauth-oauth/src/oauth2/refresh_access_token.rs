use std::collections::BTreeMap;

use super::error::OAuthError;
use super::http::{default_http_client, OAuthHttpClient};
use super::request::{
    apply_client_authentication, post_form_with_client, ClientAuthentication, OAuthFormRequest,
};
use super::tokens::{get_oauth2_tokens, OAuth2Tokens, ProviderOptions};
use super::validate_authorization_code::ClientTokenRequest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshAccessTokenRequest {
    pub refresh_token: String,
    pub options: ProviderOptions,
    pub authentication: ClientAuthentication,
    pub extra_params: BTreeMap<String, String>,
    pub resource: Vec<String>,
}

impl Default for RefreshAccessTokenRequest {
    fn default() -> Self {
        Self {
            refresh_token: String::new(),
            options: ProviderOptions::default(),
            authentication: ClientAuthentication::Post,
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
    request.set_body("grant_type", "refresh_token");
    request.set_body("refresh_token", input.refresh_token);
    apply_client_authentication(&mut request, &input.options, input.authentication, false)?;
    for resource in input.resource {
        request.push_body("resource", resource);
    }
    for (key, value) in input.extra_params {
        request.set_body(key, value);
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

pub fn refresh_access_token_request(
    input: RefreshAccessTokenRequest,
) -> Result<OAuthFormRequest, OAuthError> {
    create_refresh_access_token_request(input)
}

pub async fn refresh_access_token(
    input: ClientTokenRequest<RefreshAccessTokenRequest>,
) -> Result<OAuth2Tokens, OAuthError> {
    refresh_access_token_with_client(input, &default_http_client()?).await
}

pub async fn refresh_access_token_with_client(
    input: ClientTokenRequest<RefreshAccessTokenRequest>,
    client: &OAuthHttpClient,
) -> Result<OAuth2Tokens, OAuthError> {
    let request = refresh_access_token_request(input.request)?;
    let data = post_form_with_client(&input.token_endpoint, request, client).await?;
    get_oauth2_tokens(data)
}
