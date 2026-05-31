use super::error::OAuthError;
use super::http::{default_http_client, OAuthHttpClient};
use super::request::{
    apply_client_authentication, post_form_with_client, ClientAuthentication, OAuthFormRequest,
};
use super::tokens::{get_oauth2_tokens, get_primary_client_id, OAuth2Tokens, ProviderOptions};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentialsTokenRequest {
    pub options: ProviderOptions,
    pub scope: Option<String>,
    pub authentication: ClientAuthentication,
    pub resource: Vec<String>,
}

impl Default for ClientCredentialsTokenRequest {
    fn default() -> Self {
        Self {
            options: ProviderOptions::default(),
            scope: None,
            authentication: ClientAuthentication::Post,
            resource: Vec::new(),
        }
    }
}

impl ClientCredentialsTokenRequest {
    pub fn try_new(options: ProviderOptions) -> Result<Self, OAuthError> {
        get_primary_client_id(&options.client_id).ok_or(OAuthError::MissingOption("client_id"))?;
        options
            .client_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
            .ok_or(OAuthError::MissingOption("client_secret"))?;
        Ok(Self {
            options,
            ..Self::default()
        })
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn authentication(mut self, authentication: ClientAuthentication) -> Self {
        self.authentication = authentication;
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource.push(resource.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCredentialsGrant {
    pub token_endpoint: String,
    pub request: ClientCredentialsTokenRequest,
}

pub fn create_client_credentials_token_request(
    input: ClientCredentialsTokenRequest,
) -> Result<OAuthFormRequest, OAuthError> {
    let mut request = OAuthFormRequest::new();
    request.set_body("grant_type", "client_credentials");
    if let Some(scope) = input.scope {
        request.set_body("scope", scope);
    }
    for resource in input.resource {
        request.push_body("resource", resource);
    }
    get_primary_client_id(&input.options.client_id)
        .ok_or(OAuthError::MissingOption("client_id"))?;
    input
        .options
        .client_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
        .ok_or(OAuthError::MissingOption("client_secret"))?;
    apply_client_authentication(&mut request, &input.options, input.authentication, true)?;
    Ok(request)
}

pub fn client_credentials_token_request(
    input: ClientCredentialsTokenRequest,
) -> Result<OAuthFormRequest, OAuthError> {
    create_client_credentials_token_request(input)
}

pub async fn client_credentials_token(
    input: ClientCredentialsGrant,
) -> Result<OAuth2Tokens, OAuthError> {
    client_credentials_token_with_client(input, &default_http_client()?).await
}

pub async fn client_credentials_token_with_client(
    input: ClientCredentialsGrant,
    client: &OAuthHttpClient,
) -> Result<OAuth2Tokens, OAuthError> {
    let request = client_credentials_token_request(input.request)?;
    let data = post_form_with_client(&input.token_endpoint, request, client).await?;
    get_oauth2_tokens(data)
}
