use super::error::OAuthError;
use super::request::{apply_client_authentication, ClientAuthentication, OAuthFormRequest};
use super::tokens::{get_primary_client_id, ProviderOptions};

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
            .client_secret_str()
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
        .client_secret_str()
        .ok_or(OAuthError::MissingOption("client_secret"))?;
    apply_client_authentication(&mut request, &input.options, input.authentication, true)?;
    Ok(request)
}
