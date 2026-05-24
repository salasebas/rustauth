use std::collections::BTreeMap;

use super::error::OAuthError;
use super::request::{
    apply_client_authentication, post_form, ClientAuthentication, OAuthFormRequest,
};
use super::tokens::{get_oauth2_tokens, OAuth2Tokens, ProviderOptions};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRequest {
    pub code: String,
    pub redirect_uri: String,
    pub options: ProviderOptions,
    pub code_verifier: Option<String>,
    pub device_id: Option<String>,
    pub authentication: ClientAuthentication,
    pub headers: BTreeMap<String, String>,
    pub additional_params: BTreeMap<String, String>,
    pub override_params: BTreeMap<String, String>,
    pub resource: Vec<String>,
}

impl Default for AuthorizationCodeRequest {
    fn default() -> Self {
        Self {
            code: String::new(),
            redirect_uri: String::new(),
            options: ProviderOptions::default(),
            code_verifier: None,
            device_id: None,
            authentication: ClientAuthentication::Post,
            headers: BTreeMap::new(),
            additional_params: BTreeMap::new(),
            override_params: BTreeMap::new(),
            resource: Vec::new(),
        }
    }
}

impl AuthorizationCodeRequest {
    pub fn try_new(
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
        options: ProviderOptions,
    ) -> Result<Self, OAuthError> {
        let code = code.into();
        if code.is_empty() {
            return Err(OAuthError::InvalidConfiguration(
                "authorization code cannot be empty".to_owned(),
            ));
        }
        let redirect_uri = redirect_uri.into();
        url::Url::parse(options.redirect_uri.as_deref().unwrap_or(&redirect_uri))?;
        Ok(Self {
            code,
            redirect_uri,
            options,
            ..Self::default()
        })
    }

    pub fn code_verifier(mut self, code_verifier: impl Into<String>) -> Self {
        self.code_verifier = Some(code_verifier.into());
        self
    }

    pub fn authentication(mut self, authentication: ClientAuthentication) -> Self {
        self.authentication = authentication;
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn additional_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.additional_params.insert(key.into(), value.into());
        self
    }

    pub fn override_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.override_params.insert(key.into(), value.into());
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource.push(resource.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTokenRequest<T> {
    pub token_endpoint: String,
    pub request: T,
}

pub fn create_authorization_code_request(
    input: AuthorizationCodeRequest,
) -> Result<OAuthFormRequest, OAuthError> {
    validate_authorization_code_request(&input)?;
    let mut request = OAuthFormRequest::new();
    for (key, value) in input.headers {
        request.set_header(key, value);
    }
    request.set_body("grant_type", "authorization_code");
    request.set_body("code", input.code);
    if let Some(code_verifier) = input.code_verifier {
        request.set_body("code_verifier", code_verifier);
    }
    if let Some(client_key) = &input.options.client_key {
        request.set_body("client_key", client_key);
    }
    if let Some(device_id) = input.device_id {
        request.set_body("device_id", device_id);
    }
    request.set_body(
        "redirect_uri",
        input
            .options
            .redirect_uri
            .as_deref()
            .unwrap_or(&input.redirect_uri),
    );
    for resource in input.resource {
        request.push_body("resource", resource);
    }
    apply_client_authentication(&mut request, &input.options, input.authentication, false)?;
    for (key, value) in input.additional_params {
        if !request.has_body(&key) {
            request.push_body(key, value);
        }
    }
    for (key, value) in input.override_params {
        request.set_body(key, value);
    }
    Ok(request)
}

fn validate_authorization_code_request(input: &AuthorizationCodeRequest) -> Result<(), OAuthError> {
    if input.code.is_empty() {
        return Err(OAuthError::InvalidConfiguration(
            "authorization code cannot be empty".to_owned(),
        ));
    }
    let redirect_uri = input
        .options
        .redirect_uri
        .as_deref()
        .unwrap_or(&input.redirect_uri);
    url::Url::parse(redirect_uri)?;
    Ok(())
}

pub fn authorization_code_request(
    input: AuthorizationCodeRequest,
) -> Result<OAuthFormRequest, OAuthError> {
    create_authorization_code_request(input)
}

pub async fn validate_authorization_code(
    input: ClientTokenRequest<AuthorizationCodeRequest>,
) -> Result<OAuth2Tokens, OAuthError> {
    let request = authorization_code_request(input.request)?;
    let data = post_form(&input.token_endpoint, request).await?;
    get_oauth2_tokens(data)
}
