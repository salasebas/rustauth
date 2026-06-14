use std::collections::BTreeMap;

use url::Url;

use super::authorization_url::{create_authorization_url, AuthorizationUrlRequest};
use super::client_credentials_token::{
    create_client_credentials_token_request, ClientCredentialsTokenRequest,
};
use super::error::OAuthError;
use super::http::{default_http_client, OAuthHttpClient, OAuthHttpClientConfig};
use super::refresh_access_token::{create_refresh_access_token_request, RefreshAccessTokenRequest};
use super::request::{post_form_with_client, ClientAuthentication, OAuthFormRequest};
use super::tokens::{get_oauth2_tokens, get_primary_client_id, OAuth2Tokens, ProviderOptions};
use super::types::{AuthorizationEndpoint, TokenEndpoint};
use super::validate_authorization_code::{
    create_authorization_code_request, AuthorizationCodeRequest,
};

/// Configured OAuth 2.0 client for a single provider (fixed authorization and token endpoints).
#[derive(Debug, Clone)]
pub struct OAuth2Client {
    id: String,
    authorization_endpoint: AuthorizationEndpoint,
    token_endpoint: TokenEndpoint,
    options: ProviderOptions,
    default_scopes: Vec<String>,
    scope_joiner: String,
    authentication: ClientAuthentication,
    http: OAuthHttpClient,
}

/// Builder for [`OAuth2Client`]. Validates endpoints and `client_id` at [`OAuth2ClientBuilder::build`].
#[must_use = "OAuth2ClientBuilder must be built to produce a client"]
pub struct OAuth2ClientBuilder {
    id: String,
    options: ProviderOptions,
    authorization_endpoint: Option<AuthorizationEndpoint>,
    token_endpoint: Option<TokenEndpoint>,
    default_scopes: Vec<String>,
    scope_joiner: String,
    authentication: ClientAuthentication,
    http: Option<OAuthHttpClient>,
}

impl OAuth2Client {
    pub fn builder(
        provider_id: impl Into<String>,
        options: ProviderOptions,
    ) -> OAuth2ClientBuilder {
        OAuth2ClientBuilder {
            id: provider_id.into(),
            options,
            authorization_endpoint: None,
            token_endpoint: None,
            default_scopes: Vec::new(),
            scope_joiner: " ".to_owned(),
            authentication: ClientAuthentication::Post,
            http: None,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn options(&self) -> &ProviderOptions {
        &self.options
    }

    pub fn http(&self) -> &OAuthHttpClient {
        &self.http
    }

    pub fn authorization_endpoint(&self) -> &AuthorizationEndpoint {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &TokenEndpoint {
        &self.token_endpoint
    }

    pub fn authorization_url(
        &self,
        state: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<AuthorizationUrlBuilder<'_>, OAuthError> {
        let state = state.into();
        if state.is_empty() {
            return Err(OAuthError::InvalidConfiguration(
                "authorization state cannot be empty".to_owned(),
            ));
        }
        let redirect_uri = redirect_uri.into();
        url::Url::parse(
            self.options
                .redirect_uri
                .as_deref()
                .unwrap_or(&redirect_uri),
        )?;
        Ok(AuthorizationUrlBuilder {
            client: self,
            state,
            redirect_uri,
            code_verifier: None,
            scopes: Vec::new(),
            login_hint: None,
            prompt: None,
            access_type: None,
            response_type: None,
            response_mode: None,
            display: None,
            hd: None,
            duration: None,
            claims: Vec::new(),
            additional_params: BTreeMap::new(),
        })
    }

    pub fn exchange_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<ExchangeCodeBuilder<'_>, OAuthError> {
        Ok(ExchangeCodeBuilder {
            client: self,
            request: AuthorizationCodeRequest::try_new(code, redirect_uri, self.options.clone())?
                .authentication(self.authentication),
        })
    }

    pub fn refresh_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<RefreshTokenBuilder<'_>, OAuthError> {
        Ok(RefreshTokenBuilder {
            client: self,
            request: RefreshAccessTokenRequest::try_new(refresh_token, self.options.clone())?
                .authentication(self.authentication),
        })
    }

    pub fn client_credentials(&self) -> Result<ClientCredentialsBuilder<'_>, OAuthError> {
        Ok(ClientCredentialsBuilder {
            client: self,
            request: ClientCredentialsTokenRequest::try_new(self.options.clone())?
                .authentication(self.authentication),
        })
    }
}

impl OAuth2ClientBuilder {
    pub fn authorization_endpoint(mut self, url: impl Into<String>) -> Result<Self, OAuthError> {
        self.authorization_endpoint = Some(AuthorizationEndpoint::new(url)?);
        Ok(self)
    }

    pub fn token_endpoint(mut self, url: impl Into<String>) -> Result<Self, OAuthError> {
        self.token_endpoint = Some(TokenEndpoint::new(url)?);
        Ok(self)
    }

    pub fn default_scope(mut self, scope: impl Into<String>) -> Self {
        self.default_scopes.push(scope.into());
        self
    }

    pub fn default_scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.default_scopes
            .extend(scopes.into_iter().map(Into::into));
        self
    }

    pub fn scope_joiner(mut self, joiner: impl Into<String>) -> Self {
        self.scope_joiner = joiner.into();
        self
    }

    pub fn authentication(mut self, authentication: ClientAuthentication) -> Self {
        self.authentication = authentication;
        self
    }

    pub fn http_client(mut self, http: OAuthHttpClient) -> Self {
        self.http = Some(http);
        self
    }

    pub fn http_config(mut self, config: OAuthHttpClientConfig) -> Result<Self, OAuthError> {
        self.http = Some(OAuthHttpClient::from_config(config)?);
        Ok(self)
    }

    pub fn build(self) -> Result<OAuth2Client, OAuthError> {
        let authorization_endpoint = self
            .authorization_endpoint
            .ok_or(OAuthError::MissingOption("authorization_endpoint"))?;
        let token_endpoint = self
            .token_endpoint
            .ok_or(OAuthError::MissingOption("token_endpoint"))?;
        get_primary_client_id(&self.options.client_id)
            .ok_or(OAuthError::MissingOption("client_id"))?;
        let http = match self.http {
            Some(http) => http,
            None => default_http_client()?,
        };
        Ok(OAuth2Client {
            id: self.id,
            authorization_endpoint,
            token_endpoint,
            options: self.options,
            default_scopes: self.default_scopes,
            scope_joiner: self.scope_joiner,
            authentication: self.authentication,
            http,
        })
    }
}

/// Authorization URL builder returned by [`OAuth2Client::authorization_url`].
#[must_use = "AuthorizationUrlBuilder must be built to produce a URL"]
pub struct AuthorizationUrlBuilder<'a> {
    client: &'a OAuth2Client,
    state: String,
    redirect_uri: String,
    code_verifier: Option<String>,
    scopes: Vec<String>,
    login_hint: Option<String>,
    prompt: Option<String>,
    access_type: Option<String>,
    response_type: Option<String>,
    response_mode: Option<String>,
    display: Option<String>,
    hd: Option<String>,
    duration: Option<String>,
    claims: Vec<String>,
    additional_params: BTreeMap<String, String>,
}

impl AuthorizationUrlBuilder<'_> {
    pub fn code_verifier(mut self, code_verifier: impl Into<String>) -> Self {
        self.code_verifier = Some(code_verifier.into());
        self
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes.extend(scopes.into_iter().map(Into::into));
        self
    }

    pub fn login_hint(mut self, login_hint: impl Into<String>) -> Self {
        self.login_hint = Some(login_hint.into());
        self
    }

    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    pub fn access_type(mut self, access_type: impl Into<String>) -> Self {
        self.access_type = Some(access_type.into());
        self
    }

    pub fn response_type(mut self, response_type: impl Into<String>) -> Self {
        self.response_type = Some(response_type.into());
        self
    }

    pub fn response_mode(mut self, response_mode: impl Into<String>) -> Self {
        self.response_mode = Some(response_mode.into());
        self
    }

    pub fn claim(mut self, claim: impl Into<String>) -> Self {
        self.claims.push(claim.into());
        self
    }

    pub fn duration(mut self, duration: impl Into<String>) -> Self {
        self.duration = Some(duration.into());
        self
    }

    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.additional_params.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Result<Url, OAuthError> {
        let mut scopes = if !self.client.options.disable_default_scope {
            self.client.default_scopes.clone()
        } else {
            Vec::new()
        };
        scopes.extend(self.client.options.scope.iter().cloned());
        scopes.extend(self.scopes);

        create_authorization_url(AuthorizationUrlRequest {
            id: self.client.id.clone(),
            options: self.client.options.clone(),
            authorization_endpoint: self.client.authorization_endpoint.as_str().to_owned(),
            redirect_uri: self.redirect_uri,
            state: self.state,
            code_verifier: self.code_verifier,
            scopes,
            login_hint: self.login_hint,
            prompt: self.prompt.or_else(|| self.client.options.prompt.clone()),
            access_type: self.access_type,
            response_type: self.response_type,
            response_mode: self
                .response_mode
                .or_else(|| self.client.options.response_mode.clone()),
            display: self.display,
            hd: self.hd,
            duration: self.duration,
            claims: self.claims,
            additional_params: self.additional_params,
            scope_joiner: self.client.scope_joiner.clone(),
        })
    }
}

/// Authorization-code exchange builder returned by [`OAuth2Client::exchange_code`].
#[must_use = "ExchangeCodeBuilder must be sent or converted to a form request"]
pub struct ExchangeCodeBuilder<'a> {
    client: &'a OAuth2Client,
    request: AuthorizationCodeRequest,
}

impl ExchangeCodeBuilder<'_> {
    pub fn code_verifier(mut self, code_verifier: impl Into<String>) -> Self {
        self.request = self.request.code_verifier(code_verifier);
        self
    }

    pub fn device_id(mut self, device_id: impl Into<String>) -> Self {
        self.request.device_id = Some(device_id.into());
        self
    }

    pub fn authentication(mut self, authentication: ClientAuthentication) -> Self {
        self.request = self.request.authentication(authentication);
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.header(key, value);
        self
    }

    pub fn additional_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.additional_param(key, value);
        self
    }

    pub fn override_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.override_param(key, value);
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.request = self.request.resource(resource);
        self
    }

    pub fn into_form_request(self) -> Result<OAuthFormRequest, OAuthError> {
        create_authorization_code_request(self.request)
    }

    pub async fn send(self) -> Result<OAuth2Tokens, OAuthError> {
        exchange_authorization_code(
            self.client.token_endpoint.as_str(),
            self.request,
            &self.client.http,
        )
        .await
    }
}

/// Refresh-token builder returned by [`OAuth2Client::refresh_token`].
#[must_use = "RefreshTokenBuilder must be sent or converted to a form request"]
pub struct RefreshTokenBuilder<'a> {
    client: &'a OAuth2Client,
    request: RefreshAccessTokenRequest,
}

impl RefreshTokenBuilder<'_> {
    pub fn authentication(mut self, authentication: ClientAuthentication) -> Self {
        self.request = self.request.authentication(authentication);
        self
    }

    pub fn header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.header(key, value);
        self
    }

    pub fn extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.request = self.request.extra_param(key, value);
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.request = self.request.resource(resource);
        self
    }

    pub fn into_form_request(self) -> Result<OAuthFormRequest, OAuthError> {
        create_refresh_access_token_request(self.request)
    }

    pub async fn send(self) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token_at(
            self.client.token_endpoint.as_str(),
            self.request,
            &self.client.http,
        )
        .await
    }
}

/// Client-credentials grant builder returned by [`OAuth2Client::client_credentials`].
#[must_use = "ClientCredentialsBuilder must be sent or converted to a form request"]
pub struct ClientCredentialsBuilder<'a> {
    client: &'a OAuth2Client,
    request: ClientCredentialsTokenRequest,
}

impl ClientCredentialsBuilder<'_> {
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.request = self.request.scope(scope);
        self
    }

    pub fn authentication(mut self, authentication: ClientAuthentication) -> Self {
        self.request = self.request.authentication(authentication);
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.request = self.request.resource(resource);
        self
    }

    pub fn into_form_request(self) -> Result<OAuthFormRequest, OAuthError> {
        create_client_credentials_token_request(self.request)
    }

    pub async fn send(self) -> Result<OAuth2Tokens, OAuthError> {
        let request = create_client_credentials_token_request(self.request)?;
        let data = post_form_with_client(
            self.client.token_endpoint.as_str(),
            request,
            &self.client.http,
        )
        .await?;
        get_oauth2_tokens(data)
    }
}

/// Submits a prepared token form request (advanced / test flows).
pub async fn submit_token_form(
    token_endpoint: &str,
    request: OAuthFormRequest,
    client: &OAuthHttpClient,
) -> Result<OAuth2Tokens, OAuthError> {
    let data = post_form_with_client(token_endpoint, request, client).await?;
    get_oauth2_tokens(data)
}

/// Exchanges an authorization code at a token endpoint (advanced / discovery-based flows).
pub async fn exchange_authorization_code(
    token_endpoint: &str,
    request: AuthorizationCodeRequest,
    client: &OAuthHttpClient,
) -> Result<OAuth2Tokens, OAuthError> {
    let form = create_authorization_code_request(request)?;
    let data = post_form_with_client(token_endpoint, form, client).await?;
    get_oauth2_tokens(data)
}

/// Refreshes an access token at a token endpoint (advanced / discovery-based flows).
pub async fn refresh_access_token_at(
    token_endpoint: &str,
    request: RefreshAccessTokenRequest,
    client: &OAuthHttpClient,
) -> Result<OAuth2Tokens, OAuthError> {
    let form = create_refresh_access_token_request(request)?;
    let data = post_form_with_client(token_endpoint, form, client).await?;
    get_oauth2_tokens(data)
}
