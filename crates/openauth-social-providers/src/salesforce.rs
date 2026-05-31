//! Salesforce social OAuth provider.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use openauth_oauth::oauth2::{
    create_authorization_code_request, create_authorization_url,
    create_refresh_access_token_request, refresh_access_token, validate_authorization_code,
    AuthorizationCodeRequest, AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest,
    OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract,
    ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::http::ProviderHttpClient;

pub const SALESFORCE_ID: &str = "salesforce";
pub const SALESFORCE_NAME: &str = "Salesforce";
pub const SALESFORCE_PRODUCTION_AUTHORIZATION_ENDPOINT: &str =
    "https://login.salesforce.com/services/oauth2/authorize";
pub const SALESFORCE_PRODUCTION_TOKEN_ENDPOINT: &str =
    "https://login.salesforce.com/services/oauth2/token";
pub const SALESFORCE_PRODUCTION_USERINFO_ENDPOINT: &str =
    "https://login.salesforce.com/services/oauth2/userinfo";
pub const SALESFORCE_SANDBOX_AUTHORIZATION_ENDPOINT: &str =
    "https://test.salesforce.com/services/oauth2/authorize";
pub const SALESFORCE_SANDBOX_TOKEN_ENDPOINT: &str =
    "https://test.salesforce.com/services/oauth2/token";
pub const SALESFORCE_SANDBOX_USERINFO_ENDPOINT: &str =
    "https://test.salesforce.com/services/oauth2/userinfo";
pub const SALESFORCE_DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

pub type SalesforceUserInfoFuture =
    Pin<Box<dyn Future<Output = Result<Option<SalesforceUserInfo>, OAuthError>> + Send>>;
pub type SalesforceRefreshFuture =
    Pin<Box<dyn Future<Output = Result<OAuth2Tokens, OAuthError>> + Send>>;
pub type SalesforceGetUserInfo =
    Arc<dyn Fn(OAuth2Tokens) -> SalesforceUserInfoFuture + Send + Sync>;
pub type SalesforceRefreshAccessToken =
    Arc<dyn Fn(String) -> SalesforceRefreshFuture + Send + Sync>;
pub type SalesforceProfileMapper =
    Arc<dyn Fn(&SalesforceProfile) -> SalesforceUserPatch + Send + Sync>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SalesforceEnvironment {
    #[default]
    Production,
    Sandbox,
}

#[derive(Clone, Default)]
pub struct SalesforceOptions {
    pub oauth: ProviderOptions,
    pub environment: SalesforceEnvironment,
    pub login_url: Option<String>,
    pub get_user_info: Option<SalesforceGetUserInfo>,
    pub map_profile_to_user: Option<SalesforceProfileMapper>,
    pub refresh_access_token: Option<SalesforceRefreshAccessToken>,
}

impl From<ProviderOptions> for SalesforceOptions {
    fn from(oauth: ProviderOptions) -> Self {
        Self {
            oauth,
            environment: SalesforceEnvironment::Production,
            login_url: None,
            get_user_info: None,
            map_profile_to_user: None,
            refresh_access_token: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SalesforceAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SalesforcePhotos {
    #[serde(default)]
    pub picture: Option<String>,
    #[serde(default)]
    pub thumbnail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SalesforceProfile {
    pub sub: String,
    pub user_id: String,
    pub organization_id: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    pub email: String,
    #[serde(default)]
    pub email_verified: Option<bool>,
    pub name: String,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub zoneinfo: Option<String>,
    #[serde(default)]
    pub photos: Option<SalesforcePhotos>,
}

impl SalesforceProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.user_id.clone(),
            name: Some(self.name.clone()),
            email: Some(self.email.clone()),
            image: self
                .photos
                .as_ref()
                .and_then(|photos| photos.picture.clone().or_else(|| photos.thumbnail.clone())),
            email_verified: self.email_verified.unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SalesforceUserPatch {
    pub id: Option<String>,
    pub name: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub image: Option<Option<String>>,
    pub email_verified: Option<bool>,
}

impl SalesforceUserPatch {
    fn apply_to(self, user: &mut OAuth2UserInfo) {
        if let Some(id) = self.id {
            user.id = id;
        }
        if let Some(name) = self.name {
            user.name = name;
        }
        if let Some(email) = self.email {
            user.email = email;
        }
        if let Some(image) = self.image {
            user.image = image;
        }
        if let Some(email_verified) = self.email_verified {
            user.email_verified = email_verified;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SalesforceUserInfo {
    pub user: OAuth2UserInfo,
    pub data: SalesforceProfile,
}

#[derive(Clone)]
pub struct SalesforceProvider {
    options: SalesforceOptions,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    http_client: ProviderHttpClient,
}

pub fn salesforce(options: impl Into<SalesforceOptions>) -> SalesforceProvider {
    SalesforceProvider::new(options)
}

impl SalesforceProvider {
    pub fn new(options: impl Into<SalesforceOptions>) -> Self {
        let options = options.into();
        let endpoints = salesforce_endpoints(&options);

        Self {
            options,
            authorization_endpoint: endpoints.authorization,
            token_endpoint: endpoints.token,
            userinfo_endpoint: endpoints.userinfo,
            http_client: ProviderHttpClient::shared(),
        }
    }

    /// Overrides the HTTP client used for userinfo requests. Use
    /// [`ProviderHttpClient::permissive`] in tests to reach local fixtures.
    pub fn with_http_client(mut self, http_client: ProviderHttpClient) -> Self {
        self.http_client = http_client;
        self
    }

    pub fn options(&self) -> &SalesforceOptions {
        &self.options
    }

    pub fn provider_options(&self) -> &ProviderOptions {
        &self.options.oauth
    }

    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    pub fn userinfo_endpoint(&self) -> &str {
        &self.userinfo_endpoint
    }

    pub fn create_authorization_url(
        &self,
        input: SalesforceAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.ensure_client_credentials()?;
        let code_verifier = input
            .code_verifier
            .ok_or(OAuthError::MissingOption("code_verifier"))?;

        create_authorization_url(AuthorizationUrlRequest {
            id: SALESFORCE_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            scopes: self.authorization_scopes(input.scopes),
            state: input.state,
            code_verifier: Some(code_verifier),
            redirect_uri: input.redirect_uri,
            prompt: self.options.oauth.prompt.clone(),
            response_mode: self.options.oauth.response_mode.clone(),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn create_authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        let code_verifier = code_verifier
            .map(Into::into)
            .ok_or(OAuthError::MissingOption("code_verifier"))?;

        create_authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            code_verifier: Some(code_verifier),
            redirect_uri: redirect_uri.into(),
            options: self.options.oauth.clone(),
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
                code_verifier: Some(code_verifier),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub fn create_refresh_access_token_request(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        create_refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token_value.into(),
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Post,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let refresh_token_value = refresh_token_value.into();
        if let Some(refresh_access_token) = &self.options.refresh_access_token {
            return refresh_access_token(refresh_token_value).await;
        }

        refresh_access_token(ClientTokenRequest {
            token_endpoint: self.token_endpoint.clone(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token_value,
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<SalesforceUserInfo>, OAuthError> {
        if let Some(get_user_info) = &self.options.get_user_info {
            return get_user_info(tokens.clone()).await;
        }

        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };

        let response = match self
            .http_client
            .get(&self.userinfo_endpoint)?
            .bearer_auth(access_token)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }

        let profile = match response.json::<SalesforceProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(self.map_profile(profile)))
    }

    pub fn user_info_from_profile(profile: SalesforceProfile) -> SalesforceUserInfo {
        SalesforceUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }
    }

    pub fn map_profile(&self, profile: SalesforceProfile) -> SalesforceUserInfo {
        let mut user_info = Self::user_info_from_profile(profile);
        if let Some(map_profile_to_user) = &self.options.map_profile_to_user {
            map_profile_to_user(&user_info.data).apply_to(&mut user_info.user);
        }
        user_info
    }

    fn ensure_client_credentials(&self) -> Result<(), OAuthError> {
        if self.options.oauth.client_id.is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if self.options.oauth.client_secret.is_none() {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }

    fn authorization_scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = Vec::new();
        if !self.options.oauth.disable_default_scope {
            scopes.extend(
                SALESFORCE_DEFAULT_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_owned()),
            );
        }
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl OAuthProviderContract for SalesforceProvider {
    fn id(&self) -> &str {
        SALESFORCE_ID
    }

    fn name(&self) -> &str {
        SALESFORCE_NAME
    }
}

struct SalesforceEndpoints {
    authorization: String,
    token: String,
    userinfo: String,
}

fn salesforce_endpoints(options: &SalesforceOptions) -> SalesforceEndpoints {
    if let Some(login_url) = &options.login_url {
        let base = format!("https://{login_url}/services/oauth2");
        return SalesforceEndpoints {
            authorization: format!("{base}/authorize"),
            token: format!("{base}/token"),
            userinfo: format!("{base}/userinfo"),
        };
    }

    match options.environment {
        SalesforceEnvironment::Production => SalesforceEndpoints {
            authorization: SALESFORCE_PRODUCTION_AUTHORIZATION_ENDPOINT.to_owned(),
            token: SALESFORCE_PRODUCTION_TOKEN_ENDPOINT.to_owned(),
            userinfo: SALESFORCE_PRODUCTION_USERINFO_ENDPOINT.to_owned(),
        },
        SalesforceEnvironment::Sandbox => SalesforceEndpoints {
            authorization: SALESFORCE_SANDBOX_AUTHORIZATION_ENDPOINT.to_owned(),
            token: SALESFORCE_SANDBOX_TOKEN_ENDPOINT.to_owned(),
            userinfo: SALESFORCE_SANDBOX_USERINFO_ENDPOINT.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "provider tests use local HTTP fixtures and fail fast on setup errors"
    )]

    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[tokio::test]
    async fn get_user_info_returns_none_for_invalid_json() {
        let server = RawServer::spawn("not-json");
        let provider = SalesforceProvider {
            options: SalesforceOptions::default(),
            authorization_endpoint: "http://127.0.0.1/unused".to_owned(),
            token_endpoint: "http://127.0.0.1/unused".to_owned(),
            userinfo_endpoint: server.url(),
            http_client: ProviderHttpClient::permissive(),
        };

        let result = provider
            .get_user_info(&OAuth2Tokens {
                access_token: Some("access-token".to_owned()),
                ..OAuth2Tokens::default()
            })
            .await
            .expect("invalid userinfo JSON should not error");

        assert_eq!(result, None);
    }

    struct RawServer {
        url: String,
    }

    impl RawServer {
        fn spawn(body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
            let address = listener.local_addr().expect("local address");
            thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
            });

            Self {
                url: format!("http://{address}"),
            }
        }

        fn url(&self) -> String {
            self.url.clone()
        }
    }
}
