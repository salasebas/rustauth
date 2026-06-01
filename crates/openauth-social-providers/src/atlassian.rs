//! Atlassian social OAuth provider.

use std::collections::BTreeMap;
use std::sync::Arc;

use openauth_oauth::oauth2::{
    create_authorization_url, refresh_access_token_with_client,
    validate_authorization_code_with_client, AuthorizationCodeRequest, AuthorizationUrlRequest,
    ClientId, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthProviderContract,
    ProviderOptions, RefreshAccessTokenRequest,
};

use crate::http::ValidationHttpClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const ATLASSIAN_ID: &str = "atlassian";
pub const ATLASSIAN_NAME: &str = "Atlassian";
pub const ATLASSIAN_AUTHORIZATION_ENDPOINT: &str = "https://auth.atlassian.com/authorize";
pub const ATLASSIAN_TOKEN_ENDPOINT: &str = "https://auth.atlassian.com/oauth/token";
pub const ATLASSIAN_USER_INFO_ENDPOINT: &str = "https://api.atlassian.com/me";

type UserMapper = Arc<dyn Fn(&AtlassianProfile) -> OAuth2UserInfo + Send + Sync>;

#[derive(Clone, Default)]
pub struct AtlassianOptions {
    pub oauth: ProviderOptions,
    pub map_profile_to_user: Option<UserMapper>,
}

impl AtlassianOptions {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            oauth: ProviderOptions {
                client_id: Some(ClientId::Single(client_id.into())),
                client_secret: Some(client_secret.into()),
                ..ProviderOptions::default()
            },
            map_profile_to_user: None,
        }
    }

    pub fn map_profile_to_user(
        mut self,
        mapper: impl Fn(&AtlassianProfile) -> OAuth2UserInfo + Send + Sync + 'static,
    ) -> Self {
        self.map_profile_to_user = Some(Arc::new(mapper));
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AtlassianAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AtlassianExtendedProfile {
    pub job_title: Option<String>,
    pub organization: Option<String>,
    pub department: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AtlassianProfile {
    pub account_type: Option<String>,
    pub account_id: String,
    pub email: Option<String>,
    pub name: String,
    pub picture: Option<String>,
    pub nickname: Option<String>,
    pub locale: Option<String>,
    pub extended_profile: Option<AtlassianExtendedProfile>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl AtlassianProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.account_id.clone(),
            name: Some(self.name.clone()),
            email: self.email.clone(),
            image: self.picture.clone(),
            email_verified: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AtlassianUserInfo {
    pub user: OAuth2UserInfo,
    pub data: AtlassianProfile,
}

#[derive(Clone)]
pub struct AtlassianProvider {
    options: AtlassianOptions,
    authorization_endpoint: &'static str,
    token_endpoint: String,
    user_info_endpoint: String,
    http_client: reqwest::Client,
    token_http_client: ValidationHttpClient,
}

pub fn atlassian(options: AtlassianOptions) -> AtlassianProvider {
    AtlassianProvider::new(options)
}

impl AtlassianProvider {
    pub fn new(options: AtlassianOptions) -> Self {
        Self {
            options,
            authorization_endpoint: ATLASSIAN_AUTHORIZATION_ENDPOINT,
            token_endpoint: ATLASSIAN_TOKEN_ENDPOINT.to_owned(),
            user_info_endpoint: ATLASSIAN_USER_INFO_ENDPOINT.to_owned(),
            http_client: crate::http::shared_client(),
            token_http_client: ValidationHttpClient::shared(),
        }
    }

    #[cfg(test)]
    fn with_endpoints(
        options: AtlassianOptions,
        token_endpoint: impl Into<String>,
        user_info_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            options,
            authorization_endpoint: ATLASSIAN_AUTHORIZATION_ENDPOINT,
            token_endpoint: token_endpoint.into(),
            user_info_endpoint: user_info_endpoint.into(),
            http_client: reqwest::Client::new(),
            token_http_client: ValidationHttpClient::permissive(),
        }
    }

    pub fn options(&self) -> &AtlassianOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        request: AtlassianAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        self.validate_authorization_options()?;
        let code_verifier = request
            .code_verifier
            .ok_or(OAuthError::MissingOption("code_verifier"))?;
        let mut scopes = Vec::new();
        if !self.options.oauth.disable_default_scope {
            scopes.push("read:jira-user".to_owned());
            scopes.push("offline_access".to_owned());
        }
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request.scopes);

        create_authorization_url(AuthorizationUrlRequest {
            id: ATLASSIAN_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: self.authorization_endpoint.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: Some(code_verifier),
            scopes,
            prompt: self.options.oauth.prompt.clone(),
            additional_params: BTreeMap::from([(
                "audience".to_owned(),
                "api.atlassian.com".to_owned(),
            )]),
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
        code_verifier: Option<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code_with_client(
            ClientTokenRequest {
                token_endpoint: self.token_endpoint.to_owned(),
                request: AuthorizationCodeRequest {
                    code: code.into(),
                    redirect_uri: redirect_uri.into(),
                    options: self.options.oauth.clone(),
                    code_verifier,
                    ..AuthorizationCodeRequest::default()
                },
            },
            self.token_http_client.inner(),
        )
        .await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token_with_client(
            ClientTokenRequest {
                token_endpoint: self.token_endpoint.to_owned(),
                request: RefreshAccessTokenRequest {
                    refresh_token: refresh_token_value.into(),
                    options: self.options.oauth.clone(),
                    ..RefreshAccessTokenRequest::default()
                },
            },
            self.token_http_client.inner(),
        )
        .await
    }

    pub async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<AtlassianUserInfo>, OAuthError> {
        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };

        let response = match self
            .http_client
            .get(&self.user_info_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        let response = match response.error_for_status() {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        let profile = match response.json::<AtlassianProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };

        let user = self
            .options
            .map_profile_to_user
            .as_ref()
            .map(|mapper| mapper(&profile))
            .unwrap_or_else(|| profile.to_user_info());

        Ok(Some(AtlassianUserInfo {
            user,
            data: profile,
        }))
    }

    fn validate_authorization_options(&self) -> Result<(), OAuthError> {
        if self
            .options
            .oauth
            .client_id
            .as_ref()
            .and_then(ClientId::primary)
            .is_none()
        {
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

impl OAuthProviderContract for AtlassianProvider {
    fn id(&self) -> &str {
        ATLASSIAN_ID
    }

    fn name(&self) -> &str {
        ATLASSIAN_NAME
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn atlassian_provider_contract_and_authorization_url_match_upstream_behavior() {
        let provider = AtlassianProvider::new(AtlassianOptions::new("client-id", "client-secret"));

        assert_eq!(provider.id(), "atlassian");
        assert_eq!(provider.name(), "Atlassian");

        let url = provider
            .create_authorization_url(AtlassianAuthorizationUrlRequest {
                state: "state-123".to_owned(),
                redirect_uri: "https://app.example.com/callback".to_owned(),
                code_verifier: Some(
                    "01234567890123456789012345678901234567890123456789".to_owned(),
                ),
                scopes: vec!["custom:scope".to_owned()],
            })
            .expect("authorization url should build");

        assert_eq!(
            url.as_str().split('?').next(),
            Some("https://auth.atlassian.com/authorize")
        );
        assert_eq!(query_value(&url, "response_type"), Some("code".to_owned()));
        assert_eq!(query_value(&url, "client_id"), Some("client-id".to_owned()));
        assert_eq!(query_value(&url, "state"), Some("state-123".to_owned()));
        assert_eq!(
            query_value(&url, "redirect_uri"),
            Some("https://app.example.com/callback".to_owned())
        );
        assert_eq!(
            query_value(&url, "scope"),
            Some("read:jira-user offline_access custom:scope".to_owned())
        );
        assert_eq!(
            query_value(&url, "audience"),
            Some("api.atlassian.com".to_owned())
        );
        assert_eq!(
            query_value(&url, "code_challenge_method"),
            Some("S256".to_owned())
        );
        assert!(query_value(&url, "code_challenge").is_some());
    }

    #[test]
    fn authorization_url_appends_configured_scopes_and_prompt() {
        let mut options = AtlassianOptions::new("client-id", "client-secret");
        options.oauth.scope = vec!["configured:scope".to_owned()];
        options.oauth.prompt = Some("consent".to_owned());
        let provider = AtlassianProvider::new(options);

        let url = provider
            .create_authorization_url(AtlassianAuthorizationUrlRequest {
                state: "state-123".to_owned(),
                redirect_uri: "https://app.example.com/callback".to_owned(),
                code_verifier: Some(
                    "01234567890123456789012345678901234567890123456789".to_owned(),
                ),
                scopes: vec!["request:scope".to_owned()],
            })
            .expect("authorization url should build");

        assert_eq!(
            query_value(&url, "scope"),
            Some("read:jira-user offline_access configured:scope request:scope".to_owned())
        );
        assert_eq!(query_value(&url, "prompt"), Some("consent".to_owned()));
    }

    #[test]
    fn authorization_url_validates_required_options() {
        let provider = AtlassianProvider::new(AtlassianOptions::default());
        let err = provider
            .create_authorization_url(valid_authorization_request())
            .expect_err("missing client id should fail");
        assert!(matches!(err, OAuthError::MissingOption("client_id")));

        let mut options = AtlassianOptions::default();
        options.oauth.client_id = Some(ClientId::Single("client-id".to_owned()));
        let provider = AtlassianProvider::new(options);
        let err = provider
            .create_authorization_url(valid_authorization_request())
            .expect_err("missing client secret should fail");
        assert!(matches!(err, OAuthError::MissingOption("client_secret")));

        let provider = AtlassianProvider::new(AtlassianOptions::new("client-id", "client-secret"));
        let mut request = valid_authorization_request();
        request.code_verifier = None;
        let err = provider
            .create_authorization_url(request)
            .expect_err("missing code verifier should fail");
        assert!(matches!(err, OAuthError::MissingOption("code_verifier")));
    }

    #[test]
    fn authorization_url_can_disable_default_scopes() {
        let mut options = AtlassianOptions::new("client-id", "client-secret");
        options.oauth.disable_default_scope = true;
        options.oauth.scope = vec!["configured:scope".to_owned()];
        let provider = AtlassianProvider::new(options);

        let url = provider
            .create_authorization_url(AtlassianAuthorizationUrlRequest {
                scopes: vec!["request:scope".to_owned()],
                ..valid_authorization_request()
            })
            .expect("authorization url should build");

        assert_eq!(
            query_value(&url, "scope"),
            Some("configured:scope request:scope".to_owned())
        );
    }

    #[tokio::test]
    async fn token_methods_post_expected_authorization_and_refresh_forms() {
        let code_server = JsonServer::spawn(json_object("access_token", "access-token"));
        let provider = AtlassianProvider::with_endpoints(
            AtlassianOptions::new("client-id", "client-secret"),
            code_server.url(),
            "http://127.0.0.1/unused",
        );

        let tokens = provider
            .validate_authorization_code(
                "code-123",
                "https://app.example.com/callback",
                Some("01234567890123456789012345678901234567890123456789".to_owned()),
            )
            .await
            .expect("authorization code should validate");

        assert_eq!(tokens.access_token.as_deref(), Some("access-token"));
        let body = code_server.request_body();
        assert!(body.contains("grant_type=authorization_code"));
        assert!(body.contains("code=code-123"));
        assert!(body.contains("code_verifier=01234567890123456789012345678901234567890123456789"));
        assert!(body.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback"));
        assert!(body.contains("client_id=client-id"));
        assert!(body.contains("client_secret=client-secret"));

        let refresh_server = JsonServer::spawn(json_object("access_token", "new-access-token"));
        let provider = AtlassianProvider::with_endpoints(
            AtlassianOptions::new("client-id", "client-secret"),
            refresh_server.url(),
            "http://127.0.0.1/unused",
        );

        let tokens = provider
            .refresh_access_token("refresh-token")
            .await
            .expect("refresh token should validate");

        assert_eq!(tokens.access_token.as_deref(), Some("new-access-token"));
        let body = refresh_server.request_body();
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=refresh-token"));
        assert!(body.contains("client_id=client-id"));
        assert!(body.contains("client_secret=client-secret"));
    }

    #[tokio::test]
    async fn get_user_info_maps_profile_and_sends_bearer_authorization() {
        let user_server = JsonServer::spawn(serde_json::json!({
            "account_type": "atlassian",
            "account_id": "account-123",
            "email": "ada@example.com",
            "name": "Ada Lovelace",
            "picture": "https://example.com/ada.png",
            "nickname": "ada",
            "locale": "en-US",
            "extended_profile": {
                "job_title": "Engineer",
                "organization": "Example",
                "department": "R&D",
                "location": "London"
            }
        }));
        let provider = AtlassianProvider::with_endpoints(
            AtlassianOptions::new("client-id", "client-secret"),
            "http://127.0.0.1/unused",
            user_server.url(),
        );

        let info = provider
            .get_user_info(&OAuth2Tokens {
                access_token: Some("access-token".to_owned()),
                ..OAuth2Tokens::default()
            })
            .await
            .expect("user info should fetch")
            .expect("access token should produce user info");

        assert_eq!(info.user.id, "account-123");
        assert_eq!(info.user.name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(info.user.email.as_deref(), Some("ada@example.com"));
        assert_eq!(
            info.user.image.as_deref(),
            Some("https://example.com/ada.png")
        );
        assert!(!info.user.email_verified);
        assert_eq!(info.data.nickname.as_deref(), Some("ada"));
        assert!(user_server
            .request_headers()
            .contains("authorization: bearer access-token"));
    }

    #[tokio::test]
    async fn get_user_info_returns_none_without_access_token_and_allows_mapper_override() {
        let provider = AtlassianProvider::new(AtlassianOptions::new("client-id", "client-secret"));
        assert_eq!(
            provider
                .get_user_info(&OAuth2Tokens::default())
                .await
                .expect("missing access token should not error"),
            None
        );

        let user_server = JsonServer::spawn(serde_json::json!({
            "account_id": "account-123",
            "email": "ada@example.com",
            "name": "Ada Lovelace"
        }));
        let options =
            AtlassianOptions::new("client-id", "client-secret").map_profile_to_user(|profile| {
                OAuth2UserInfo {
                    id: format!("mapped-{}", profile.account_id),
                    name: Some("Mapped Name".to_owned()),
                    email: Some("mapped@example.com".to_owned()),
                    image: Some("https://example.com/mapped.png".to_owned()),
                    email_verified: true,
                }
            });
        let provider = AtlassianProvider::with_endpoints(
            options,
            "http://127.0.0.1/unused",
            user_server.url(),
        );

        let info = provider
            .get_user_info(&OAuth2Tokens {
                access_token: Some("access-token".to_owned()),
                ..OAuth2Tokens::default()
            })
            .await
            .expect("user info should fetch")
            .expect("access token should produce user info");

        assert_eq!(info.user.id, "mapped-account-123");
        assert_eq!(info.user.name.as_deref(), Some("Mapped Name"));
        assert_eq!(info.user.email.as_deref(), Some("mapped@example.com"));
        assert!(info.user.email_verified);
    }

    fn valid_authorization_request() -> AtlassianAuthorizationUrlRequest {
        AtlassianAuthorizationUrlRequest {
            state: "state-123".to_owned(),
            redirect_uri: "https://app.example.com/callback".to_owned(),
            code_verifier: Some("01234567890123456789012345678901234567890123456789".to_owned()),
            scopes: Vec::new(),
        }
    }

    fn query_value(url: &url::Url, key: &str) -> Option<String> {
        url.query_pairs()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value.into_owned())
    }

    fn json_object(key: &str, value: &str) -> serde_json::Value {
        serde_json::json!({
            key: value,
            "token_type": "Bearer"
        })
    }

    struct JsonServer {
        url: String,
        request: Arc<std::sync::Mutex<String>>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl JsonServer {
        fn spawn(response: serde_json::Value) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
            let url = format!(
                "http://{}",
                listener.local_addr().expect("local addr should exist")
            );
            let request = Arc::new(std::sync::Mutex::new(String::new()));
            let request_for_thread = Arc::clone(&request);
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("connection should accept");
                let mut buffer = [0; 8192];
                let read = stream.read(&mut buffer).expect("request should read");
                let raw_request = String::from_utf8_lossy(&buffer[..read]).to_string();
                *request_for_thread.lock().expect("request lock") = raw_request;
                let response_body = response.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response should write");
            });

            Self {
                url,
                request,
                handle: Some(handle),
            }
        }

        fn url(&self) -> String {
            self.url.clone()
        }

        fn request_body(&self) -> String {
            self.request
                .lock()
                .expect("request lock")
                .split_once("\r\n\r\n")
                .map(|(_, body)| body.to_owned())
                .unwrap_or_default()
        }

        fn request_headers(&self) -> String {
            self.request
                .lock()
                .expect("request lock")
                .split_once("\r\n\r\n")
                .map(|(headers, _)| headers.to_ascii_lowercase())
                .unwrap_or_default()
        }
    }

    impl Drop for JsonServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }
}
