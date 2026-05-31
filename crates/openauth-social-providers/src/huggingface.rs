//! Hugging Face social OAuth provider.

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
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::http::ProviderHttpClient;

pub const HUGGINGFACE_ID: &str = "huggingface";
pub const HUGGINGFACE_NAME: &str = "Hugging Face";
pub const HUGGINGFACE_AUTHORIZATION_ENDPOINT: &str = "https://huggingface.co/oauth/authorize";
pub const HUGGINGFACE_TOKEN_ENDPOINT: &str = "https://huggingface.co/oauth/token";
pub const HUGGINGFACE_USERINFO_ENDPOINT: &str = "https://huggingface.co/oauth/userinfo";
pub const HUGGINGFACE_DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];

pub type HuggingFaceUserInfoFuture =
    Pin<Box<dyn Future<Output = Result<Option<HuggingFaceUserInfo>, OAuthError>> + Send>>;
pub type HuggingFaceRefreshFuture =
    Pin<Box<dyn Future<Output = Result<OAuth2Tokens, OAuthError>> + Send>>;
pub type HuggingFaceGetUserInfo =
    Arc<dyn Fn(OAuth2Tokens) -> HuggingFaceUserInfoFuture + Send + Sync>;
pub type HuggingFaceRefreshAccessToken =
    Arc<dyn Fn(String) -> HuggingFaceRefreshFuture + Send + Sync>;
pub type HuggingFaceProfileMapper =
    Arc<dyn Fn(&HuggingFaceProfile) -> HuggingFaceUserPatch + Send + Sync>;

/// Role values returned by Hugging Face organization payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HuggingFaceRole {
    Admin,
    Write,
    Contributor,
    Read,
}

/// Hugging Face `isEnterprise` can be a boolean or the literal string `plus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HuggingFaceOrgEnterprise {
    Bool(bool),
    Plus,
}

impl Serialize for HuggingFaceOrgEnterprise {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Plus => serializer.serialize_str("plus"),
        }
    }
}

impl<'de> Deserialize<'de> for HuggingFaceOrgEnterprise {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Bool(value) => Ok(Self::Bool(value)),
            serde_json::Value::String(value) if value == "plus" => Ok(Self::Plus),
            other => Err(serde::de::Error::custom(format!(
                "expected boolean or \"plus\" for Hugging Face isEnterprise, got {other}"
            ))),
        }
    }
}

/// Hugging Face organization resource group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuggingFaceResourceGroup {
    pub sub: String,
    pub name: String,
    pub role: HuggingFaceRole,
}

/// Hugging Face organization membership data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuggingFaceOrg {
    pub sub: String,
    pub name: String,
    pub picture: String,
    pub preferred_username: String,
    #[serde(rename = "isEnterprise")]
    pub is_enterprise: HuggingFaceOrgEnterprise,
    #[serde(rename = "canPay", default)]
    pub can_pay: Option<bool>,
    #[serde(rename = "roleInOrg", default)]
    pub role_in_org: Option<HuggingFaceRole>,
    #[serde(rename = "pendingSSO", default)]
    pub pending_sso: Option<bool>,
    #[serde(rename = "missingMFA", default)]
    pub missing_mfa: Option<bool>,
    #[serde(rename = "resourceGroups", default)]
    pub resource_groups: Option<Vec<HuggingFaceResourceGroup>>,
}

/// Hugging Face OpenID profile returned by `/oauth/userinfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuggingFaceProfile {
    pub sub: String,
    pub name: String,
    pub preferred_username: String,
    pub profile: String,
    pub picture: String,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(rename = "isPro")]
    pub is_pro: bool,
    #[serde(rename = "canPay", default)]
    pub can_pay: Option<bool>,
    #[serde(default)]
    pub orgs: Option<Vec<HuggingFaceOrg>>,
}

/// Partial user override returned by `map_profile_to_user`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HuggingFaceUserPatch {
    pub id: Option<String>,
    pub name: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub image: Option<Option<String>>,
    pub email_verified: Option<bool>,
}

impl HuggingFaceUserPatch {
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

/// Hugging Face user info plus raw provider profile data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuggingFaceUserInfo {
    pub user: OAuth2UserInfo,
    pub data: HuggingFaceProfile,
}

/// Inputs required to build the Hugging Face authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HuggingFaceAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

/// Configuration for Hugging Face as a Better Auth-compatible social provider.
#[derive(Clone, Default)]
pub struct HuggingFaceOptions {
    pub oauth: ProviderOptions,
    pub get_user_info: Option<HuggingFaceGetUserInfo>,
    pub map_profile_to_user: Option<HuggingFaceProfileMapper>,
    pub refresh_access_token: Option<HuggingFaceRefreshAccessToken>,
}

impl From<ProviderOptions> for HuggingFaceOptions {
    fn from(oauth: ProviderOptions) -> Self {
        Self {
            oauth,
            get_user_info: None,
            map_profile_to_user: None,
            refresh_access_token: None,
        }
    }
}

/// Hugging Face OAuth provider.
#[derive(Clone)]
pub struct HuggingFaceProvider {
    options: HuggingFaceOptions,
    userinfo_endpoint: String,
    http_client: ProviderHttpClient,
}

impl Default for HuggingFaceProvider {
    fn default() -> Self {
        Self::new(HuggingFaceOptions::default())
    }
}

impl HuggingFaceProvider {
    pub fn new(options: impl Into<HuggingFaceOptions>) -> Self {
        Self {
            options: options.into(),
            userinfo_endpoint: HUGGINGFACE_USERINFO_ENDPOINT.to_owned(),
            http_client: ProviderHttpClient::shared(),
        }
    }

    /// Overrides the HTTP client used for userinfo requests. Use
    /// [`ProviderHttpClient::permissive`] in tests to reach local fixtures.
    pub fn with_http_client(mut self, http_client: ProviderHttpClient) -> Self {
        self.http_client = http_client;
        self
    }

    pub fn options(&self) -> &HuggingFaceOptions {
        &self.options
    }

    pub fn provider_options(&self) -> &ProviderOptions {
        &self.options.oauth
    }

    pub fn token_endpoint(&self) -> &str {
        HUGGINGFACE_TOKEN_ENDPOINT
    }

    pub fn userinfo_endpoint(&self) -> &str {
        &self.userinfo_endpoint
    }

    pub fn create_authorization_url(
        &self,
        input: HuggingFaceAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: self.id().to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: HUGGINGFACE_AUTHORIZATION_ENDPOINT.to_owned(),
            scopes: self.authorization_scopes(input.scopes),
            state: input.state,
            code_verifier: input.code_verifier,
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
        create_authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            code_verifier: code_verifier.map(Into::into),
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
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: HUGGINGFACE_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                code_verifier: code_verifier.map(Into::into),
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
            token_endpoint: HUGGINGFACE_TOKEN_ENDPOINT.to_owned(),
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
        token: &OAuth2Tokens,
    ) -> Result<Option<HuggingFaceUserInfo>, OAuthError> {
        if let Some(get_user_info) = &self.options.get_user_info {
            return get_user_info(token.clone()).await;
        }

        let Some(access_token) = token.access_token.as_deref() else {
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

        let profile = match response.json::<HuggingFaceProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(self.map_profile(profile)))
    }

    pub fn user_info_from_profile(profile: HuggingFaceProfile) -> HuggingFaceUserInfo {
        let name = if profile.name.is_empty() {
            profile.preferred_username.clone()
        } else {
            profile.name.clone()
        };

        HuggingFaceUserInfo {
            user: OAuth2UserInfo {
                id: profile.sub.clone(),
                name: Some(name),
                email: profile.email.clone(),
                image: Some(profile.picture.clone()),
                email_verified: profile.email_verified.unwrap_or(false),
            },
            data: profile,
        }
    }

    pub fn map_profile(&self, profile: HuggingFaceProfile) -> HuggingFaceUserInfo {
        let mut user_info = Self::user_info_from_profile(profile);
        if let Some(map_profile_to_user) = &self.options.map_profile_to_user {
            map_profile_to_user(&user_info.data).apply_to(&mut user_info.user);
        }
        user_info
    }

    fn authorization_scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = Vec::new();
        if !self.options.oauth.disable_default_scope {
            scopes.extend(
                HUGGINGFACE_DEFAULT_SCOPES
                    .iter()
                    .map(|scope| (*scope).to_owned()),
            );
        }
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl OAuthProviderContract for HuggingFaceProvider {
    fn id(&self) -> &str {
        HUGGINGFACE_ID
    }

    fn name(&self) -> &str {
        HUGGINGFACE_NAME
    }
}

pub fn huggingface(options: impl Into<HuggingFaceOptions>) -> HuggingFaceProvider {
    HuggingFaceProvider::new(options)
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
        let provider = HuggingFaceProvider {
            options: HuggingFaceOptions::default(),
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
