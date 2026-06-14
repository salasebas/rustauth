//! Hugging Face social OAuth provider.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::http::ProviderHttpClient;
use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://huggingface.co/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://huggingface.co/oauth/token";
const USERINFO_ENDPOINT: &str = "https://huggingface.co/oauth/userinfo";
const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];

pub const HUGGINGFACE_ID: &str = "huggingface";
pub const HUGGINGFACE_NAME: &str = "Hugging Face";
pub const HUGGINGFACE_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const HUGGINGFACE_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const HUGGINGFACE_USERINFO_ENDPOINT: &str = USERINFO_ENDPOINT;
pub const HUGGINGFACE_DEFAULT_SCOPES: &[&str] = DEFAULT_SCOPES;

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
    client: OAuth2Client,
    options: HuggingFaceOptions,
    userinfo_endpoint: String,
    http_client: ProviderHttpClient,
}

impl HuggingFaceProvider {
    #[deprecated(note = "use advanced::huggingface::huggingface() instead")]
    pub fn new(options: impl Into<HuggingFaceOptions>) -> Result<Self, OAuthError> {
        let options = options.into();
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("huggingface", options.oauth.clone())
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
            options,
            userinfo_endpoint: USERINFO_ENDPOINT.to_owned(),
            http_client: ProviderHttpClient::shared(),
        })
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
        self.client.options()
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn userinfo_endpoint(&self) -> &str {
        &self.userinfo_endpoint
    }

    pub fn create_authorization_url(
        &self,
        input: HuggingFaceAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(input.state, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        if let Some(prompt) = self.client.options().prompt.clone() {
            url = url.prompt(prompt);
        }
        if let Some(response_mode) = self.client.options().response_mode.clone() {
            url = url.response_mode(response_mode);
        }
        url.scopes(input.scopes).build()
    }

    pub fn create_authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier.into());
        }
        exchange.into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier.into());
        }
        exchange.send().await
    }

    pub fn create_refresh_access_token_request(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .refresh_token(refresh_token_value)?
            .into_form_request()
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let refresh_token_value = refresh_token_value.into();
        if let Some(refresh_access_token) = &self.options.refresh_access_token {
            return refresh_access_token(refresh_token_value).await;
        }

        self.client.refresh_token(refresh_token_value)?.send().await
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

    pub fn id(&self) -> &str {
        HUGGINGFACE_ID
    }

    pub fn name(&self) -> &str {
        HUGGINGFACE_NAME
    }
}

impl ProviderIdentity for HuggingFaceProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}

#[allow(deprecated)]
pub fn huggingface(
    options: impl Into<HuggingFaceOptions>,
) -> Result<HuggingFaceProvider, OAuthError> {
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
            client: OAuth2Client::builder(
                "huggingface",
                ProviderOptions {
                    client_id: Some("client".into()),
                    ..ProviderOptions::default()
                },
            )
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)
            .expect("authorization endpoint")
            .token_endpoint(TOKEN_ENDPOINT)
            .expect("token endpoint")
            .build()
            .expect("client"),
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
