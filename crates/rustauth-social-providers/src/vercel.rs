//! Vercel social OAuth provider.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

pub const VERCEL_ID: &str = "vercel";
pub const VERCEL_NAME: &str = "Vercel";
pub const VERCEL_AUTHORIZATION_ENDPOINT: &str = "https://vercel.com/oauth/authorize";
pub const VERCEL_TOKEN_ENDPOINT: &str = "https://api.vercel.com/login/oauth/token";
pub const VERCEL_USERINFO_ENDPOINT: &str = "https://api.vercel.com/login/oauth/userinfo";

pub type VercelUserInfoFuture =
    Pin<Box<dyn Future<Output = Result<Option<VercelUserInfo>, OAuthError>> + Send>>;
pub type VercelGetUserInfo = Arc<dyn Fn(OAuth2Tokens) -> VercelUserInfoFuture + Send + Sync>;
pub type VercelProfileMapper = Arc<dyn Fn(&VercelProfile) -> VercelUserPatch + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VercelProfile {
    pub sub: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub picture: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VercelUserPatch {
    pub id: Option<String>,
    pub name: Option<Option<String>>,
    pub email: Option<Option<String>>,
    pub image: Option<Option<String>>,
    pub email_verified: Option<bool>,
}

impl VercelUserPatch {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VercelUserInfo {
    pub user: OAuth2UserInfo,
    pub data: VercelProfile,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VercelAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Clone, Default)]
pub struct VercelOptions {
    pub oauth: ProviderOptions,
    pub get_user_info: Option<VercelGetUserInfo>,
    pub map_profile_to_user: Option<VercelProfileMapper>,
}

impl From<ProviderOptions> for VercelOptions {
    fn from(oauth: ProviderOptions) -> Self {
        Self {
            oauth,
            get_user_info: None,
            map_profile_to_user: None,
        }
    }
}

#[derive(Clone)]
pub struct VercelProvider {
    client: OAuth2Client,
    get_user_info: Option<VercelGetUserInfo>,
    map_profile_to_user: Option<VercelProfileMapper>,
    userinfo_endpoint: String,
    http_client: reqwest::Client,
}

#[allow(deprecated)]
pub fn vercel(options: impl Into<VercelOptions>) -> Result<VercelProvider, OAuthError> {
    VercelProvider::new(options)
}

impl VercelProvider {
    #[deprecated(note = "use advanced::vercel::vercel() instead")]
    pub fn new(options: impl Into<VercelOptions>) -> Result<Self, OAuthError> {
        let options = options.into();
        let VercelOptions {
            oauth,
            get_user_info,
            map_profile_to_user,
        } = options;
        Ok(Self {
            client: OAuth2Client::builder(VERCEL_ID, oauth)
                .authorization_endpoint(VERCEL_AUTHORIZATION_ENDPOINT)?
                .token_endpoint(VERCEL_TOKEN_ENDPOINT)?
                .build()?,
            get_user_info,
            map_profile_to_user,
            userinfo_endpoint: VERCEL_USERINFO_ENDPOINT.to_owned(),
            http_client: crate::http::shared_client(),
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn token_endpoint(&self) -> &str {
        VERCEL_TOKEN_ENDPOINT
    }

    pub fn userinfo_endpoint(&self) -> &str {
        &self.userinfo_endpoint
    }

    pub fn create_authorization_url(
        &self,
        request: VercelAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let code_verifier = request
            .code_verifier
            .ok_or(OAuthError::MissingOption("code_verifier"))?;
        self.client
            .authorization_url(request.state, request.redirect_uri)?
            .code_verifier(code_verifier)
            .scopes(request.scopes)
            .build()
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
        self.client
            .exchange_code(code, redirect_uri)?
            .code_verifier(code_verifier)
            .send()
            .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<VercelUserInfo>, OAuthError> {
        if let Some(get_user_info) = &self.get_user_info {
            return get_user_info(token.clone()).await;
        }

        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let response = match self
            .http_client
            .get(&self.userinfo_endpoint)
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

        let profile = match response.json::<VercelProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(self.map_profile(profile)))
    }

    pub fn user_info_from_profile(profile: VercelProfile) -> VercelUserInfo {
        let name = profile
            .name
            .clone()
            .or_else(|| profile.preferred_username.clone())
            .unwrap_or_default();

        VercelUserInfo {
            user: OAuth2UserInfo {
                id: profile.sub.clone(),
                name: Some(name),
                email: profile.email.clone(),
                image: profile.picture.clone(),
                email_verified: profile.email_verified.unwrap_or(false),
            },
            data: profile,
        }
    }

    pub fn map_profile(&self, profile: VercelProfile) -> VercelUserInfo {
        let mut user_info = Self::user_info_from_profile(profile);
        if let Some(map_profile_to_user) = &self.map_profile_to_user {
            map_profile_to_user(&user_info.data).apply_to(&mut user_info.user);
        }
        user_info
    }
}

impl ProviderIdentity for VercelProvider {
    fn id(&self) -> &str {
        VERCEL_ID
    }

    fn name(&self) -> &str {
        VERCEL_NAME
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
    use rustauth_oauth::oauth2::ClientId;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[tokio::test]
    async fn get_user_info_returns_none_for_invalid_json() {
        let server = RawServer::spawn("not-json");
        let provider = VercelProvider {
            client: OAuth2Client::builder(
                VERCEL_ID,
                ProviderOptions {
                    client_id: Some(ClientId::from("vercel-test-client")),
                    ..ProviderOptions::default()
                },
            )
            .authorization_endpoint(VERCEL_AUTHORIZATION_ENDPOINT)
            .expect("authorization endpoint")
            .token_endpoint(VERCEL_TOKEN_ENDPOINT)
            .expect("token endpoint")
            .build()
            .expect("client"),
            get_user_info: None,
            map_profile_to_user: None,
            userinfo_endpoint: server.url(),
            http_client: crate::http::shared_client(),
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
