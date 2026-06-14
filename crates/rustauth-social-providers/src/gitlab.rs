//! GitLab OAuth provider.

use std::collections::BTreeMap;

use rustauth_oauth::oauth2::ClientAuthentication;
use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::http::ProviderHttpClient;
use crate::runtime::ProviderIdentity;

pub const GITLAB_ID: &str = "gitlab";
pub const GITLAB_NAME: &str = "Gitlab";
pub const GITLAB_DEFAULT_ISSUER: &str = "https://gitlab.com";
pub const GITLAB_AUTHORIZATION_ENDPOINT: &str = "https://gitlab.com/oauth/authorize";
pub const GITLAB_TOKEN_ENDPOINT: &str = "https://gitlab.com/oauth/token";
pub const GITLAB_USERINFO_ENDPOINT: &str = "https://gitlab.com/api/v4/user";
const DEFAULT_SCOPE: &str = "read_user";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitlabOptions {
    pub oauth: ProviderOptions,
    pub issuer: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitlabAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitlabProfile {
    pub id: u64,
    pub username: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub state: Option<String>,
    pub avatar_url: Option<String>,
    pub web_url: Option<String>,
    pub created_at: Option<String>,
    pub bio: Option<String>,
    pub location: Option<String>,
    pub public_email: Option<String>,
    pub skype: Option<String>,
    pub linkedin: Option<String>,
    pub twitter: Option<String>,
    pub website_url: Option<String>,
    pub organization: Option<String>,
    pub job_title: Option<String>,
    pub pronouns: Option<String>,
    pub bot: Option<bool>,
    pub work_information: Option<String>,
    pub followers: Option<u64>,
    pub following: Option<u64>,
    pub local_time: Option<String>,
    pub last_sign_in_at: Option<String>,
    pub confirmed_at: Option<String>,
    pub theme_id: Option<u64>,
    pub last_activity_on: Option<String>,
    pub color_scheme_id: Option<u64>,
    pub projects_limit: Option<u64>,
    pub current_sign_in_at: Option<String>,
    pub identities: Vec<GitlabIdentity>,
    pub can_create_group: Option<bool>,
    pub can_create_project: Option<bool>,
    pub two_factor_enabled: Option<bool>,
    pub external: Option<bool>,
    pub private_profile: Option<bool>,
    pub commit_email: Option<String>,
    pub shared_runners_minutes_limit: Option<u64>,
    pub extra_shared_runners_minutes_limit: Option<u64>,
    pub email_verified: Option<bool>,
    pub locked: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitlabIdentity {
    pub provider: String,
    pub extern_uid: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitlabUserInfo {
    pub user: OAuth2UserInfo,
    pub data: GitlabProfile,
}

#[derive(Debug, Clone)]
pub struct GitlabProvider {
    client: OAuth2Client,
    issuer: Option<String>,
    userinfo_endpoint: String,
    http_client: ProviderHttpClient,
}

#[allow(deprecated)]
pub fn gitlab(options: GitlabOptions) -> Result<GitlabProvider, OAuthError> {
    GitlabProvider::new(options)
}

impl GitlabProfile {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.id.to_string(),
            name: Some(
                self.name
                    .clone()
                    .or_else(|| self.username.clone())
                    .unwrap_or_default(),
            ),
            email: self.email.clone(),
            image: self.avatar_url.clone(),
            email_verified: self.email_verified.unwrap_or(false),
        }
    }
}

impl GitlabProvider {
    #[deprecated(note = "use advanced::gitlab::gitlab() instead")]
    pub fn new(options: GitlabOptions) -> Result<Self, OAuthError> {
        let issuer = options.issuer.clone();
        let endpoints = issuer_to_endpoints(issuer.as_deref());
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder(GITLAB_ID, options.oauth)
            .authorization_endpoint(&endpoints.authorization)?
            .token_endpoint(&endpoints.token)?
            .authentication(ClientAuthentication::Post);
        if !disable_default_scope {
            builder = builder.default_scope(DEFAULT_SCOPE);
        }
        Ok(Self {
            client: builder.build()?,
            issuer,
            userinfo_endpoint: endpoints.userinfo,
            http_client: ProviderHttpClient::shared(),
        })
    }

    /// Overrides the HTTP client used for userinfo requests. Use
    /// [`ProviderHttpClient::permissive`] in tests to reach local fixtures.
    pub fn with_http_client(mut self, http_client: ProviderHttpClient) -> Self {
        self.http_client = http_client;
        self
    }

    pub fn authorization_endpoint(&self) -> &str {
        self.client.authorization_endpoint().as_str()
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn userinfo_endpoint(&self) -> &str {
        &self.userinfo_endpoint
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn gitlab_options(&self) -> GitlabOptions {
        GitlabOptions {
            oauth: self.options(),
            issuer: self.issuer.clone(),
        }
    }

    pub fn create_authorization_url(
        &self,
        input: GitlabAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(input.state, input.redirect_uri)?
            .scopes(input.scopes);
        if let Some(code_verifier) = input.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        if let Some(login_hint) = input.login_hint {
            url = url.login_hint(login_hint);
        }
        url.build()
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        let mut exchange = self.client.exchange_code(code, redirect_uri)?;
        if let Some(code_verifier) = code_verifier {
            exchange = exchange.code_verifier(code_verifier);
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
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.send().await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .refresh_token(refresh_token)?
            .into_form_request()
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token)?.send().await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<GitlabUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let response = match self
            .http_client
            .get(&self.userinfo_endpoint)?
            .header("authorization", format!("Bearer {access_token}"))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };

        if !response.status().is_success() {
            return Ok(None);
        }

        let profile = match response.json::<GitlabProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };

        if profile.state.as_deref() != Some("active") || profile.locked.unwrap_or(false) {
            return Ok(None);
        }

        Ok(Some(GitlabUserInfo {
            user: profile.to_user_info(),
            data: profile,
        }))
    }
}

impl ProviderIdentity for GitlabProvider {
    fn id(&self) -> &str {
        GITLAB_ID
    }

    fn name(&self) -> &str {
        GITLAB_NAME
    }
}

struct GitlabEndpoints {
    authorization: String,
    token: String,
    userinfo: String,
}

fn issuer_to_endpoints(issuer: Option<&str>) -> GitlabEndpoints {
    let base_url = issuer.unwrap_or(GITLAB_DEFAULT_ISSUER);
    GitlabEndpoints {
        authorization: clean_double_slashes(&format!("{base_url}/oauth/authorize")),
        token: clean_double_slashes(&format!("{base_url}/oauth/token")),
        userinfo: clean_double_slashes(&format!("{base_url}/api/v4/user")),
    }
}

fn clean_double_slashes(input: &str) -> String {
    input
        .split("://")
        .map(collapse_slashes)
        .collect::<Vec<_>>()
        .join("://")
}

fn collapse_slashes(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut last_was_slash = false;
    for ch in input.chars() {
        if ch == '/' {
            if !last_was_slash {
                output.push(ch);
            }
            last_was_slash = true;
        } else {
            output.push(ch);
            last_was_slash = false;
        }
    }
    output
}
