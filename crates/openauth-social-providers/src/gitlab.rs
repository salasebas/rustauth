//! GitLab OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::http::ProviderHttpClient;

pub const GITLAB_ID: &str = "gitlab";
pub const GITLAB_NAME: &str = "Gitlab";
pub const GITLAB_DEFAULT_ISSUER: &str = "https://gitlab.com";
pub const GITLAB_AUTHORIZATION_ENDPOINT: &str = "https://gitlab.com/oauth/authorize";
pub const GITLAB_TOKEN_ENDPOINT: &str = "https://gitlab.com/oauth/token";
pub const GITLAB_USERINFO_ENDPOINT: &str = "https://gitlab.com/api/v4/user";

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
    options: GitlabOptions,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    http_client: ProviderHttpClient,
}

pub fn gitlab(options: GitlabOptions) -> GitlabProvider {
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
    pub fn new(options: GitlabOptions) -> Self {
        let endpoints = issuer_to_endpoints(options.issuer.as_deref());
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

    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    pub fn userinfo_endpoint(&self) -> &str {
        &self.userinfo_endpoint
    }

    pub fn options(&self) -> &GitlabOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        input: GitlabAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            vec!["read_user".to_owned()]
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(input.scopes);

        create_authorization_url(AuthorizationUrlRequest {
            id: GITLAB_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            redirect_uri: input.redirect_uri,
            state: input.state,
            code_verifier: input.code_verifier,
            scopes,
            login_hint: input.login_hint,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.oauth.clone(),
            code_verifier: code_verifier.map(Into::into),
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
            token_endpoint: self.token_endpoint.clone(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                code_verifier: code_verifier.map(Into::into),
                authentication: ClientAuthentication::Post,
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        refresh_access_token_request(RefreshAccessTokenRequest {
            refresh_token: refresh_token.into(),
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Post,
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: self.token_endpoint.clone(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
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

impl OAuthProviderContract for GitlabProvider {
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
