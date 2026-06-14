//! GitHub social OAuth provider.

use std::collections::BTreeMap;
use std::sync::Arc;

use rustauth_oauth::oauth2::ClientAuthentication;
use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest, ProviderOptions,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use url::Url;

use crate::runtime::ProviderIdentity;

const DEFAULT_SCOPES: &[&str] = &["read:user", "user:email"];
const AUTHORIZATION_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";
const USER_ENDPOINT: &str = "https://api.github.com/user";
const EMAILS_ENDPOINT: &str = "https://api.github.com/user/emails";
const USER_AGENT: &str = "better-auth";

type UserMapper = Arc<dyn Fn(&GitHubProfile) -> OAuth2UserInfo + Send + Sync>;

/// GitHub profile returned by `GET /user`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GitHubProfile {
    #[serde(default)]
    pub login: String,
    #[serde(default, deserialize_with = "deserialize_string_or_number")]
    pub id: String,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub gravatar_id: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
    #[serde(default)]
    pub followers_url: Option<String>,
    #[serde(default)]
    pub following_url: Option<String>,
    #[serde(default)]
    pub gists_url: Option<String>,
    #[serde(default)]
    pub starred_url: Option<String>,
    #[serde(default)]
    pub subscriptions_url: Option<String>,
    #[serde(default)]
    pub organizations_url: Option<String>,
    #[serde(default)]
    pub repos_url: Option<String>,
    #[serde(default)]
    pub events_url: Option<String>,
    #[serde(default)]
    pub received_events_url: Option<String>,
    #[serde(rename = "type", default)]
    pub profile_type: Option<String>,
    #[serde(default)]
    pub site_admin: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub blog: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub hireable: Option<bool>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub twitter_username: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// GitHub email returned by `GET /user/emails`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitHubEmail {
    pub email: String,
    #[serde(default)]
    pub primary: bool,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub visibility: Option<String>,
}

/// Provider-specific user info plus the raw GitHub profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitHubUserInfo {
    pub user: OAuth2UserInfo,
    pub data: GitHubProfile,
}

/// Configuration for GitHub as a Better Auth-compatible social provider.
#[derive(Clone, Default)]
pub struct GitHubOptions {
    pub oauth: ProviderOptions,
    pub map_profile_to_user: Option<UserMapper>,
}

impl From<ProviderOptions> for GitHubOptions {
    fn from(oauth: ProviderOptions) -> Self {
        Self {
            oauth,
            map_profile_to_user: None,
        }
    }
}

/// Inputs required to build the GitHub authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitHubAuthorizationUrlRequest {
    pub state: String,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
}

/// Inputs required to exchange a GitHub authorization code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitHubValidateAuthorizationCodeRequest {
    pub code: String,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
}

/// GitHub OAuth provider.
#[derive(Clone)]
pub struct GitHubProvider {
    client: OAuth2Client,
    map_profile_to_user: Option<UserMapper>,
}

impl GitHubProvider {
    #[deprecated(note = "use advanced::github::github() instead")]
    pub fn new(options: impl Into<GitHubOptions>) -> Result<Self, OAuthError> {
        let options = options.into();
        let disable_default_scope = options.oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder("github", options.oauth)
            .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
            .token_endpoint(TOKEN_ENDPOINT)?
            .authentication(ClientAuthentication::Post);
        if !disable_default_scope {
            builder = builder.default_scopes(DEFAULT_SCOPES.iter().copied());
        }
        Ok(Self {
            client: builder.build()?,
            map_profile_to_user: options.map_profile_to_user,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn provider_options(&self) -> ProviderOptions {
        self.options()
    }

    pub fn create_authorization_url(
        &self,
        input: GitHubAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(input.state, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            url = url.code_verifier(code_verifier);
        }
        if let Some(login_hint) = input.login_hint {
            url = url.login_hint(login_hint);
        }
        url.scopes(input.scopes).build()
    }

    pub fn create_authorization_code_request(
        &self,
        input: GitHubValidateAuthorizationCodeRequest,
    ) -> Result<OAuthFormRequest, OAuthError> {
        let mut exchange = self.client.exchange_code(input.code, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        input: GitHubValidateAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut exchange = self.client.exchange_code(input.code, input.redirect_uri)?;
        if let Some(code_verifier) = input.code_verifier {
            exchange = exchange.code_verifier(code_verifier);
        }
        exchange.send().await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token_value: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.refresh_token(refresh_token_value)?.send().await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<GitHubUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let client = crate::http::shared_client();
        let Some(profile) = fetch_github_profile(&client, access_token).await else {
            return Ok(None);
        };
        let emails = fetch_github_emails(&client, access_token)
            .await
            .unwrap_or_default();

        let mut user_info = map_github_user_info(profile, &emails);
        if let Some(mapper) = &self.map_profile_to_user {
            user_info.user = mapper(&user_info.data);
        }

        Ok(Some(user_info))
    }
}

impl ProviderIdentity for GitHubProvider {
    fn id(&self) -> &str {
        "github"
    }

    fn name(&self) -> &str {
        "GitHub"
    }
}

#[allow(deprecated)]
pub fn github(options: impl Into<GitHubOptions>) -> Result<GitHubProvider, OAuthError> {
    GitHubProvider::new(options)
}

pub fn map_github_user_info(mut profile: GitHubProfile, emails: &[GitHubEmail]) -> GitHubUserInfo {
    if profile.email.is_none() {
        profile.email = emails
            .iter()
            .find(|email| email.primary)
            .or_else(|| emails.first())
            .map(|email| email.email.clone());
    }

    let email_verified = profile
        .email
        .as_deref()
        .and_then(|profile_email| {
            emails
                .iter()
                .find(|email| email.email == profile_email)
                .map(|email| email.verified)
        })
        .unwrap_or(false);

    let name = profile
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&profile.login)
        .to_owned();

    GitHubUserInfo {
        user: OAuth2UserInfo {
            id: profile.id.clone(),
            name: Some(name),
            email: profile.email.clone(),
            image: profile.avatar_url.clone(),
            email_verified,
        },
        data: profile,
    }
}

async fn fetch_github_profile(
    client: &reqwest::Client,
    access_token: &str,
) -> Option<GitHubProfile> {
    client
        .get(USER_ENDPOINT)
        .bearer_auth(access_token)
        .header("user-agent", USER_AGENT)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json::<GitHubProfile>()
        .await
        .ok()
}

async fn fetch_github_emails(
    client: &reqwest::Client,
    access_token: &str,
) -> Option<Vec<GitHubEmail>> {
    client
        .get(EMAILS_ENDPOINT)
        .bearer_auth(access_token)
        .header("user-agent", USER_AGENT)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json::<Vec<GitHubEmail>>()
        .await
        .ok()
}

fn deserialize_string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(Value::String(value)) => value,
        Some(Value::Number(value)) => value.to_string(),
        Some(other) => other.to_string(),
        None => String::new(),
    })
}
