//! Notion social OAuth provider.

use rustauth_oauth::oauth2::{
    ClientAuthentication, OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthFormRequest,
    ProviderOptions,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::runtime::ProviderIdentity;

const AUTHORIZATION_ENDPOINT: &str = "https://api.notion.com/v1/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://api.notion.com/v1/oauth/token";
const USER_INFO_ENDPOINT: &str = "https://api.notion.com/v1/users/me";
const NOTION_VERSION: &str = "2022-06-28";

pub const NOTION_ID: &str = "notion";
pub const NOTION_NAME: &str = "Notion";
pub const NOTION_AUTHORIZATION_ENDPOINT: &str = AUTHORIZATION_ENDPOINT;
pub const NOTION_TOKEN_ENDPOINT: &str = TOKEN_ENDPOINT;
pub const NOTION_USER_INFO_ENDPOINT: &str = USER_INFO_ENDPOINT;

/// Input used to create a Notion authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotionAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

/// Notion person-specific profile data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotionPerson {
    pub email: Option<String>,
}

/// Notion user profile payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotionProfile {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub person: Option<NotionPerson>,
}

/// Notion nested OAuth owner user payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotionOwnerUser {
    pub user: NotionProfile,
}

/// Notion `bot` payload returned by `GET /v1/users/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotionOwner {
    pub owner: NotionOwnerUser,
}

/// Notion user info response returned by `GET /v1/users/me`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotionUserInfoResponse {
    pub bot: NotionOwner,
}

/// User info plus raw Notion profile data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotionUserInfo {
    pub user: OAuth2UserInfo,
    pub data: NotionProfile,
}

/// Notion OAuth provider.
#[derive(Debug, Clone)]
pub struct NotionProvider {
    client: OAuth2Client,
}

#[allow(deprecated)]
pub fn notion(options: ProviderOptions) -> Result<NotionProvider, OAuthError> {
    NotionProvider::new(options)
}

impl NotionProvider {
    #[deprecated(note = "use advanced::notion::notion() instead")]
    pub fn new(options: ProviderOptions) -> Result<Self, OAuthError> {
        Ok(Self {
            client: OAuth2Client::builder("notion", options)
                .authorization_endpoint(AUTHORIZATION_ENDPOINT)?
                .token_endpoint(TOKEN_ENDPOINT)?
                .authentication(ClientAuthentication::Basic)
                .build()?,
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
    }

    pub fn token_endpoint(&self) -> &str {
        self.client.token_endpoint().as_str()
    }

    pub fn user_info_endpoint(&self) -> &str {
        USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: NotionAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?
            .scopes(request.scopes)
            .param("owner", "user");
        if let Some(login_hint) = request.login_hint {
            url = url.login_hint(login_hint);
        }
        url.build()
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .exchange_code(code, redirect_uri)?
            .into_form_request()
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client.exchange_code(code, redirect_uri)?.send().await
    }

    pub fn refresh_access_token_request(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        self.client
            .refresh_token(refresh_token)?
            .authentication(ClientAuthentication::Post)
            .into_form_request()
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client
            .refresh_token(refresh_token)?
            .authentication(ClientAuthentication::Post)
            .send()
            .await
    }

    pub async fn get_user_info(&self, token: &OAuth2Tokens) -> Option<NotionUserInfo> {
        let access_token = token.access_token.as_deref()?;
        let response = crate::http::shared_client()
            .get(USER_INFO_ENDPOINT)
            .bearer_auth(access_token)
            .header("Notion-Version", NOTION_VERSION)
            .send()
            .await
            .ok()?
            .error_for_status()
            .ok()?
            .json::<NotionUserInfoResponse>()
            .await
            .ok()?;

        Self::user_info_from_response(response)
    }

    pub fn user_info_from_response(response: NotionUserInfoResponse) -> Option<NotionUserInfo> {
        Some(Self::user_info_from_profile(response.bot.owner.user))
    }

    pub fn user_info_from_profile(profile: NotionProfile) -> NotionUserInfo {
        let user = OAuth2UserInfo {
            id: profile.id.clone(),
            name: Some(profile.name.clone().unwrap_or_default()),
            email: profile
                .person
                .as_ref()
                .and_then(|person| person.email.clone()),
            image: profile.avatar_url.clone(),
            email_verified: false,
        };

        NotionUserInfo {
            user,
            data: profile,
        }
    }

    pub fn id(&self) -> &str {
        NOTION_ID
    }

    pub fn name(&self) -> &str {
        NOTION_NAME
    }
}

impl ProviderIdentity for NotionProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}
