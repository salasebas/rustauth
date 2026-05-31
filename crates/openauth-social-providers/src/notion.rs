//! Notion social OAuth provider.

use std::collections::BTreeMap;

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract, OAuthProviderMetadata,
    ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use url::Url;

pub const NOTION_ID: &str = "notion";
pub const NOTION_NAME: &str = "Notion";
pub const NOTION_AUTHORIZATION_ENDPOINT: &str = "https://api.notion.com/v1/oauth/authorize";
pub const NOTION_TOKEN_ENDPOINT: &str = "https://api.notion.com/v1/oauth/token";
pub const NOTION_USER_INFO_ENDPOINT: &str = "https://api.notion.com/v1/users/me";
pub const NOTION_VERSION: &str = "2022-06-28";

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotionProvider {
    options: ProviderOptions,
    metadata: OAuthProviderMetadata,
}

pub fn notion(options: ProviderOptions) -> NotionProvider {
    NotionProvider::new(options)
}

impl NotionProvider {
    pub fn new(options: ProviderOptions) -> Self {
        Self {
            options,
            metadata: OAuthProviderMetadata::new(NOTION_ID, NOTION_NAME),
        }
    }

    pub fn options(&self) -> &ProviderOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        NOTION_TOKEN_ENDPOINT
    }

    pub fn user_info_endpoint(&self) -> &str {
        NOTION_USER_INFO_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: NotionAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        let mut additional_params = BTreeMap::new();
        additional_params.insert("owner".to_owned(), "user".to_owned());

        create_authorization_url(AuthorizationUrlRequest {
            id: self.id().to_owned(),
            options: self.options.clone(),
            authorization_endpoint: NOTION_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            scopes: self.scopes(request.scopes),
            login_hint: request.login_hint,
            additional_params,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn authorization_code_request(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: code.into(),
            redirect_uri: redirect_uri.into(),
            options: self.options.clone(),
            authentication: ClientAuthentication::Basic,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: NOTION_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.clone(),
                authentication: ClientAuthentication::Basic,
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
            options: self.options.clone(),
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: NOTION_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.clone(),
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(&self, token: &OAuth2Tokens) -> Option<NotionUserInfo> {
        let access_token = token.access_token.as_deref()?;
        let response = crate::http::shared_client()
            .get(NOTION_USER_INFO_ENDPOINT)
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

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = Vec::new();
        scopes.extend(self.options.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl Default for NotionProvider {
    fn default() -> Self {
        Self::new(ProviderOptions::default())
    }
}

impl OAuthProviderContract for NotionProvider {
    fn id(&self) -> &str {
        self.metadata.id()
    }

    fn name(&self) -> &str {
        self.metadata.name()
    }
}
