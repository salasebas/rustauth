//! Linear social OAuth provider.

use std::collections::BTreeMap;
use std::sync::Arc;

use openauth_oauth::oauth2::{
    authorization_code_request, create_authorization_url, refresh_access_token,
    refresh_access_token_request, validate_authorization_code, AuthorizationCodeRequest,
    AuthorizationUrlRequest, ClientAuthentication, ClientTokenRequest, OAuth2Tokens,
    OAuth2UserInfo, OAuthError, OAuthFormRequest, OAuthProviderContract, ProviderOptions,
    RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

pub const LINEAR_ID: &str = "linear";
pub const LINEAR_NAME: &str = "Linear";
pub const LINEAR_AUTHORIZATION_ENDPOINT: &str = "https://linear.app/oauth/authorize";
pub const LINEAR_TOKEN_ENDPOINT: &str = "https://api.linear.app/oauth/token";
pub const LINEAR_GRAPHQL_ENDPOINT: &str = "https://api.linear.app/graphql";
pub const LINEAR_DEFAULT_SCOPE: &str = "read";

const LINEAR_VIEWER_QUERY: &str = r#"
query {
  viewer {
    id
    name
    email
    avatarUrl
    active
    createdAt
    updatedAt
  }
}
"#;

type UserMapper = Arc<dyn Fn(&LinearUser) -> OAuth2UserInfo + Send + Sync>;

/// Linear-specific OAuth options.
#[derive(Clone, Default)]
pub struct LinearOptions {
    pub oauth: ProviderOptions,
    pub map_profile_to_user: Option<UserMapper>,
}

/// Input used to create a Linear authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinearAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

/// Input used to create or send a Linear authorization-code token request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinearValidateAuthorizationCodeRequest {
    pub code: String,
    pub redirect_uri: String,
}

/// Linear viewer returned by the GraphQL `viewer` query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearUser {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(rename = "avatarUrl")]
    pub avatar_url: Option<String>,
    pub active: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

impl LinearUser {
    pub fn to_user_info(&self) -> OAuth2UserInfo {
        OAuth2UserInfo {
            id: self.id.clone(),
            name: Some(self.name.clone()),
            email: Some(self.email.clone()),
            image: self.avatar_url.clone(),
            email_verified: false,
        }
    }
}

/// Linear GraphQL profile response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearProfile {
    pub data: Option<LinearProfileData>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearProfileData {
    pub viewer: Option<LinearUser>,
}

/// User info plus raw Linear profile data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearUserInfo {
    pub user: OAuth2UserInfo,
    pub data: LinearUser,
}

/// Linear OAuth provider.
#[derive(Clone)]
pub struct LinearProvider {
    options: LinearOptions,
    http_client: reqwest::Client,
}

pub fn linear(options: LinearOptions) -> LinearProvider {
    LinearProvider::new(options)
}

impl LinearProvider {
    pub fn new(options: LinearOptions) -> Self {
        Self {
            options,
            http_client: crate::http::shared_client(),
        }
    }

    pub fn id(&self) -> &str {
        LINEAR_ID
    }

    pub fn name(&self) -> &str {
        LINEAR_NAME
    }

    pub fn options(&self) -> &LinearOptions {
        &self.options
    }

    pub fn token_endpoint(&self) -> &str {
        LINEAR_TOKEN_ENDPOINT
    }

    pub fn graphql_endpoint(&self) -> &str {
        LINEAR_GRAPHQL_ENDPOINT
    }

    pub fn create_authorization_url(
        &self,
        request: LinearAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: LINEAR_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: LINEAR_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            scopes: self.scopes(request.scopes),
            login_hint: request.login_hint,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub fn authorization_code_request(
        &self,
        request: LinearValidateAuthorizationCodeRequest,
    ) -> Result<OAuthFormRequest, OAuthError> {
        authorization_code_request(AuthorizationCodeRequest {
            code: request.code,
            redirect_uri: request.redirect_uri,
            options: self.options.oauth.clone(),
            authentication: ClientAuthentication::Post,
            ..AuthorizationCodeRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        request: LinearValidateAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: LINEAR_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: request.code,
                redirect_uri: request.redirect_uri,
                options: self.options.oauth.clone(),
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
            extra_params: self.refresh_extra_params(),
            ..RefreshAccessTokenRequest::default()
        })
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: LINEAR_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                extra_params: self.refresh_extra_params(),
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<LinearUserInfo>, OAuthError> {
        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match self
            .http_client
            .post(LINEAR_GRAPHQL_ENDPOINT)
            .header("content-type", "application/json")
            .bearer_auth(access_token)
            .json(&json!({ "query": LINEAR_VIEWER_QUERY }))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };

        if !response.status().is_success() {
            return Ok(None);
        }

        let profile = match response.json::<LinearProfile>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        let Some(user) = profile.data.and_then(|data| data.viewer) else {
            return Ok(None);
        };

        Ok(Some(self.user_info_from_profile(user)))
    }

    pub fn user_info_from_profile(&self, profile: LinearUser) -> LinearUserInfo {
        let user = self
            .options
            .map_profile_to_user
            .as_ref()
            .map(|mapper| mapper(&profile))
            .unwrap_or_else(|| profile.to_user_info());

        LinearUserInfo {
            user,
            data: profile,
        }
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            vec![LINEAR_DEFAULT_SCOPE.to_owned()]
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }

    fn refresh_extra_params(&self) -> BTreeMap<String, String> {
        self.options
            .oauth
            .client_key
            .as_ref()
            .map(|client_key| BTreeMap::from([("client_key".to_owned(), client_key.clone())]))
            .unwrap_or_default()
    }
}

impl OAuthProviderContract for LinearProvider {
    fn id(&self) -> &str {
        self.id()
    }

    fn name(&self) -> &str {
        self.name()
    }
}
