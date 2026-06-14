//! Linear social OAuth provider.

use std::sync::Arc;

use rustauth_oauth::oauth2::{
    OAuth2Client, OAuth2Tokens, OAuth2UserInfo, OAuthError, ProviderOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::runtime::ProviderIdentity;

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
    client: OAuth2Client,
    map_profile_to_user: Option<UserMapper>,
    http_client: reqwest::Client,
}

#[allow(deprecated)]
pub fn linear(options: LinearOptions) -> Result<LinearProvider, OAuthError> {
    LinearProvider::new(options)
}

impl LinearProvider {
    #[deprecated(note = "use advanced::linear::linear() instead")]
    pub fn new(options: LinearOptions) -> Result<Self, OAuthError> {
        let LinearOptions {
            oauth,
            map_profile_to_user,
        } = options;
        let disable_default_scope = oauth.disable_default_scope;
        let mut builder = OAuth2Client::builder(LINEAR_ID, oauth)
            .authorization_endpoint(LINEAR_AUTHORIZATION_ENDPOINT)?
            .token_endpoint(LINEAR_TOKEN_ENDPOINT)?;
        if !disable_default_scope {
            builder = builder.default_scope(LINEAR_DEFAULT_SCOPE);
        }
        Ok(Self {
            client: builder.build()?,
            map_profile_to_user,
            http_client: crate::http::shared_client(),
        })
    }

    pub fn options(&self) -> ProviderOptions {
        self.client.options().clone()
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
        let mut url = self
            .client
            .authorization_url(request.state, request.redirect_uri)?;
        if let Some(login_hint) = request.login_hint {
            url = url.login_hint(login_hint);
        }
        url.scopes(request.scopes).build()
    }

    pub async fn validate_authorization_code(
        &self,
        request: LinearValidateAuthorizationCodeRequest,
    ) -> Result<OAuth2Tokens, OAuthError> {
        self.client
            .exchange_code(request.code, request.redirect_uri)?
            .send()
            .await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        let mut refresh = self.client.refresh_token(refresh_token)?;
        if let Some(client_key) = self.client.options().client_key.clone() {
            refresh = refresh.extra_param("client_key", client_key);
        }
        refresh.send().await
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
            .map_profile_to_user
            .as_ref()
            .map(|mapper| mapper(&profile))
            .unwrap_or_else(|| profile.to_user_info());

        LinearUserInfo {
            user,
            data: profile,
        }
    }
}

impl ProviderIdentity for LinearProvider {
    fn id(&self) -> &str {
        LINEAR_ID
    }

    fn name(&self) -> &str {
        LINEAR_NAME
    }
}
