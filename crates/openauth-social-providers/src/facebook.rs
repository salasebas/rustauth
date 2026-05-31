//! Facebook OAuth provider.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{
    create_authorization_url, get_primary_client_id, refresh_access_token,
    validate_authorization_code, validate_token, AuthorizationCodeRequest, AuthorizationUrlRequest,
    ClientId, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError, OAuthProviderContract,
    ProviderOptions, RefreshAccessTokenRequest, TokenValidationOptions,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const FACEBOOK_PROVIDER_ID: &str = "facebook";
pub const FACEBOOK_PROVIDER_NAME: &str = "Facebook";
pub const FACEBOOK_AUTHORIZATION_ENDPOINT: &str = "https://www.facebook.com/v24.0/dialog/oauth";
pub const FACEBOOK_TOKEN_ENDPOINT: &str = "https://graph.facebook.com/v24.0/oauth/access_token";
pub const FACEBOOK_USER_INFO_ENDPOINT: &str = "https://graph.facebook.com/me";
pub const FACEBOOK_LIMITED_LOGIN_JWKS_ENDPOINT: &str =
    "https://limited.facebook.com/.well-known/oauth/openid/jwks/";
pub const FACEBOOK_LIMITED_LOGIN_ISSUER: &str = "https://www.facebook.com";

const DEFAULT_PROFILE_FIELDS: &[&str] = &["id", "name", "email", "picture"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacebookProfile {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub picture: FacebookPicture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacebookPicture {
    pub data: FacebookPictureData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacebookPictureData {
    pub height: u32,
    pub is_silhouette: bool,
    pub url: String,
    pub width: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacebookOptions {
    pub oauth: ProviderOptions,
    pub fields: Vec<String>,
    pub config_id: Option<String>,
    pub user_info_endpoint: String,
    pub limited_login_jwks_endpoint: String,
}

impl Default for FacebookOptions {
    fn default() -> Self {
        Self {
            oauth: ProviderOptions::default(),
            fields: Vec::new(),
            config_id: None,
            user_info_endpoint: FACEBOOK_USER_INFO_ENDPOINT.to_owned(),
            limited_login_jwks_endpoint: FACEBOOK_LIMITED_LOGIN_JWKS_ENDPOINT.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FacebookUserInfo {
    pub user: OAuth2UserInfo,
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacebookProvider {
    options: FacebookOptions,
}

impl FacebookProvider {
    pub fn new(options: FacebookOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &FacebookOptions {
        &self.options
    }

    pub fn create_authorization_url<I, S>(
        &self,
        state: impl Into<String>,
        scopes: I,
        redirect_uri: impl Into<String>,
        login_hint: Option<&str>,
    ) -> Result<Url, OAuthError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.ensure_required_credentials()?;

        let mut resolved_scopes = Vec::new();
        if !self.options.oauth.disable_default_scope {
            resolved_scopes.extend(["email".to_owned(), "public_profile".to_owned()]);
        }
        resolved_scopes.extend(self.options.oauth.scope.iter().cloned());
        resolved_scopes.extend(scopes.into_iter().map(Into::into));

        let additional_params = self
            .options
            .config_id
            .as_ref()
            .map(|config_id| BTreeMap::from([("config_id".to_owned(), config_id.clone())]))
            .unwrap_or_default();

        create_authorization_url(AuthorizationUrlRequest {
            id: FACEBOOK_PROVIDER_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: FACEBOOK_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: redirect_uri.into(),
            state: state.into(),
            scopes: resolved_scopes,
            login_hint: login_hint.map(str::to_owned),
            additional_params,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: FACEBOOK_TOKEN_ENDPOINT.to_owned(),
            request: AuthorizationCodeRequest {
                code: code.into(),
                redirect_uri: redirect_uri.into(),
                options: self.options.oauth.clone(),
                ..AuthorizationCodeRequest::default()
            },
        })
        .await
    }

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: FACEBOOK_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.oauth.clone(),
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn verify_id_token(&self, token: &str, nonce: Option<&str>) -> bool {
        if self.options.oauth.disable_id_token_sign_in {
            return false;
        }

        if !is_jwt(token) {
            return true;
        }

        let result = validate_token(
            token,
            &self.options.limited_login_jwks_endpoint,
            TokenValidationOptions {
                audience: client_id_audiences(&self.options.oauth.client_id),
                issuer: vec![FACEBOOK_LIMITED_LOGIN_ISSUER.to_owned()],
                ..TokenValidationOptions::default()
            },
        )
        .await;

        let Ok(result) = result else {
            return false;
        };

        match nonce {
            Some(nonce) => result.payload.get("nonce").and_then(Value::as_str) == Some(nonce),
            None => true,
        }
    }

    pub async fn get_user_info(
        &self,
        token: &OAuth2Tokens,
    ) -> Result<Option<FacebookUserInfo>, OAuthError> {
        if let Some(id_token) = token.id_token.as_deref().filter(|token| is_jwt(token)) {
            return self.user_info_from_id_token(id_token);
        }

        let Some(access_token) = token.access_token.as_deref() else {
            return Ok(None);
        };

        let profile = self.fetch_profile(access_token).await?;
        Ok(profile.map(|profile| self.user_info_from_profile(profile)))
    }

    pub fn user_info_from_profile(&self, profile: FacebookProfile) -> FacebookUserInfo {
        let user = OAuth2UserInfo {
            id: profile.id.clone(),
            name: Some(profile.name.clone()),
            email: profile.email.clone(),
            image: Some(profile.picture.data.url.clone()),
            email_verified: profile.email_verified.unwrap_or(false),
        };

        FacebookUserInfo {
            user,
            data: serde_json::to_value(profile).unwrap_or(Value::Null),
        }
    }

    pub fn user_info_from_id_token(
        &self,
        token: &str,
    ) -> Result<Option<FacebookUserInfo>, OAuthError> {
        if !is_jwt(token) {
            return Ok(None);
        }

        let payload = decode_jwt_payload(token)?;
        let Some(subject) = payload.get("sub").and_then(Value::as_str) else {
            return Ok(None);
        };
        let name = payload
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let email = payload
            .get("email")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let picture = payload
            .get("picture")
            .and_then(Value::as_str)
            .map(str::to_owned);

        let user = OAuth2UserInfo {
            id: subject.to_owned(),
            name,
            email,
            image: picture.clone(),
            email_verified: false,
        };

        Ok(Some(FacebookUserInfo {
            user,
            data: payload,
        }))
    }

    pub fn user_info_url(&self) -> Result<Url, OAuthError> {
        let mut url = Url::parse(&self.options.user_info_endpoint)?;
        url.query_pairs_mut()
            .append_pair("fields", &self.profile_fields().join(","));
        Ok(url)
    }

    pub fn profile_fields(&self) -> Vec<String> {
        DEFAULT_PROFILE_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .chain(self.options.fields.iter().cloned())
            .collect()
    }

    async fn fetch_profile(
        &self,
        access_token: &str,
    ) -> Result<Option<FacebookProfile>, OAuthError> {
        let response = crate::http::shared_client()
            .get(self.user_info_url()?)
            .bearer_auth(access_token)
            .send()
            .await;

        let Ok(response) = response else {
            return Ok(None);
        };
        let Ok(response) = response.error_for_status() else {
            return Ok(None);
        };

        match response.json::<FacebookProfile>().await {
            Ok(profile) => Ok(Some(profile)),
            Err(_) => Ok(None),
        }
    }

    fn ensure_required_credentials(&self) -> Result<(), OAuthError> {
        if get_primary_client_id(&self.options.oauth.client_id).is_none() {
            return Err(OAuthError::MissingOption("client_id"));
        }
        if self.options.oauth.client_secret.is_none() {
            return Err(OAuthError::MissingOption("client_secret"));
        }
        Ok(())
    }
}

impl Default for FacebookProvider {
    fn default() -> Self {
        Self::new(FacebookOptions::default())
    }
}

impl OAuthProviderContract for FacebookProvider {
    fn id(&self) -> &str {
        FACEBOOK_PROVIDER_ID
    }

    fn name(&self) -> &str {
        FACEBOOK_PROVIDER_NAME
    }
}

pub fn facebook(options: FacebookOptions) -> FacebookProvider {
    FacebookProvider::new(options)
}

fn client_id_audiences(client_id: &Option<ClientId>) -> Vec<String> {
    match client_id {
        Some(ClientId::Single(value)) if !value.is_empty() => vec![value.clone()],
        Some(ClientId::Multiple(values)) => values
            .iter()
            .filter(|value| !value.is_empty())
            .cloned()
            .collect(),
        _ => Vec::new(),
    }
}

fn is_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

fn decode_jwt_payload(token: &str) -> Result<Value, OAuthError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| OAuthError::InvalidResponse("id token must contain a payload".to_owned()))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| OAuthError::InvalidResponse(error.to_string()))?;
    serde_json::from_slice(&decoded).map_err(|error| OAuthError::InvalidResponse(error.to_string()))
}
