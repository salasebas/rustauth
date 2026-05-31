//! LINE Login v2.1 social OAuth provider.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openauth_oauth::oauth2::{
    create_authorization_url, get_primary_client_id, refresh_access_token,
    validate_authorization_code, AuthorizationCodeRequest, AuthorizationUrlRequest,
    ClientAuthentication, ClientTokenRequest, OAuth2Tokens, OAuth2UserInfo, OAuthError,
    OAuthProviderContract, ProviderOptions, RefreshAccessTokenRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

pub const LINE_ID: &str = "line";
pub const LINE_NAME: &str = "LINE";
pub const LINE_AUTHORIZATION_ENDPOINT: &str = "https://access.line.me/oauth2/v2.1/authorize";
pub const LINE_TOKEN_ENDPOINT: &str = "https://api.line.me/oauth2/v2.1/token";
pub const LINE_USER_INFO_ENDPOINT: &str = "https://api.line.me/oauth2/v2.1/userinfo";
pub const LINE_VERIFY_ID_TOKEN_ENDPOINT: &str = "https://api.line.me/oauth2/v2.1/verify";

const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];

/// LINE provider configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineOptions {
    pub oauth: ProviderOptions,
}

/// Input used to create a LINE authorization URL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineAuthorizationUrlRequest {
    pub state: String,
    pub redirect_uri: String,
    pub code_verifier: Option<String>,
    pub scopes: Vec<String>,
    pub login_hint: Option<String>,
}

/// LINE ID token payload returned by LINE Login.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LineIdTokenPayload {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email: Option<String>,
    #[serde(default)]
    pub amr: Vec<String>,
    pub nonce: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// LINE UserInfo payload returned by `/userinfo`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LineUserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Raw LINE profile source used to build normalized user info.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LineProfile {
    IdToken(LineIdTokenPayload),
    UserInfo(LineUserInfo),
}

/// LINE user info plus raw profile data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineUserProfile {
    pub user: OAuth2UserInfo,
    pub data: LineProfile,
}

/// LINE OAuth provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineProvider {
    options: LineOptions,
}

pub fn line(options: LineOptions) -> LineProvider {
    LineProvider::new(options)
}

impl LineProvider {
    pub fn new(options: LineOptions) -> Self {
        Self { options }
    }

    pub fn options(&self) -> &LineOptions {
        &self.options
    }

    pub fn create_authorization_url(
        &self,
        request: LineAuthorizationUrlRequest,
    ) -> Result<Url, OAuthError> {
        create_authorization_url(AuthorizationUrlRequest {
            id: LINE_ID.to_owned(),
            options: self.options.oauth.clone(),
            authorization_endpoint: LINE_AUTHORIZATION_ENDPOINT.to_owned(),
            redirect_uri: request.redirect_uri,
            state: request.state,
            code_verifier: request.code_verifier,
            scopes: self.scopes(request.scopes),
            login_hint: request.login_hint,
            ..AuthorizationUrlRequest::default()
        })
    }

    pub async fn validate_authorization_code(
        &self,
        code: impl Into<String>,
        code_verifier: Option<impl Into<String>>,
        redirect_uri: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        validate_authorization_code(ClientTokenRequest {
            token_endpoint: LINE_TOKEN_ENDPOINT.to_owned(),
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

    pub async fn refresh_access_token(
        &self,
        refresh_token: impl Into<String>,
    ) -> Result<OAuth2Tokens, OAuthError> {
        refresh_access_token(ClientTokenRequest {
            token_endpoint: LINE_TOKEN_ENDPOINT.to_owned(),
            request: RefreshAccessTokenRequest {
                refresh_token: refresh_token.into(),
                options: self.options.oauth.clone(),
                authentication: ClientAuthentication::Post,
                ..RefreshAccessTokenRequest::default()
            },
        })
        .await
    }

    pub async fn verify_id_token(
        &self,
        token: &str,
        nonce: Option<&str>,
    ) -> Result<bool, OAuthError> {
        if self.options.oauth.disable_id_token_sign_in {
            return Ok(false);
        }
        let Some(client_id) = get_primary_client_id(&self.options.oauth.client_id) else {
            return Ok(false);
        };

        let mut params = vec![
            ("id_token".to_owned(), token.to_owned()),
            ("client_id".to_owned(), client_id.to_owned()),
        ];
        if let Some(nonce) = nonce {
            params.push(("nonce".to_owned(), nonce.to_owned()));
        }

        let response = match crate::http::shared_client()
            .post(LINE_VERIFY_ID_TOKEN_ENDPOINT)
            .header("content-type", "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(false),
        };
        if !response.status().is_success() {
            return Ok(false);
        }
        let payload = match response.json::<LineIdTokenPayload>().await {
            Ok(payload) => payload,
            Err(_) => return Ok(false),
        };

        Ok(self.validate_id_token_payload(&payload, nonce))
    }

    pub async fn get_user_info(
        &self,
        tokens: &OAuth2Tokens,
    ) -> Result<Option<LineUserProfile>, OAuthError> {
        if let Some(id_token) = tokens.id_token.as_deref() {
            if let Ok(profile) = decode_jwt_payload::<LineIdTokenPayload>(id_token) {
                return Ok(Some(Self::map_id_token_payload(profile)));
            }
        }

        let Some(access_token) = tokens.access_token.as_deref() else {
            return Ok(None);
        };
        let response = match crate::http::shared_client()
            .get(LINE_USER_INFO_ENDPOINT)
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
        let profile = match response.json::<LineUserInfo>().await {
            Ok(profile) => profile,
            Err(_) => return Ok(None),
        };
        Ok(Some(Self::map_user_info(profile)))
    }

    pub fn map_id_token_payload(profile: LineIdTokenPayload) -> LineUserProfile {
        let user = OAuth2UserInfo {
            id: profile.sub.clone(),
            name: profile.name.clone(),
            email: profile.email.clone(),
            image: profile.picture.clone(),
            email_verified: false,
        };
        LineUserProfile {
            user,
            data: LineProfile::IdToken(profile),
        }
    }

    pub fn map_user_info(profile: LineUserInfo) -> LineUserProfile {
        let user = OAuth2UserInfo {
            id: profile.sub.clone(),
            name: profile.name.clone(),
            email: profile.email.clone(),
            image: profile.picture.clone(),
            email_verified: false,
        };
        LineUserProfile {
            user,
            data: LineProfile::UserInfo(profile),
        }
    }

    pub fn validate_id_token_payload(
        &self,
        payload: &LineIdTokenPayload,
        nonce: Option<&str>,
    ) -> bool {
        if self.options.oauth.disable_id_token_sign_in {
            return false;
        }
        let Some(client_id) = get_primary_client_id(&self.options.oauth.client_id) else {
            return false;
        };
        if payload.aud != client_id {
            return false;
        }
        if payload
            .nonce
            .as_deref()
            .is_some_and(|actual| Some(actual) != nonce)
        {
            return false;
        }
        true
    }

    fn scopes(&self, request_scopes: Vec<String>) -> Vec<String> {
        let mut scopes = if self.options.oauth.disable_default_scope {
            Vec::new()
        } else {
            DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        };
        scopes.extend(self.options.oauth.scope.iter().cloned());
        scopes.extend(request_scopes);
        scopes
    }
}

impl Default for LineProvider {
    fn default() -> Self {
        Self::new(LineOptions::default())
    }
}

impl OAuthProviderContract for LineProvider {
    fn id(&self) -> &str {
        LINE_ID
    }

    fn name(&self) -> &str {
        LINE_NAME
    }
}

fn decode_jwt_payload<T>(token: &str) -> Result<T, OAuthError>
where
    T: for<'de> Deserialize<'de>,
{
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| OAuthError::TokenVerification("missing jwt payload".to_owned()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| OAuthError::TokenVerification(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| OAuthError::InvalidResponse(error.to_string()))
}
