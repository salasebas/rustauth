use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use super::error::OAuthError;

const MAX_TOKEN_EXPIRY_SECONDS: i64 = 10 * 365 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClientId {
    Single(String),
    Multiple(Vec<String>),
}

impl ClientId {
    pub fn primary(&self) -> Option<&str> {
        match self {
            Self::Single(value) if !value.is_empty() => Some(value),
            Self::Single(_) => None,
            Self::Multiple(values) => values
                .first()
                .map(String::as_str)
                .filter(|value| !value.is_empty()),
        }
    }
}

impl From<&str> for ClientId {
    fn from(value: &str) -> Self {
        Self::Single(value.to_owned())
    }
}

impl From<String> for ClientId {
    fn from(value: String) -> Self {
        Self::Single(value)
    }
}

impl From<Vec<String>> for ClientId {
    fn from(value: Vec<String>) -> Self {
        Self::Multiple(value)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderOptions {
    pub client_id: Option<ClientId>,
    pub client_secret: Option<String>,
    pub scope: Vec<String>,
    pub disable_default_scope: bool,
    pub redirect_uri: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub client_key: Option<String>,
    pub disable_id_token_sign_in: bool,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub prompt: Option<String>,
    pub response_mode: Option<String>,
    pub override_user_info_on_sign_in: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuth2Tokens {
    pub token_type: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scopes: Vec<String>,
    pub id_token: Option<String>,
    pub raw: Value,
}

impl Default for OAuth2Tokens {
    fn default() -> Self {
        Self {
            token_type: None,
            access_token: None,
            refresh_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scopes: Vec::new(),
            id_token: None,
            raw: Value::Null,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuth2UserInfo {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
}

pub fn get_primary_client_id(client_id: &Option<ClientId>) -> Option<&str> {
    client_id.as_ref().and_then(ClientId::primary)
}

pub fn get_oauth2_tokens(data: Value) -> Result<OAuth2Tokens, OAuthError> {
    let object = data.as_object().ok_or_else(|| {
        OAuthError::InvalidTokenResponse("token response must be a JSON object".to_owned())
    })?;
    let now = OffsetDateTime::now_utc();
    let access_token = optional_string_field(object, "access_token")?;
    let refresh_token = optional_string_field(object, "refresh_token")?;
    let id_token = optional_string_field(object, "id_token")?;
    if access_token.is_none() && refresh_token.is_none() && id_token.is_none() {
        return Err(OAuthError::InvalidTokenResponse(
            "token response must include access_token, refresh_token, or id_token".to_owned(),
        ));
    }

    Ok(OAuth2Tokens {
        token_type: optional_string_field(object, "token_type")?,
        access_token,
        refresh_token,
        access_token_expires_at: expires_at(object, "expires_in", now)?,
        refresh_token_expires_at: expires_at(object, "refresh_token_expires_in", now)?,
        scopes: scopes_field(object.get("scope"))?,
        id_token,
        raw: data,
    })
}

fn optional_string_field(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<String>, OAuthError> {
    match object.get(key) {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(OAuthError::InvalidTokenResponse(format!(
            "`{key}` must be a string"
        ))),
        None => Ok(None),
    }
}

fn expires_at(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
    now: OffsetDateTime,
) -> Result<Option<OffsetDateTime>, OAuthError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let seconds = value.as_i64().ok_or_else(|| {
        OAuthError::InvalidTokenResponse(format!("`{key}` must be an integer number of seconds"))
    })?;
    if !(0..=MAX_TOKEN_EXPIRY_SECONDS).contains(&seconds) {
        return Err(OAuthError::InvalidTokenResponse(format!(
            "`{key}` must be between 0 and {MAX_TOKEN_EXPIRY_SECONDS} seconds"
        )));
    }
    now.checked_add(Duration::seconds(seconds))
        .ok_or_else(|| OAuthError::InvalidTokenResponse(format!("`{key}` is out of range")))
        .map(Some)
}

fn scopes_field(value: Option<&Value>) -> Result<Vec<String>, OAuthError> {
    match value {
        Some(Value::String(scope)) => Ok(scope.split_whitespace().map(str::to_owned).collect()),
        Some(Value::Array(scopes)) => scopes
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    OAuthError::InvalidTokenResponse(
                        "`scope` array values must be strings".to_owned(),
                    )
                })
            })
            .collect(),
        Some(_) => Err(OAuthError::InvalidTokenResponse(
            "`scope` must be a string or string array".to_owned(),
        )),
        None => Ok(Vec::new()),
    }
}
