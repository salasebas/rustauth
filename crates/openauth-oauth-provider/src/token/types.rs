use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::models::SchemaClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code: Option<String>,
    pub code_verifier: Option<String>,
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
    #[serde(default, deserialize_with = "deserialize_resource")]
    pub resource: Vec<String>,
    pub scope: Option<String>,
}

fn deserialize_resource<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(Value::String(resource)) if !resource.is_empty() => vec![resource],
        Some(Value::String(_)) => return Err(D::Error::custom("resource must not be empty")),
        Some(Value::Array(resources)) => resources
            .into_iter()
            .map(|resource| match resource {
                Value::String(resource) if !resource.is_empty() => Ok(resource),
                _ => Err(D::Error::custom(
                    "resource must be a string or array of strings",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(D::Error::custom(
                "resource must be a string or array of strings",
            ))
        }
        _ => Vec::new(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub expires_at: i64,
    pub token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedAccessToken {
    pub active: bool,
    pub claims: Value,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedIdTokenHint {
    pub client: SchemaClient,
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct RefreshTokenGrantInput<'a> {
    pub client_id: &'a str,
    pub client_secret: Option<&'a str>,
    pub refresh_token: &'a str,
    pub requested_scopes: Vec<String>,
    pub resource: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct AccessTokenInput {
    pub(super) user_id: Option<String>,
    pub(super) session_id: Option<String>,
    pub(super) reference_id: Option<String>,
    pub(super) scopes: Vec<String>,
    pub(super) machine_to_machine: bool,
    pub(super) resource: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct IdTokenInput<'a> {
    pub(super) user_id: &'a str,
    pub(super) session_id: Option<&'a str>,
    pub(super) scopes: &'a [String],
    pub(super) nonce: Option<&'a str>,
    pub(super) auth_time: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuthorizationCodeValue {
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scopes: Vec<String>,
    pub user_id: String,
    pub session_id: String,
    pub reference_id: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub auth_time: Option<OffsetDateTime>,
}
