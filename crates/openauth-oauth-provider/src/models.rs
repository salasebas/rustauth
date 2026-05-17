use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

/// Stored OAuth client row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SchemaClient {
    pub id: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_secret_expires_at: Option<OffsetDateTime>,
    pub disabled: Option<bool>,
    pub skip_consent: Option<bool>,
    pub enable_end_session: Option<bool>,
    pub subject_type: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub user_id: Option<String>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
    pub name: Option<String>,
    pub uri: Option<String>,
    pub icon: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub tos: Option<String>,
    pub policy: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub software_statement: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub public: Option<bool>,
    #[serde(rename = "type")]
    pub client_type: Option<String>,
    pub require_pkce: Option<bool>,
    pub reference_id: Option<String>,
    pub metadata: Option<Value>,
}

/// Stored OAuth refresh token row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthRefreshToken {
    pub id: String,
    pub token: String,
    pub client_id: String,
    pub session_id: Option<String>,
    pub user_id: String,
    pub reference_id: Option<String>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub revoked: Option<OffsetDateTime>,
    pub auth_time: Option<OffsetDateTime>,
    pub scopes: Vec<String>,
}

/// Stored opaque OAuth access token row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthAccessToken {
    pub id: String,
    pub token: String,
    pub client_id: String,
    pub session_id: Option<String>,
    pub user_id: Option<String>,
    pub reference_id: Option<String>,
    pub refresh_id: Option<String>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub scopes: Vec<String>,
}

/// Stored OAuth consent row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OAuthConsent {
    pub id: String,
    pub client_id: String,
    pub user_id: Option<String>,
    pub reference_id: Option<String>,
    pub scopes: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
