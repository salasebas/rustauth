use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Core user record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default, alias = "displayUsername")]
    pub display_username: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Linked credential, OAuth, or social provider account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub provider_id: String,
    pub account_id: String,
    pub user_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub access_token_expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub refresh_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
    pub password: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Persisted user session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Verification token or value used by flows such as email verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

/// Database-backed rate limit bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    pub key: String,
    pub count: u64,
    pub last_request: i64,
}
