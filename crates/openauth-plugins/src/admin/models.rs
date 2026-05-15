use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use openauth_core::db::{DbRecord, DbValue};
use openauth_core::error::OpenAuthError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub role: Option<String>,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub ban_expires: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSession {
    pub id: String,
    pub user_id: String,
    pub expires_at: OffsetDateTime,
    pub token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub impersonated_by: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdBody {
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRoleBody {
    pub user_id: String,
    pub role: RoleInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    pub fn roles(&self) -> Vec<String> {
        match self {
            Self::One(role) => vec![role.clone()],
            Self::Many(roles) => roles.clone(),
        }
    }

    pub fn joined(&self) -> String {
        self.roles().join(",")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserBody {
    pub email: String,
    pub password: Option<String>,
    pub name: String,
    pub role: Option<RoleInput>,
    #[serde(default)]
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserBody {
    pub user_id: String,
    pub data: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BanUserBody {
    pub user_id: String,
    pub ban_reason: Option<String>,
    pub ban_expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSessionBody {
    pub session_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordBody {
    pub user_id: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HasPermissionBody {
    pub user_id: Option<String>,
    pub role: Option<String>,
    #[serde(default, alias = "permission")]
    pub permissions: crate::admin::PermissionMap,
}

pub(crate) fn admin_user_from_record(record: DbRecord) -> Result<AdminUser, OpenAuthError> {
    Ok(AdminUser {
        id: string(&record, "id")?.to_owned(),
        name: string(&record, "name")?.to_owned(),
        email: string(&record, "email")?.to_owned(),
        email_verified: bool_field(&record, "email_verified")?,
        image: optional_string(&record, "image")?,
        created_at: timestamp(&record, "created_at")?,
        updated_at: timestamp(&record, "updated_at")?,
        role: optional_string(&record, "role")?,
        banned: optional_bool(&record, "banned")?.unwrap_or(false),
        ban_reason: optional_string(&record, "ban_reason")?,
        ban_expires: optional_timestamp(&record, "ban_expires")?,
    })
}

pub(crate) fn admin_session_from_record(record: DbRecord) -> Result<AdminSession, OpenAuthError> {
    Ok(AdminSession {
        id: string(&record, "id")?.to_owned(),
        user_id: string(&record, "user_id")?.to_owned(),
        expires_at: timestamp(&record, "expires_at")?,
        token: string(&record, "token")?.to_owned(),
        ip_address: optional_string(&record, "ip_address")?,
        user_agent: optional_string(&record, "user_agent")?,
        created_at: timestamp(&record, "created_at")?,
        updated_at: timestamp(&record, "updated_at")?,
        impersonated_by: optional_string(&record, "impersonated_by")?,
    })
}

fn string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing string field `{field}`"
        ))),
    }
}

fn bool_field(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing boolean field `{field}`"
        ))),
    }
}

fn timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing timestamp field `{field}`"
        ))),
    }
}

fn optional_string(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.clone())),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(OpenAuthError::Adapter(format!(
            "invalid string field `{field}`"
        ))),
    }
}

fn optional_bool(record: &DbRecord, field: &str) -> Result<Option<bool>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(OpenAuthError::Adapter(format!(
            "invalid boolean field `{field}`"
        ))),
    }
}

fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(OpenAuthError::Adapter(format!(
            "invalid timestamp field `{field}`"
        ))),
    }
}
