use std::collections::BTreeMap;

use rustauth_core::db::{DbRecord, DbValue};
use rustauth_core::error::RustAuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: OffsetDateTime,
    pub updated_at: Option<OffsetDateTime>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub id: String,
    pub organization_id: String,
    pub user_id: String,
    pub role: String,
    pub created_at: OffsetDateTime,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Rejected,
    Canceled,
}

impl InvitationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Canceled => "canceled",
        }
    }
}

impl TryFrom<&str> for InvitationStatus {
    type Error = RustAuthError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "canceled" => Ok(Self::Canceled),
            _ => Err(RustAuthError::Adapter(format!(
                "invalid invitation status `{value}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invitation {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub status: InvitationStatus,
    pub team_id: Option<String>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub inviter_id: String,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    pub id: String,
    pub name: String,
    pub organization_id: String,
    pub created_at: OffsetDateTime,
    pub updated_at: Option<OffsetDateTime>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TeamMember {
    pub id: String,
    pub team_id: String,
    pub user_id: String,
    pub created_at: OffsetDateTime,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationRoleRecord {
    pub id: String,
    pub organization_id: String,
    pub role: String,
    pub permission: serde_json::Value,
    pub created_at: OffsetDateTime,
    pub updated_at: Option<OffsetDateTime>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub additional_fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FullOrganization {
    #[serde(flatten)]
    pub organization: Organization,
    pub members: Vec<Member>,
    pub invitations: Vec<Invitation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub teams: Vec<Team>,
}

pub(crate) fn required_string(record: &DbRecord, field: &str) -> Result<String, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value.clone()),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

pub(crate) fn optional_string(
    record: &DbRecord,
    field: &str,
) -> Result<Option<String>, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.clone())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

pub(crate) fn required_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<OffsetDateTime, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

pub(crate) fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

pub(crate) fn optional_json(
    record: &DbRecord,
    field: &str,
) -> Result<Option<serde_json::Value>, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Json(value)) => Ok(Some(value.clone())),
        Some(DbValue::String(value)) => serde_json::from_str(value)
            .map(Some)
            .map_err(|error| RustAuthError::Adapter(error.to_string())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "json, string, or null")),
    }
}

fn missing_field(field: &str) -> RustAuthError {
    RustAuthError::Adapter(format!("record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> RustAuthError {
    RustAuthError::Adapter(format!("record field `{field}` must be {expected}"))
}
