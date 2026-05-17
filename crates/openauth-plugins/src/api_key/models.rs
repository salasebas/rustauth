use openauth_core::db::{DbRecord, DbValue};
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::options::ApiKeyPermissions;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyRecord {
    pub id: String,
    pub config_id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    pub key: String,
    pub reference_id: String,
    pub refill_interval: Option<i64>,
    pub refill_amount: Option<i64>,
    pub last_refill_at: Option<OffsetDateTime>,
    pub enabled: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub request_count: i64,
    pub remaining: Option<i64>,
    pub last_request: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub metadata: Option<Value>,
    pub permissions: Option<ApiKeyPermissions>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyPublicRecord {
    pub id: String,
    pub config_id: String,
    pub name: Option<String>,
    pub start: Option<String>,
    pub prefix: Option<String>,
    pub reference_id: String,
    pub refill_interval: Option<i64>,
    pub refill_amount: Option<i64>,
    pub last_refill_at: Option<OffsetDateTime>,
    pub enabled: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub request_count: i64,
    pub remaining: Option<i64>,
    pub last_request: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub metadata: Option<Value>,
    pub permissions: Option<ApiKeyPermissions>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyCreateRecord {
    #[serde(flatten)]
    pub record: ApiKeyPublicRecord,
    pub key: String,
}

impl ApiKeyRecord {
    pub fn public(&self) -> ApiKeyPublicRecord {
        ApiKeyPublicRecord {
            id: self.id.clone(),
            config_id: self.config_id.clone(),
            name: self.name.clone(),
            start: self.start.clone(),
            prefix: self.prefix.clone(),
            reference_id: self.reference_id.clone(),
            refill_interval: self.refill_interval,
            refill_amount: self.refill_amount,
            last_refill_at: self.last_refill_at,
            enabled: self.enabled,
            rate_limit_enabled: self.rate_limit_enabled,
            rate_limit_time_window: self.rate_limit_time_window,
            rate_limit_max: self.rate_limit_max,
            request_count: self.request_count,
            remaining: self.remaining,
            last_request: self.last_request,
            expires_at: self.expires_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
            metadata: normalize_metadata(self.metadata.clone()),
            permissions: self.permissions.clone(),
        }
    }

    pub fn to_record(&self) -> DbRecord {
        DbRecord::from([
            ("id".to_owned(), DbValue::String(self.id.clone())),
            (
                "config_id".to_owned(),
                DbValue::String(self.config_id.clone()),
            ),
            ("name".to_owned(), optional_string(self.name.clone())),
            ("start".to_owned(), optional_string(self.start.clone())),
            ("prefix".to_owned(), optional_string(self.prefix.clone())),
            ("key".to_owned(), DbValue::String(self.key.clone())),
            (
                "reference_id".to_owned(),
                DbValue::String(self.reference_id.clone()),
            ),
            (
                "refill_interval".to_owned(),
                optional_number(self.refill_interval),
            ),
            (
                "refill_amount".to_owned(),
                optional_number(self.refill_amount),
            ),
            (
                "last_refill_at".to_owned(),
                optional_timestamp(self.last_refill_at),
            ),
            ("enabled".to_owned(), DbValue::Boolean(self.enabled)),
            (
                "rate_limit_enabled".to_owned(),
                DbValue::Boolean(self.rate_limit_enabled),
            ),
            (
                "rate_limit_time_window".to_owned(),
                optional_number(self.rate_limit_time_window),
            ),
            (
                "rate_limit_max".to_owned(),
                optional_number(self.rate_limit_max),
            ),
            (
                "request_count".to_owned(),
                DbValue::Number(self.request_count),
            ),
            ("remaining".to_owned(), optional_number(self.remaining)),
            (
                "last_request".to_owned(),
                optional_timestamp(self.last_request),
            ),
            ("expires_at".to_owned(), optional_timestamp(self.expires_at)),
            ("created_at".to_owned(), DbValue::Timestamp(self.created_at)),
            ("updated_at".to_owned(), DbValue::Timestamp(self.updated_at)),
            (
                "metadata".to_owned(),
                self.metadata
                    .clone()
                    .map(DbValue::Json)
                    .unwrap_or(DbValue::Null),
            ),
            (
                "permissions".to_owned(),
                self.permissions
                    .as_ref()
                    .and_then(|permissions| serde_json::to_value(permissions).ok())
                    .map(DbValue::Json)
                    .unwrap_or(DbValue::Null),
            ),
        ])
    }
}

pub(crate) const API_KEY_FIELDS: [&str; 22] = [
    "id",
    "config_id",
    "name",
    "start",
    "prefix",
    "key",
    "reference_id",
    "refill_interval",
    "refill_amount",
    "last_refill_at",
    "enabled",
    "rate_limit_enabled",
    "rate_limit_time_window",
    "rate_limit_max",
    "request_count",
    "remaining",
    "last_request",
    "expires_at",
    "created_at",
    "updated_at",
    "metadata",
    "permissions",
];

pub(crate) fn record_from_db(record: DbRecord) -> Result<ApiKeyRecord, OpenAuthError> {
    Ok(ApiKeyRecord {
        id: required_string(&record, "id")?.to_owned(),
        config_id: required_string(&record, "config_id")?.to_owned(),
        name: optional_string_field(&record, "name")?,
        start: optional_string_field(&record, "start")?,
        prefix: optional_string_field(&record, "prefix")?,
        key: required_string(&record, "key")?.to_owned(),
        reference_id: required_string(&record, "reference_id")?.to_owned(),
        refill_interval: optional_number_field(&record, "refill_interval")?,
        refill_amount: optional_number_field(&record, "refill_amount")?,
        last_refill_at: optional_timestamp_field(&record, "last_refill_at")?,
        enabled: optional_bool_field(&record, "enabled")?.unwrap_or(true),
        rate_limit_enabled: optional_bool_field(&record, "rate_limit_enabled")?.unwrap_or(true),
        rate_limit_time_window: optional_number_field(&record, "rate_limit_time_window")?,
        rate_limit_max: optional_number_field(&record, "rate_limit_max")?,
        request_count: optional_number_field(&record, "request_count")?.unwrap_or(0),
        remaining: optional_number_field(&record, "remaining")?,
        last_request: optional_timestamp_field(&record, "last_request")?,
        expires_at: optional_timestamp_field(&record, "expires_at")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
        metadata: optional_json_field(&record, "metadata")?,
        permissions: optional_json_field(&record, "permissions")?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| OpenAuthError::Adapter(error.to_string()))?,
    })
}

fn normalize_metadata(metadata: Option<Value>) -> Option<Value> {
    match metadata {
        Some(Value::String(value)) => serde_json::from_str(&value).ok(),
        other => other,
    }
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn optional_number(value: Option<i64>) -> DbValue {
    value.map(DbValue::Number).unwrap_or(DbValue::Null)
}

fn optional_timestamp(value: Option<OffsetDateTime>) -> DbValue {
    value.map(DbValue::Timestamp).unwrap_or(DbValue::Null)
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(DbValue::Null) | None => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` is missing"
        ))),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` has invalid type"
        ))),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(DbValue::Null) | None => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` is missing"
        ))),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` has invalid type"
        ))),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.clone())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` has invalid type"
        ))),
    }
}

fn optional_number_field(record: &DbRecord, field: &str) -> Result<Option<i64>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Number(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` has invalid type"
        ))),
    }
}

fn optional_bool_field(record: &DbRecord, field: &str) -> Result<Option<bool>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` has invalid type"
        ))),
    }
}

fn optional_timestamp_field(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` has invalid type"
        ))),
    }
}

fn optional_json_field(record: &DbRecord, field: &str) -> Result<Option<Value>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Json(value)) => Ok(Some(value.clone())),
        Some(DbValue::String(value)) => serde_json::from_str(value)
            .map(Some)
            .map_err(|error| OpenAuthError::Adapter(error.to_string())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(OpenAuthError::Adapter(format!(
            "api key field `{field}` has invalid type"
        ))),
    }
}
