use time::OffsetDateTime;

use crate::db::{Account, DbRecord, DbValue, User};
use crate::error::OpenAuthError;

pub(super) const USER_FIELDS: [&str; 7] = [
    "id",
    "name",
    "email",
    "email_verified",
    "image",
    "created_at",
    "updated_at",
];

pub(super) const USER_FIELDS_WITH_USERNAME: [&str; 9] = [
    "id",
    "name",
    "email",
    "email_verified",
    "image",
    "username",
    "display_username",
    "created_at",
    "updated_at",
];

pub(super) const ACCOUNT_FIELDS: [&str; 13] = [
    "id",
    "provider_id",
    "account_id",
    "user_id",
    "access_token",
    "refresh_token",
    "id_token",
    "access_token_expires_at",
    "refresh_token_expires_at",
    "scope",
    "password",
    "created_at",
    "updated_at",
];

pub(super) fn user_from_record(record: DbRecord) -> Result<User, OpenAuthError> {
    Ok(User {
        id: required_string(&record, "id")?.to_owned(),
        name: required_string(&record, "name")?.to_owned(),
        email: required_string(&record, "email")?.to_owned(),
        email_verified: required_bool(&record, "email_verified")?,
        image: optional_string_field(&record, "image")?,
        username: optional_string_field(&record, "username")?,
        display_username: optional_string_field(&record, "display_username")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

pub(super) fn account_from_record(record: DbRecord) -> Result<Account, OpenAuthError> {
    Ok(Account {
        id: required_string(&record, "id")?.to_owned(),
        provider_id: required_string(&record, "provider_id")?.to_owned(),
        account_id: required_string(&record, "account_id")?.to_owned(),
        user_id: required_string(&record, "user_id")?.to_owned(),
        access_token: optional_string_field(&record, "access_token")?,
        refresh_token: optional_string_field(&record, "refresh_token")?,
        id_token: optional_string_field(&record, "id_token")?,
        access_token_expires_at: optional_timestamp_field(&record, "access_token_expires_at")?,
        refresh_token_expires_at: optional_timestamp_field(&record, "refresh_token_expires_at")?,
        scope: optional_string_field(&record, "scope")?,
        password: optional_string_field(&record, "password")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn required_bool(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "boolean")),
        None => Err(missing_field(field)),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

fn optional_timestamp_field(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("record field `{field}` must be {expected}"))
}
