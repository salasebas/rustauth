use serde::Serialize;
use time::OffsetDateTime;

use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, Update, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::user::{CreateUserInput, DbUserStore};

use super::schema::{PHONE_NUMBER_FIELD, PHONE_NUMBER_VERIFIED_FIELD};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PhoneUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
}

pub(crate) async fn find_by_phone(
    adapter: &dyn DbAdapter,
    phone_number: &str,
) -> Result<Option<PhoneUser>, OpenAuthError> {
    let record = adapter
        .find_one(FindOne::new("user").where_clause(Where::new(
            PHONE_NUMBER_FIELD,
            DbValue::String(phone_number.to_owned()),
        )))
        .await?;
    record.map(phone_user_from_record).transpose()
}

pub(crate) async fn update_phone(
    adapter: &dyn DbAdapter,
    user_id: &str,
    phone_number: Option<&str>,
    verified: bool,
) -> Result<Option<PhoneUser>, OpenAuthError> {
    let phone_value = phone_number
        .map(|phone| DbValue::String(phone.to_owned()))
        .unwrap_or(DbValue::Null);
    adapter
        .update(
            Update::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
                .data(PHONE_NUMBER_FIELD, phone_value)
                .data(PHONE_NUMBER_VERIFIED_FIELD, DbValue::Boolean(verified))
                .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
        )
        .await?
        .map(phone_user_from_record)
        .transpose()
}

pub(crate) async fn update_verified(
    adapter: &dyn DbAdapter,
    user_id: &str,
    verified: bool,
) -> Result<Option<PhoneUser>, OpenAuthError> {
    adapter
        .update(
            Update::new("user")
                .where_clause(Where::new("id", DbValue::String(user_id.to_owned())))
                .data(PHONE_NUMBER_VERIFIED_FIELD, DbValue::Boolean(verified))
                .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
        )
        .await?
        .map(phone_user_from_record)
        .transpose()
}

pub(crate) async fn create_user_with_phone(
    adapter: &dyn DbAdapter,
    name: String,
    email: String,
    phone_number: &str,
) -> Result<PhoneUser, OpenAuthError> {
    let user = DbUserStore::new(adapter)
        .create_user(CreateUserInput::new(name, email))
        .await?;
    update_phone(adapter, &user.id, Some(phone_number), true)
        .await?
        .ok_or_else(|| OpenAuthError::Adapter("failed to update created user".to_owned()))
}

fn phone_user_from_record(record: DbRecord) -> Result<PhoneUser, OpenAuthError> {
    Ok(PhoneUser {
        id: string_field(&record, "id")?,
        name: string_field(&record, "name")?,
        email: string_field(&record, "email")?,
        email_verified: bool_field(&record, "email_verified")?,
        image: optional_string_field(&record, "image")?,
        created_at: timestamp_field(&record, "created_at")?,
        updated_at: timestamp_field(&record, "updated_at")?,
        phone_number: optional_string_field(&record, PHONE_NUMBER_FIELD)?,
        phone_number_verified: optional_bool_field(&record, PHONE_NUMBER_VERIFIED_FIELD)?
            .unwrap_or(false),
    })
}

fn string_field(record: &DbRecord, field: &str) -> Result<String, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value.clone()),
        _ => Err(OpenAuthError::Adapter(format!(
            "user.{field} must be a string"
        ))),
    }
}

fn bool_field(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        _ => Err(OpenAuthError::Adapter(format!(
            "user.{field} must be a boolean"
        ))),
    }
}

fn optional_bool_field(record: &DbRecord, field: &str) -> Result<Option<bool>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(OpenAuthError::Adapter(format!(
            "user.{field} must be a boolean or null"
        ))),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.clone())),
        Some(DbValue::Null) | None => Ok(None),
        _ => Err(OpenAuthError::Adapter(format!(
            "user.{field} must be a string or null"
        ))),
    }
}

fn timestamp_field(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        _ => Err(OpenAuthError::Adapter(format!(
            "user.{field} must be a timestamp"
        ))),
    }
}
