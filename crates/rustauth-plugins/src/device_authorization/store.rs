use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindOne, Update, Where,
};
use rustauth_core::error::RustAuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::schema::DEVICE_CODE_MODEL;

const DEVICE_CODE_FIELDS: [&str; 12] = [
    "id",
    "device_code",
    "user_code",
    "user_id",
    "expires_at",
    "status",
    "last_polled_at",
    "polling_interval",
    "client_id",
    "scope",
    "created_at",
    "updated_at",
];
const DEFAULT_ID_LENGTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceAuthorizationStatus {
    Pending,
    Approved,
    Denied,
}

impl DeviceAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}

impl TryFrom<&str> for DeviceAuthorizationStatus {
    type Error = RustAuthError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            _ => Err(RustAuthError::Adapter(format!(
                "device code status `{value}` is invalid"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCodeRecord {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub user_id: Option<String>,
    pub expires_at: OffsetDateTime,
    pub status: DeviceAuthorizationStatus,
    pub last_polled_at: Option<OffsetDateTime>,
    pub polling_interval: Option<i64>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDeviceCodeInput {
    pub device_code: String,
    pub user_code: String,
    pub expires_at: OffsetDateTime,
    pub polling_interval: i64,
    pub client_id: String,
    pub scope: Option<String>,
}

#[derive(Clone, Copy)]
pub struct DeviceCodeStore<'a> {
    adapter: &'a dyn DbAdapter,
}

impl<'a> DeviceCodeStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub async fn create(
        &self,
        input: CreateDeviceCodeInput,
    ) -> Result<DeviceCodeRecord, RustAuthError> {
        let now = OffsetDateTime::now_utc();
        let record = self
            .adapter
            .create(
                Create::new(DEVICE_CODE_MODEL)
                    .data(
                        "id",
                        DbValue::String(generate_random_string(DEFAULT_ID_LENGTH)),
                    )
                    .data("device_code", DbValue::String(input.device_code))
                    .data("user_code", DbValue::String(input.user_code))
                    .data("user_id", DbValue::Null)
                    .data("expires_at", DbValue::Timestamp(input.expires_at))
                    .data(
                        "status",
                        DbValue::String(DeviceAuthorizationStatus::Pending.as_str().to_owned()),
                    )
                    .data("last_polled_at", DbValue::Null)
                    .data("polling_interval", DbValue::Number(input.polling_interval))
                    .data("client_id", DbValue::String(input.client_id))
                    .data("scope", optional_string(input.scope))
                    .data("created_at", DbValue::Timestamp(now))
                    .data("updated_at", DbValue::Timestamp(now))
                    .select(DEVICE_CODE_FIELDS)
                    .force_allow_id(),
            )
            .await?;
        record_from_db(record)
    }

    pub async fn find_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeRecord>, RustAuthError> {
        self.find_one(Where::new(
            "device_code",
            DbValue::String(device_code.to_owned()),
        ))
        .await
    }

    pub async fn find_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeRecord>, RustAuthError> {
        self.find_one(Where::new(
            "user_code",
            DbValue::String(user_code.to_owned()),
        ))
        .await
    }

    pub async fn mark_polled(&self, id: &str) -> Result<Option<DeviceCodeRecord>, RustAuthError> {
        self.update(
            id,
            DbRecord::from([(
                "last_polled_at".to_owned(),
                DbValue::Timestamp(OffsetDateTime::now_utc()),
            )]),
        )
        .await
    }

    pub async fn approve(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<DeviceCodeRecord>, RustAuthError> {
        self.update(
            id,
            DbRecord::from([
                (
                    "status".to_owned(),
                    DbValue::String(DeviceAuthorizationStatus::Approved.as_str().to_owned()),
                ),
                ("user_id".to_owned(), DbValue::String(user_id.to_owned())),
            ]),
        )
        .await
    }

    pub async fn deny(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<DeviceCodeRecord>, RustAuthError> {
        self.update(
            id,
            DbRecord::from([
                (
                    "status".to_owned(),
                    DbValue::String(DeviceAuthorizationStatus::Denied.as_str().to_owned()),
                ),
                ("user_id".to_owned(), DbValue::String(user_id.to_owned())),
            ]),
        )
        .await
    }

    pub async fn delete(&self, id: &str) -> Result<(), RustAuthError> {
        self.adapter
            .delete(Delete::new(DEVICE_CODE_MODEL).where_clause(id_where(id)))
            .await
    }

    /// Atomically consumes an approved device code before token minting.
    ///
    /// Parallel callers racing on the same approved code only observe a
    /// successful consume once: the delete is keyed by both row id and
    /// `status = approved`, so later attempts delete zero rows.
    pub async fn consume_approved(&self, id: &str) -> Result<bool, RustAuthError> {
        let deleted = self
            .adapter
            .delete_many(
                DeleteMany::new(DEVICE_CODE_MODEL)
                    .where_clause(id_where(id))
                    .where_clause(Where::new(
                        "status",
                        DbValue::String(DeviceAuthorizationStatus::Approved.as_str().to_owned()),
                    )),
            )
            .await?;
        Ok(deleted == 1)
    }

    async fn find_one(
        &self,
        where_clause: Where,
    ) -> Result<Option<DeviceCodeRecord>, RustAuthError> {
        self.adapter
            .find_one(
                FindOne::new(DEVICE_CODE_MODEL)
                    .where_clause(where_clause)
                    .select(DEVICE_CODE_FIELDS),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    async fn update(
        &self,
        id: &str,
        data: DbRecord,
    ) -> Result<Option<DeviceCodeRecord>, RustAuthError> {
        let mut query = Update::new(DEVICE_CODE_MODEL)
            .where_clause(id_where(id))
            .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()));
        for (field, value) in data {
            query = query.data(field, value);
        }

        self.adapter
            .update(query)
            .await?
            .map(record_from_db)
            .transpose()
    }
}

fn id_where(id: &str) -> Where {
    Where::new("id", DbValue::String(id.to_owned()))
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn record_from_db(record: DbRecord) -> Result<DeviceCodeRecord, RustAuthError> {
    Ok(DeviceCodeRecord {
        id: required_string(&record, "id")?.to_owned(),
        device_code: required_string(&record, "device_code")?.to_owned(),
        user_code: required_string(&record, "user_code")?.to_owned(),
        user_id: optional_string_field(&record, "user_id")?,
        expires_at: required_timestamp(&record, "expires_at")?,
        status: DeviceAuthorizationStatus::try_from(required_string(&record, "status")?)?,
        last_polled_at: optional_timestamp(&record, "last_polled_at")?,
        polling_interval: optional_number(&record, "polling_interval")?,
        client_id: optional_string_field(&record, "client_id")?,
        scope: optional_string_field(&record, "scope")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

fn optional_number(record: &DbRecord, field: &str) -> Result<Option<i64>, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Number(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "number or null")),
    }
}

fn missing_field(field: &str) -> RustAuthError {
    RustAuthError::Adapter(format!("device code record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> RustAuthError {
    RustAuthError::Adapter(format!(
        "device code record field `{field}` must be {expected}"
    ))
}
