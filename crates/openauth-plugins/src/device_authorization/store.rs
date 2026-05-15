use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{Create, DbAdapter, DbRecord, DbValue, Delete, FindOne, Update, Where};
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::schema::DEVICE_CODE_MODEL;

const DEVICE_CODE_FIELDS: [&str; 12] = [
    "id",
    "deviceCode",
    "userCode",
    "userId",
    "expiresAt",
    "status",
    "lastPolledAt",
    "pollingInterval",
    "clientId",
    "scope",
    "createdAt",
    "updatedAt",
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
    type Error = OpenAuthError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            _ => Err(OpenAuthError::Adapter(format!(
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
    ) -> Result<DeviceCodeRecord, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let record = self
            .adapter
            .create(
                Create::new(DEVICE_CODE_MODEL)
                    .data(
                        "id",
                        DbValue::String(generate_random_string(DEFAULT_ID_LENGTH)),
                    )
                    .data("deviceCode", DbValue::String(input.device_code))
                    .data("userCode", DbValue::String(input.user_code))
                    .data("userId", DbValue::Null)
                    .data("expiresAt", DbValue::Timestamp(input.expires_at))
                    .data(
                        "status",
                        DbValue::String(DeviceAuthorizationStatus::Pending.as_str().to_owned()),
                    )
                    .data("lastPolledAt", DbValue::Null)
                    .data("pollingInterval", DbValue::Number(input.polling_interval))
                    .data("clientId", DbValue::String(input.client_id))
                    .data("scope", optional_string(input.scope))
                    .data("createdAt", DbValue::Timestamp(now))
                    .data("updatedAt", DbValue::Timestamp(now))
                    .select(DEVICE_CODE_FIELDS)
                    .force_allow_id(),
            )
            .await?;
        record_from_db(record)
    }

    pub async fn find_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeRecord>, OpenAuthError> {
        self.find_one(Where::new(
            "deviceCode",
            DbValue::String(device_code.to_owned()),
        ))
        .await
    }

    pub async fn find_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeRecord>, OpenAuthError> {
        self.find_one(Where::new(
            "userCode",
            DbValue::String(user_code.to_owned()),
        ))
        .await
    }

    pub async fn mark_polled(&self, id: &str) -> Result<Option<DeviceCodeRecord>, OpenAuthError> {
        self.update(
            id,
            DbRecord::from([(
                "lastPolledAt".to_owned(),
                DbValue::Timestamp(OffsetDateTime::now_utc()),
            )]),
        )
        .await
    }

    pub async fn approve(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<DeviceCodeRecord>, OpenAuthError> {
        self.update(
            id,
            DbRecord::from([
                (
                    "status".to_owned(),
                    DbValue::String(DeviceAuthorizationStatus::Approved.as_str().to_owned()),
                ),
                ("userId".to_owned(), DbValue::String(user_id.to_owned())),
            ]),
        )
        .await
    }

    pub async fn deny(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<DeviceCodeRecord>, OpenAuthError> {
        self.update(
            id,
            DbRecord::from([
                (
                    "status".to_owned(),
                    DbValue::String(DeviceAuthorizationStatus::Denied.as_str().to_owned()),
                ),
                ("userId".to_owned(), DbValue::String(user_id.to_owned())),
            ]),
        )
        .await
    }

    pub async fn delete(&self, id: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(Delete::new(DEVICE_CODE_MODEL).where_clause(id_where(id)))
            .await
    }

    async fn find_one(
        &self,
        where_clause: Where,
    ) -> Result<Option<DeviceCodeRecord>, OpenAuthError> {
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
    ) -> Result<Option<DeviceCodeRecord>, OpenAuthError> {
        let mut query = Update::new(DEVICE_CODE_MODEL)
            .where_clause(id_where(id))
            .data("updatedAt", DbValue::Timestamp(OffsetDateTime::now_utc()));
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

fn record_from_db(record: DbRecord) -> Result<DeviceCodeRecord, OpenAuthError> {
    Ok(DeviceCodeRecord {
        id: required_string(&record, "id")?.to_owned(),
        device_code: required_string(&record, "deviceCode")?.to_owned(),
        user_code: required_string(&record, "userCode")?.to_owned(),
        user_id: optional_string_field(&record, "userId")?,
        expires_at: required_timestamp(&record, "expiresAt")?,
        status: DeviceAuthorizationStatus::try_from(required_string(&record, "status")?)?,
        last_polled_at: optional_timestamp(&record, "lastPolledAt")?,
        polling_interval: optional_number(&record, "pollingInterval")?,
        client_id: optional_string_field(&record, "clientId")?,
        scope: optional_string_field(&record, "scope")?,
        created_at: required_timestamp(&record, "createdAt")?,
        updated_at: required_timestamp(&record, "updatedAt")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
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

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

fn optional_number(record: &DbRecord, field: &str) -> Result<Option<i64>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Number(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "number or null")),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("device code record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!(
        "device code record field `{field}` must be {expected}"
    ))
}
