use openauth_core::db::{DbField, DbFieldType, DbValue, IdGeneration};
use openauth_core::error::OpenAuthError;
use tokio_postgres::Row;

use super::errors::postgres_error;

pub fn row_value_at(row: &Row, field: &DbField, column: &str) -> Result<DbValue, OpenAuthError> {
    match field.field_type {
        DbFieldType::String if field.generated_id == Some(IdGeneration::Uuid) => row
            .try_get::<_, Option<uuid::Uuid>>(column)
            .map(|value| {
                value
                    .map(|uuid| DbValue::String(uuid.to_string()))
                    .unwrap_or(DbValue::Null)
            })
            .map_err(postgres_error),
        DbFieldType::String => row
            .try_get::<_, Option<String>>(column)
            .map(|value| value.map(DbValue::String).unwrap_or(DbValue::Null))
            .map_err(postgres_error),
        DbFieldType::Number => row
            .try_get::<_, Option<i64>>(column)
            .map(|value| value.map(DbValue::Number).unwrap_or(DbValue::Null))
            .map_err(postgres_error),
        DbFieldType::Boolean => row
            .try_get::<_, Option<bool>>(column)
            .map(|value| value.map(DbValue::Boolean).unwrap_or(DbValue::Null))
            .map_err(postgres_error),
        DbFieldType::Timestamp => row
            .try_get::<_, Option<time::OffsetDateTime>>(column)
            .map(|value| value.map(DbValue::Timestamp).unwrap_or(DbValue::Null))
            .map_err(postgres_error),
        DbFieldType::Json => row
            .try_get::<_, Option<serde_json::Value>>(column)
            .map(|value| value.map(DbValue::Json).unwrap_or(DbValue::Null))
            .map_err(postgres_error),
        DbFieldType::StringArray => row
            .try_get::<_, Option<Vec<String>>>(column)
            .map(|value| value.map(DbValue::StringArray).unwrap_or(DbValue::Null))
            .map_err(postgres_error),
        DbFieldType::NumberArray => row
            .try_get::<_, Option<Vec<i64>>>(column)
            .map(|value| value.map(DbValue::NumberArray).unwrap_or(DbValue::Null))
            .map_err(postgres_error),
    }
}
