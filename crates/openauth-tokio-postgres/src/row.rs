use openauth_core::db::{DbField, DbFieldType, DbValue};
use openauth_core::error::OpenAuthError;
use tokio_postgres::Row;

use super::errors::{json_error, postgres_error};

pub fn row_value_at(row: &Row, field: &DbField, column: &str) -> Result<DbValue, OpenAuthError> {
    match field.field_type {
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
        DbFieldType::StringArray => {
            let value = row
                .try_get::<_, Option<serde_json::Value>>(column)
                .map_err(postgres_error)?;
            value
                .map(|value| {
                    serde_json::from_value::<Vec<String>>(value)
                        .map(DbValue::StringArray)
                        .map_err(json_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
        DbFieldType::NumberArray => {
            let value = row
                .try_get::<_, Option<serde_json::Value>>(column)
                .map_err(postgres_error)?;
            value
                .map(|value| {
                    serde_json::from_value::<Vec<i64>>(value)
                        .map(DbValue::NumberArray)
                        .map_err(json_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
    }
}
