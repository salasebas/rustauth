use rustauth_core::db::{DbField, DbFieldType, DbValue};
use rustauth_core::error::RustAuthError;
use sqlx::mysql::MySqlRow;
use sqlx::Row;
use time::OffsetDateTime;

use super::errors::{json_error, sql_error};

pub(super) fn row_value_at(
    row: &MySqlRow,
    field: &DbField,
    column: &str,
) -> Result<DbValue, RustAuthError> {
    match field.field_type {
        DbFieldType::String => row
            .try_get::<Option<String>, _>(column)
            .map(|value| value.map(DbValue::String).unwrap_or(DbValue::Null))
            .map_err(sql_error),
        DbFieldType::Number => row
            .try_get::<Option<i64>, _>(column)
            .map(|value| value.map(DbValue::Number).unwrap_or(DbValue::Null))
            .map_err(sql_error),
        DbFieldType::Boolean => row
            .try_get::<Option<bool>, _>(column)
            .map(|value| value.map(DbValue::Boolean).unwrap_or(DbValue::Null))
            .map_err(sql_error),
        DbFieldType::Timestamp => row
            .try_get::<Option<OffsetDateTime>, _>(column)
            .map(|value| value.map(DbValue::Timestamp).unwrap_or(DbValue::Null))
            .map_err(sql_error),
        DbFieldType::Json => row
            .try_get::<Option<serde_json::Value>, _>(column)
            .map(|value| value.map(DbValue::Json).unwrap_or(DbValue::Null))
            .map_err(sql_error),
        DbFieldType::StringArray => {
            let value = row
                .try_get::<Option<serde_json::Value>, _>(column)
                .map_err(sql_error)?;
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
                .try_get::<Option<serde_json::Value>, _>(column)
                .map_err(sql_error)?;
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
