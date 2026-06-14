use rustauth_core::db::{DbField, DbFieldType, DbValue, IdGeneration};
use rustauth_core::error::RustAuthError;
use sqlx::postgres::PgRow;
use sqlx::Row;
use time::OffsetDateTime;

use super::errors::sql_error;

pub(super) fn row_value_at(
    row: &PgRow,
    field: &DbField,
    column: &str,
) -> Result<DbValue, RustAuthError> {
    match field.field_type {
        DbFieldType::String if field.generated_id == Some(IdGeneration::Uuid) => row
            .try_get::<Option<uuid::Uuid>, _>(column)
            .map(|value| {
                value
                    .map(|value| DbValue::String(value.to_string()))
                    .unwrap_or(DbValue::Null)
            })
            .map_err(sql_error),
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
        DbFieldType::StringArray => row
            .try_get::<Option<Vec<String>>, _>(column)
            .map(|value| value.map(DbValue::StringArray).unwrap_or(DbValue::Null))
            .map_err(sql_error),
        DbFieldType::NumberArray => row
            .try_get::<Option<Vec<i64>>, _>(column)
            .map(|value| value.map(DbValue::NumberArray).unwrap_or(DbValue::Null))
            .map_err(sql_error),
    }
}
