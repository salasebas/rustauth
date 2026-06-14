use rustauth_core::db::{DbField, DbFieldType, DbValue};
use rustauth_core::error::RustAuthError;
use sqlx::sqlite::SqliteRow;
use sqlx::Row;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::errors::{json_error, sql_error, time_error};

pub(super) fn row_value_at(
    row: &SqliteRow,
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
            .try_get::<Option<i64>, _>(column)
            .map(|value| {
                value
                    .map(|value| DbValue::Boolean(value != 0))
                    .unwrap_or(DbValue::Null)
            })
            .map_err(sql_error),
        DbFieldType::Timestamp => {
            let value = row
                .try_get::<Option<String>, _>(column)
                .map_err(sql_error)?;
            value
                .map(|value| {
                    OffsetDateTime::parse(&value, &Rfc3339)
                        .map(DbValue::Timestamp)
                        .map_err(time_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
        DbFieldType::Json => {
            let value = row
                .try_get::<Option<String>, _>(column)
                .map_err(sql_error)?;
            value
                .map(|value| {
                    serde_json::from_str(&value)
                        .map(DbValue::Json)
                        .map_err(json_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
        DbFieldType::StringArray => {
            let value = row
                .try_get::<Option<String>, _>(column)
                .map_err(sql_error)?;
            value
                .map(|value| {
                    serde_json::from_str::<Vec<String>>(&value)
                        .map(DbValue::StringArray)
                        .map_err(json_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
        DbFieldType::NumberArray => {
            let value = row
                .try_get::<Option<String>, _>(column)
                .map_err(sql_error)?;
            value
                .map(|value| {
                    serde_json::from_str::<Vec<i64>>(&value)
                        .map(DbValue::NumberArray)
                        .map_err(json_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
    }
}
