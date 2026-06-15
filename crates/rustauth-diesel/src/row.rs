use rustauth_core::db::{DbField, DbFieldType, DbRecord, DbValue, SqlSelectedField};
use rustauth_core::error::RustAuthError;

/// Row decoding strategy selected for the Diesel adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowDecodeStrategy {
    /// Read each projected alias with [`diesel::row::NamedRow::get`].
    DirectAlias,
}

impl RowDecodeStrategy {
    pub const SELECTED: Self = Self::DirectAlias;
}

#[cfg(feature = "mysql")]
pub use mysql::decode_mysql_row;
#[cfg(feature = "postgres")]
pub use postgres::decode_postgres_row;

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use diesel::pg::Pg;
    use diesel::row::NamedRow;
    use diesel::sql_types::{
        Array, BigInt, Bool, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid,
    };
    use rustauth_core::db::IdGeneration;
    use time::OffsetDateTime;

    pub fn decode_postgres_row<'a, R>(
        row: &R,
        selection: &[SqlSelectedField],
    ) -> Result<DbRecord, RustAuthError>
    where
        R: NamedRow<'a, Pg>,
    {
        selection
            .iter()
            .map(|selected| {
                value_at(row, &selected.field, &selected.alias)
                    .map(|value| (selected.logical_name.clone(), value))
            })
            .collect()
    }

    pub fn value_at<'a, R>(row: &R, field: &DbField, alias: &str) -> Result<DbValue, RustAuthError>
    where
        R: NamedRow<'a, Pg>,
    {
        match field.field_type {
            DbFieldType::String if field.generated_id == Some(IdGeneration::Uuid) => {
                NamedRow::get::<Nullable<DieselUuid>, Option<uuid::Uuid>>(row, alias)
                    .map(|value| {
                        value
                            .map(|value| DbValue::String(value.to_string()))
                            .unwrap_or(DbValue::Null)
                    })
                    .map_err(sql_error)
            }
            DbFieldType::String => NamedRow::get::<Nullable<Text>, Option<String>>(row, alias)
                .map(|value| value.map(DbValue::String).unwrap_or(DbValue::Null))
                .map_err(sql_error),
            DbFieldType::Number => NamedRow::get::<Nullable<BigInt>, Option<i64>>(row, alias)
                .map(|value| value.map(DbValue::Number).unwrap_or(DbValue::Null))
                .map_err(sql_error),
            DbFieldType::Boolean => NamedRow::get::<Nullable<Bool>, Option<bool>>(row, alias)
                .map(|value| value.map(DbValue::Boolean).unwrap_or(DbValue::Null))
                .map_err(sql_error),
            DbFieldType::Timestamp => {
                NamedRow::get::<Nullable<Timestamptz>, Option<OffsetDateTime>>(row, alias)
                    .map(|value| value.map(DbValue::Timestamp).unwrap_or(DbValue::Null))
                    .map_err(sql_error)
            }
            DbFieldType::Json => {
                NamedRow::get::<Nullable<Jsonb>, Option<serde_json::Value>>(row, alias)
                    .map(|value| value.map(DbValue::Json).unwrap_or(DbValue::Null))
                    .map_err(sql_error)
            }
            DbFieldType::StringArray => {
                NamedRow::get::<Nullable<Array<Text>>, Option<Vec<String>>>(row, alias)
                    .map(|value| value.map(DbValue::StringArray).unwrap_or(DbValue::Null))
                    .map_err(sql_error)
            }
            DbFieldType::NumberArray => {
                NamedRow::get::<Nullable<Array<BigInt>>, Option<Vec<i64>>>(row, alias)
                    .map(|value| value.map(DbValue::NumberArray).unwrap_or(DbValue::Null))
                    .map_err(sql_error)
            }
        }
    }

    fn sql_error(error: Box<dyn std::error::Error + Send + Sync>) -> RustAuthError {
        RustAuthError::Adapter(format!("diesel postgres row decode: {error}"))
    }
}

#[cfg(feature = "mysql")]
mod mysql {
    use super::*;
    use diesel::mysql::Mysql;
    use diesel::row::NamedRow;
    use diesel::sql_types::{BigInt, Bool, Json, Nullable, Text, Timestamp};
    use time::OffsetDateTime;

    pub fn decode_mysql_row<'a, R>(
        row: &R,
        selection: &[SqlSelectedField],
    ) -> Result<DbRecord, RustAuthError>
    where
        R: NamedRow<'a, Mysql>,
    {
        selection
            .iter()
            .map(|selected| {
                value_at(row, &selected.field, &selected.alias)
                    .map(|value| (selected.logical_name.clone(), value))
            })
            .collect()
    }

    pub fn value_at<'a, R>(row: &R, field: &DbField, alias: &str) -> Result<DbValue, RustAuthError>
    where
        R: NamedRow<'a, Mysql>,
    {
        match field.field_type {
            DbFieldType::String => NamedRow::get::<Nullable<Text>, Option<String>>(row, alias)
                .map(|value| value.map(DbValue::String).unwrap_or(DbValue::Null))
                .map_err(sql_error),
            DbFieldType::Number => NamedRow::get::<Nullable<BigInt>, Option<i64>>(row, alias)
                .map(|value| value.map(DbValue::Number).unwrap_or(DbValue::Null))
                .map_err(sql_error),
            DbFieldType::Boolean => NamedRow::get::<Nullable<Bool>, Option<bool>>(row, alias)
                .map(|value| value.map(DbValue::Boolean).unwrap_or(DbValue::Null))
                .map_err(sql_error),
            DbFieldType::Timestamp => {
                NamedRow::get::<Nullable<Timestamp>, Option<OffsetDateTime>>(row, alias)
                    .map(|value| value.map(DbValue::Timestamp).unwrap_or(DbValue::Null))
                    .map_err(sql_error)
            }
            DbFieldType::Json => {
                NamedRow::get::<Nullable<Json>, Option<serde_json::Value>>(row, alias)
                    .map(|value| value.map(DbValue::Json).unwrap_or(DbValue::Null))
                    .map_err(sql_error)
            }
            DbFieldType::StringArray => {
                let value = NamedRow::get::<Nullable<Json>, Option<serde_json::Value>>(row, alias)
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
                let value = NamedRow::get::<Nullable<Json>, Option<serde_json::Value>>(row, alias)
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

    fn sql_error(error: Box<dyn std::error::Error + Send + Sync>) -> RustAuthError {
        RustAuthError::Adapter(format!("diesel mysql row decode: {error}"))
    }

    fn json_error(error: serde_json::Error) -> RustAuthError {
        RustAuthError::Adapter(format!("diesel mysql json decode: {error}"))
    }
}
