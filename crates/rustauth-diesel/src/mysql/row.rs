use diesel::deserialize::{FromSql, QueryableByName};
use diesel::mysql::{Mysql, MysqlType, MysqlValue};
use diesel::row::{Field, NamedRow, Row};
use diesel::sql_types::{BigInt, Bool, Text, Timestamp};
use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbValue};
use rustauth_core::error::RustAuthError;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub(super) enum StoredValue {
    Null,
    String(String),
    Number(i64),
    Boolean(bool),
    Timestamp(OffsetDateTime),
    Json(serde_json::Value),
}

/// Dynamic MySQL row captured from any `sql_query` result.
#[derive(Debug, Clone, Default)]
pub(super) struct DieselMysqlRow {
    columns: IndexMap<String, StoredValue>,
}

impl QueryableByName<Mysql> for DieselMysqlRow {
    fn build<'a>(row: &impl NamedRow<'a, Mysql>) -> diesel::deserialize::Result<Self> {
        let mut columns = IndexMap::new();
        for index in 0..Row::field_count(row) {
            let field =
                Row::get(row, index).ok_or_else(|| "missing diesel mysql row field".to_string())?;
            let name = field
                .field_name()
                .ok_or_else(|| "diesel mysql row field has no name".to_string())?
                .to_owned();
            let stored = match field.value() {
                Some(value) => capture_mysql_value(value)?,
                None => StoredValue::Null,
            };
            columns.insert(name, stored);
        }
        Ok(Self { columns })
    }
}

fn capture_mysql_value(value: MysqlValue<'_>) -> diesel::deserialize::Result<StoredValue> {
    match value.value_type() {
        MysqlType::LongLong
        | MysqlType::Long
        | MysqlType::Short
        | MysqlType::Tiny
        | MysqlType::UnsignedLongLong
        | MysqlType::UnsignedLong
        | MysqlType::UnsignedShort
        | MysqlType::UnsignedTiny => Ok(StoredValue::Number(
            <i64 as FromSql<BigInt, Mysql>>::from_sql(value)?,
        )),
        MysqlType::String | MysqlType::Blob | MysqlType::Enum | MysqlType::Set => {
            let string = <String as FromSql<Text, Mysql>>::from_sql(value)?;
            if let Ok(json) = serde_json::from_str(&string) {
                Ok(StoredValue::Json(json))
            } else {
                Ok(StoredValue::String(string))
            }
        }
        MysqlType::Timestamp | MysqlType::DateTime | MysqlType::Date => {
            Ok(StoredValue::Timestamp(<OffsetDateTime as FromSql<
                Timestamp,
                Mysql,
            >>::from_sql(value)?))
        }
        MysqlType::Time => Ok(StoredValue::Timestamp(<OffsetDateTime as FromSql<
            Timestamp,
            Mysql,
        >>::from_sql(value)?)),
        MysqlType::Float | MysqlType::Double | MysqlType::Numeric => Ok(StoredValue::Number(
            <i64 as FromSql<BigInt, Mysql>>::from_sql(value)?,
        )),
        MysqlType::Bit => Ok(StoredValue::Boolean(
            <bool as FromSql<Bool, Mysql>>::from_sql(value)?,
        )),
        _ => Err("unsupported diesel mysql column type".into()),
    }
}

pub(super) fn row_value_at(
    row: &DieselMysqlRow,
    field: &DbField,
    column: &str,
) -> Result<DbValue, RustAuthError> {
    let stored = row.columns.get(column).ok_or_else(|| {
        RustAuthError::Adapter(format!("diesel mysql row missing column `{column}`"))
    })?;
    decode_field(field, stored)
}

fn decode_field(field: &DbField, stored: &StoredValue) -> Result<DbValue, RustAuthError> {
    if matches!(stored, StoredValue::Null) {
        return Ok(DbValue::Null);
    }

    match field.field_type {
        DbFieldType::String => match stored {
            StoredValue::String(value) => Ok(DbValue::String(value.clone())),
            StoredValue::Json(value) => Ok(DbValue::String(value.to_string())),
            other => type_mismatch(field, other),
        },
        DbFieldType::Number => match stored {
            StoredValue::Number(value) => Ok(DbValue::Number(*value)),
            other => type_mismatch(field, other),
        },
        DbFieldType::Boolean => match stored {
            StoredValue::Boolean(value) => Ok(DbValue::Boolean(*value)),
            StoredValue::Number(value) => Ok(DbValue::Boolean(*value != 0)),
            other => type_mismatch(field, other),
        },
        DbFieldType::Timestamp => match stored {
            StoredValue::Timestamp(value) => Ok(DbValue::Timestamp(*value)),
            other => type_mismatch(field, other),
        },
        DbFieldType::Json => match stored {
            StoredValue::Json(value) => Ok(DbValue::Json(value.clone())),
            StoredValue::String(value) => serde_json::from_str(value)
                .map(DbValue::Json)
                .map_err(super::errors::json_error),
            other => type_mismatch(field, other),
        },
        DbFieldType::StringArray => match stored {
            StoredValue::Json(value) => serde_json::from_value::<Vec<String>>(value.clone())
                .map(DbValue::StringArray)
                .map_err(super::errors::json_error),
            StoredValue::String(value) => serde_json::from_str(value)
                .map(DbValue::StringArray)
                .map_err(super::errors::json_error),
            other => type_mismatch(field, other),
        },
        DbFieldType::NumberArray => match stored {
            StoredValue::Json(value) => serde_json::from_value::<Vec<i64>>(value.clone())
                .map(DbValue::NumberArray)
                .map_err(super::errors::json_error),
            StoredValue::String(value) => serde_json::from_str(value)
                .map(DbValue::NumberArray)
                .map_err(super::errors::json_error),
            other => type_mismatch(field, other),
        },
    }
}

fn type_mismatch(field: &DbField, stored: &StoredValue) -> Result<DbValue, RustAuthError> {
    Err(RustAuthError::Adapter(format!(
        "diesel mysql row type mismatch for field `{}`: stored {stored:?}, expected {:?}",
        field.name, field.field_type
    )))
}
