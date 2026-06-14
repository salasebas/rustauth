use rustauth_core::db::{DbFieldType, DbValue, SqlParam};
use rustauth_core::error::RustAuthError;
use sqlx::mysql::MySqlArguments;
use sqlx::Arguments;
use time::OffsetDateTime;

use super::errors::argument_error;

pub(super) fn bind_param(args: &mut MySqlArguments, param: &SqlParam) -> Result<(), RustAuthError> {
    match &param.value {
        DbValue::String(value) => args.add(value.clone()).map_err(argument_error),
        DbValue::Number(value) => args.add(*value).map_err(argument_error),
        DbValue::Boolean(value) => args.add(*value).map_err(argument_error),
        DbValue::Timestamp(value) => args.add(*value).map_err(argument_error),
        DbValue::Json(value) => args.add(value.clone()).map_err(argument_error),
        DbValue::StringArray(value) => args
            .add(serde_json::Value::Array(
                value
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ))
            .map_err(argument_error),
        DbValue::NumberArray(value) => args
            .add(serde_json::Value::Array(
                value.iter().copied().map(serde_json::Value::from).collect(),
            ))
            .map_err(argument_error),
        DbValue::Record(_) | DbValue::RecordArray(_) => Err(RustAuthError::Adapter(
            "joined records cannot be bound as SQL values".to_owned(),
        )),
        DbValue::Null => match param.field_type {
            DbFieldType::String => args.add(Option::<String>::None).map_err(argument_error),
            DbFieldType::Number => args.add(Option::<i64>::None).map_err(argument_error),
            DbFieldType::Boolean => args.add(Option::<bool>::None).map_err(argument_error),
            DbFieldType::Timestamp => args
                .add(Option::<OffsetDateTime>::None)
                .map_err(argument_error),
            DbFieldType::Json | DbFieldType::StringArray | DbFieldType::NumberArray => args
                .add(Option::<serde_json::Value>::None)
                .map_err(argument_error),
        },
    }
}
