use rustauth_core::db::{DbFieldType, DbValue, SqlParam};
use rustauth_core::error::RustAuthError;
use sqlx::sqlite::SqliteArguments;
use sqlx::Arguments;
use time::format_description::well_known::Rfc3339;

use super::errors::{argument_error, json_error, time_error};

pub(super) fn bind_param(
    args: &mut SqliteArguments<'_>,
    param: &SqlParam,
) -> Result<(), RustAuthError> {
    match &param.value {
        DbValue::String(value) => args.add(value.clone()).map_err(argument_error),
        DbValue::Number(value) => args.add(*value).map_err(argument_error),
        DbValue::Boolean(value) => args.add(i64::from(*value)).map_err(argument_error),
        DbValue::Timestamp(value) => args
            .add(value.format(&Rfc3339).map_err(time_error)?)
            .map_err(argument_error),
        DbValue::Json(value) => args.add(value.to_string()).map_err(argument_error),
        DbValue::StringArray(value) => args
            .add(serde_json::to_string(value).map_err(json_error)?)
            .map_err(argument_error),
        DbValue::NumberArray(value) => args
            .add(serde_json::to_string(value).map_err(json_error)?)
            .map_err(argument_error),
        DbValue::Record(_) | DbValue::RecordArray(_) => Err(RustAuthError::Adapter(
            "joined records cannot be bound as SQL values".to_owned(),
        )),
        DbValue::Null => match param.field_type {
            DbFieldType::String
            | DbFieldType::Timestamp
            | DbFieldType::Json
            | DbFieldType::StringArray
            | DbFieldType::NumberArray => args.add(Option::<String>::None).map_err(argument_error),
            DbFieldType::Number | DbFieldType::Boolean => {
                args.add(Option::<i64>::None).map_err(argument_error)
            }
        },
    }
}
