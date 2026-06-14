use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use rustauth_core::db::{DbField, DbFieldType, DbRecord, DbValue};
use rustauth_core::error::RustAuthError;
use serde_json::Value;

pub(crate) fn create_values(
    fields: &IndexMap<String, DbField>,
    body: &serde_json::Map<String, Value>,
) -> Result<DbRecord, RustAuthError> {
    let mut values = DbRecord::new();
    for (name, field) in fields {
        match body.get(name) {
            Some(value) => {
                if !field.input {
                    return Err(invalid(format!(
                        "additional field `{name}` is not accepted as input"
                    )));
                }
                values.insert(
                    name.clone(),
                    json_to_db_value(name, &field.field_type, value)?,
                );
            }
            None if field.required => {
                return Err(invalid(format!(
                    "missing required additional field `{name}`"
                )));
            }
            None => {
                values.insert(name.clone(), DbValue::Null);
            }
        };
    }
    Ok(values)
}

pub(crate) fn update_values(
    fields: &IndexMap<String, DbField>,
    body: &serde_json::Map<String, Value>,
) -> Result<DbRecord, RustAuthError> {
    let mut values = DbRecord::new();
    for (name, value) in body {
        let Some(field) = fields.get(name) else {
            continue;
        };
        if !field.input {
            return Err(invalid(format!(
                "additional field `{name}` is not accepted as input"
            )));
        }
        values.insert(
            name.clone(),
            json_to_db_value(name, &field.field_type, value)?,
        );
    }
    Ok(values)
}

pub(crate) fn extract_record_fields(
    record: &DbRecord,
    builtin_fields: &[&str],
) -> Result<BTreeMap<String, Value>, RustAuthError> {
    let builtin_fields = builtin_fields.iter().copied().collect::<BTreeSet<_>>();
    record
        .iter()
        .filter(|(field, _)| !builtin_fields.contains(field.as_str()))
        .map(|(field, value)| db_value_to_json(value).map(|value| (field.clone(), value)))
        .collect()
}

pub(crate) fn retain_returned(
    values: &mut BTreeMap<String, Value>,
    fields: &IndexMap<String, DbField>,
) {
    values.retain(|name, _| fields.get(name).is_some_and(|field| field.returned));
}

fn json_to_db_value(
    name: &str,
    field_type: &DbFieldType,
    value: &Value,
) -> Result<DbValue, RustAuthError> {
    if value.is_null() {
        return Ok(DbValue::Null);
    }
    match field_type {
        DbFieldType::String => value
            .as_str()
            .map(|value| DbValue::String(value.to_owned())),
        DbFieldType::Number => value.as_i64().map(DbValue::Number),
        DbFieldType::Boolean => value.as_bool().map(DbValue::Boolean),
        DbFieldType::Json => Some(DbValue::Json(value.clone())),
        DbFieldType::StringArray => value.as_array().and_then(|values| {
            values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
                .map(DbValue::StringArray)
        }),
        DbFieldType::NumberArray => value.as_array().and_then(|values| {
            values
                .iter()
                .map(Value::as_i64)
                .collect::<Option<Vec<_>>>()
                .map(DbValue::NumberArray)
        }),
        DbFieldType::Timestamp => None,
    }
    .ok_or_else(|| invalid(format!("invalid value for additional field `{name}`")))
}

fn db_value_to_json(value: &DbValue) -> Result<Value, RustAuthError> {
    match value {
        DbValue::String(value) => Ok(Value::String(value.clone())),
        DbValue::Number(value) => Ok(Value::Number((*value).into())),
        DbValue::Boolean(value) => Ok(Value::Bool(*value)),
        DbValue::Timestamp(value) => {
            serde_json::to_value(value).map_err(|error| RustAuthError::Api(error.to_string()))
        }
        DbValue::Json(value) => Ok(value.clone()),
        DbValue::StringArray(values) => Ok(Value::Array(
            values.iter().cloned().map(Value::String).collect(),
        )),
        DbValue::NumberArray(values) => Ok(Value::Array(
            values
                .iter()
                .map(|value| Value::Number((*value).into()))
                .collect(),
        )),
        DbValue::Record(_) | DbValue::RecordArray(_) => Ok(Value::Null),
        DbValue::Null => Ok(Value::Null),
    }
}

fn invalid(message: String) -> RustAuthError {
    RustAuthError::Api(message)
}
