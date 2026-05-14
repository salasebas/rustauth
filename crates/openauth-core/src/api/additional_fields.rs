use std::collections::BTreeMap;

use serde_json::Value;

use crate::db::{DbFieldType, DbRecord, DbValue};
use crate::error::OpenAuthError;
use crate::options::{SessionAdditionalField, UserAdditionalField};

pub(crate) trait AdditionalField {
    fn field_type(&self) -> &DbFieldType;
    fn required(&self) -> bool;
    fn input(&self) -> bool;
    fn returned(&self) -> bool;
    fn default_value(&self) -> Option<&DbValue>;
}

impl AdditionalField for UserAdditionalField {
    fn field_type(&self) -> &DbFieldType {
        &self.field_type
    }

    fn required(&self) -> bool {
        self.required
    }

    fn input(&self) -> bool {
        self.input
    }

    fn returned(&self) -> bool {
        self.returned
    }

    fn default_value(&self) -> Option<&DbValue> {
        self.default_value.as_ref()
    }
}

impl AdditionalField for SessionAdditionalField {
    fn field_type(&self) -> &DbFieldType {
        &self.field_type
    }

    fn required(&self) -> bool {
        self.required
    }

    fn input(&self) -> bool {
        self.input
    }

    fn returned(&self) -> bool {
        self.returned
    }

    fn default_value(&self) -> Option<&DbValue> {
        self.default_value.as_ref()
    }
}

pub(crate) fn create_values<F>(
    fields: &BTreeMap<String, F>,
    body: &serde_json::Map<String, Value>,
) -> Result<DbRecord, AdditionalFieldError>
where
    F: AdditionalField,
{
    let mut values = DbRecord::new();
    for (name, field) in fields {
        match body.get(name) {
            Some(value) => {
                if !field.input() {
                    return Err(AdditionalFieldError::NotInput(name.clone()));
                }
                values.insert(
                    name.clone(),
                    json_to_db_value(name, field.field_type(), value)
                        .map_err(AdditionalFieldError::InvalidType)?,
                );
            }
            None => {
                if let Some(value) = field.default_value() {
                    values.insert(name.clone(), value.clone());
                } else if field.required() {
                    return Err(AdditionalFieldError::MissingRequired(name.clone()));
                } else {
                    values.insert(name.clone(), DbValue::Null);
                }
            }
        }
    }
    Ok(values)
}

pub(crate) fn update_values<F>(
    fields: &BTreeMap<String, F>,
    body: &serde_json::Map<String, Value>,
) -> Result<DbRecord, AdditionalFieldError>
where
    F: AdditionalField,
{
    let mut values = DbRecord::new();
    for (name, value) in body {
        let Some(field) = fields.get(name) else {
            continue;
        };
        if !field.input() {
            return Err(AdditionalFieldError::NotInput(name.clone()));
        }
        values.insert(
            name.clone(),
            json_to_db_value(name, field.field_type(), value)
                .map_err(AdditionalFieldError::InvalidType)?,
        );
    }
    Ok(values)
}

pub(crate) fn insert_returned_fields<F>(
    object: &mut serde_json::Map<String, Value>,
    fields: &BTreeMap<String, F>,
    record: &DbRecord,
) -> Result<(), OpenAuthError>
where
    F: AdditionalField,
{
    for (name, field) in fields {
        if !field.returned() {
            continue;
        }
        let value = record
            .get(name)
            .or_else(|| field.default_value())
            .unwrap_or(&DbValue::Null);
        object.insert(name.clone(), db_value_to_json(value)?);
    }
    Ok(())
}

pub(crate) fn db_value_to_json(value: &DbValue) -> Result<Value, OpenAuthError> {
    match value {
        DbValue::String(value) => Ok(Value::String(value.clone())),
        DbValue::Number(value) => Ok(Value::Number((*value).into())),
        DbValue::Boolean(value) => Ok(Value::Bool(*value)),
        DbValue::Timestamp(value) => {
            serde_json::to_value(value).map_err(|error| OpenAuthError::Api(error.to_string()))
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
        DbValue::Record(record) => db_record_to_json(record),
        DbValue::RecordArray(records) => records
            .iter()
            .map(db_record_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        DbValue::Null => Ok(Value::Null),
    }
}

pub(crate) fn json_to_db_value(
    name: &str,
    field_type: &DbFieldType,
    value: &Value,
) -> Result<DbValue, String> {
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
    .ok_or_else(|| format!("invalid value for additional field `{name}`"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdditionalFieldError {
    MissingRequired(String),
    NotInput(String),
    InvalidType(String),
}

impl AdditionalFieldError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::MissingRequired(name) => format!("missing required additional field `{name}`"),
            Self::NotInput(name) => format!("additional field `{name}` is not accepted as input"),
            Self::InvalidType(message) => message.clone(),
        }
    }
}

fn db_record_to_json(record: &DbRecord) -> Result<Value, OpenAuthError> {
    record
        .iter()
        .map(|(field, value)| db_value_to_json(value).map(|value| (field.clone(), value)))
        .collect::<Result<serde_json::Map<_, _>, _>>()
        .map(Value::Object)
}
