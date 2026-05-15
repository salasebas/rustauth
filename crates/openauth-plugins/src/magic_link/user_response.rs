use std::collections::BTreeMap;

use openauth_core::context::AuthContext;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindOne, User, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::options::UserAdditionalField;
use serde_json::{Map, Value};

pub(crate) fn additional_user_create_values(context: &AuthContext) -> DbRecord {
    context
        .options
        .user
        .additional_fields
        .iter()
        .map(|(name, field)| {
            (
                name.clone(),
                field.default_value.clone().unwrap_or(DbValue::Null),
            )
        })
        .collect()
}

pub(crate) async fn user_response_value(
    adapter: &dyn DbAdapter,
    context: &AuthContext,
    user: &User,
) -> Result<Value, OpenAuthError> {
    let mut value =
        serde_json::to_value(user).map_err(|error| OpenAuthError::Api(error.to_string()))?;
    let Value::Object(object) = &mut value else {
        return Ok(value);
    };
    let record = adapter
        .find_one(
            FindOne::new("user").where_clause(Where::new("id", DbValue::String(user.id.clone()))),
        )
        .await?;
    insert_returned_user_fields(
        object,
        &context.options.user.additional_fields,
        record.as_ref(),
    )?;
    Ok(value)
}

fn insert_returned_user_fields(
    object: &mut Map<String, Value>,
    fields: &BTreeMap<String, UserAdditionalField>,
    record: Option<&DbRecord>,
) -> Result<(), OpenAuthError> {
    for (name, field) in fields {
        if !field.returned {
            continue;
        }
        let value = record
            .and_then(|record| record.get(name))
            .or(field.default_value.as_ref())
            .unwrap_or(&DbValue::Null);
        object.insert(name.clone(), db_value_to_json(value)?);
    }
    Ok(())
}

fn db_value_to_json(value: &DbValue) -> Result<Value, OpenAuthError> {
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

fn db_record_to_json(record: &DbRecord) -> Result<Value, OpenAuthError> {
    record
        .iter()
        .map(|(field, value)| db_value_to_json(value).map(|value| (field.clone(), value)))
        .collect::<Result<Map<_, _>, _>>()
        .map(Value::Object)
}
