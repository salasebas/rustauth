use openauth_core::db::{DbFieldType, DbValue, SqlParam};
use openauth_core::error::OpenAuthError;
use tokio_postgres::types::ToSql;

pub fn postgres_params(
    params: &[SqlParam],
) -> Result<Vec<Box<dyn ToSql + Sync + Send>>, OpenAuthError> {
    params.iter().map(postgres_param).collect()
}

pub fn param_refs(values: &[Box<dyn ToSql + Sync + Send>]) -> Vec<&(dyn ToSql + Sync)> {
    values
        .iter()
        .map(|value| &**value as &(dyn ToSql + Sync))
        .collect()
}

fn postgres_param(param: &SqlParam) -> Result<Box<dyn ToSql + Sync + Send>, OpenAuthError> {
    match &param.value {
        DbValue::String(value) => Ok(Box::new(value.clone())),
        DbValue::Number(value) => Ok(Box::new(*value)),
        DbValue::Boolean(value) => Ok(Box::new(*value)),
        DbValue::Timestamp(value) => Ok(Box::new(*value)),
        DbValue::Json(value) => Ok(Box::new(value.clone())),
        DbValue::StringArray(value) => Ok(Box::new(serde_json::Value::Array(
            value
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ))),
        DbValue::NumberArray(value) => Ok(Box::new(serde_json::Value::Array(
            value.iter().copied().map(serde_json::Value::from).collect(),
        ))),
        DbValue::Record(_) | DbValue::RecordArray(_) => Err(OpenAuthError::Adapter(
            "joined records cannot be bound as SQL values".to_owned(),
        )),
        DbValue::Null => match param.field_type {
            DbFieldType::String => Ok(Box::new(Option::<String>::None)),
            DbFieldType::Number => Ok(Box::new(Option::<i64>::None)),
            DbFieldType::Boolean => Ok(Box::new(Option::<bool>::None)),
            DbFieldType::Timestamp => Ok(Box::new(Option::<time::OffsetDateTime>::None)),
            DbFieldType::Json | DbFieldType::StringArray | DbFieldType::NumberArray => {
                Ok(Box::new(Option::<serde_json::Value>::None))
            }
        },
    }
}
