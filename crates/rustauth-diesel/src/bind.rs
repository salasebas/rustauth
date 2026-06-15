use rustauth_core::db::{DbFieldType, DbValue, SqlParam};
use rustauth_core::error::RustAuthError;
use time::OffsetDateTime;

#[cfg(feature = "mysql")]
pub use mysql::bind_mysql_params;
#[cfg(feature = "postgres")]
pub use postgres::bind_postgres_params;

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use diesel::pg::Pg;
    use diesel::query_builder::{BoxedSqlQuery, SqlQuery};
    use diesel::sql_query;
    use diesel::sql_types::{
        Array, BigInt, Bool, Jsonb, Nullable, Text, Timestamptz, Uuid as DieselUuid,
    };
    use rustauth_core::db::IdGeneration;

    pub fn bind_postgres_params<'f>(
        sql: &str,
        params: &[SqlParam],
    ) -> Result<BoxedSqlQuery<'f, Pg, SqlQuery>, RustAuthError> {
        let mut query = sql_query(sql).into_boxed::<Pg>();
        for param in params {
            query = bind_one(query, param)?;
        }
        Ok(query)
    }

    fn bind_one<'f>(
        query: BoxedSqlQuery<'f, Pg, SqlQuery>,
        param: &SqlParam,
    ) -> Result<BoxedSqlQuery<'f, Pg, SqlQuery>, RustAuthError> {
        match &param.value {
            DbValue::String(value) if param.generated_id == Some(IdGeneration::Uuid) => {
                let value = uuid::Uuid::parse_str(value).map_err(|error| {
                    RustAuthError::Adapter(format!("invalid postgres UUID: {error}"))
                })?;
                Ok(query.bind::<DieselUuid, _>(value))
            }
            DbValue::String(value) => Ok(query.bind::<Text, _>(value.clone())),
            DbValue::Number(value) => Ok(query.bind::<BigInt, _>(*value)),
            DbValue::Boolean(value) => Ok(query.bind::<Bool, _>(*value)),
            DbValue::Timestamp(value) => Ok(query.bind::<Timestamptz, _>(*value)),
            DbValue::Json(value) => Ok(query.bind::<Jsonb, _>(value.clone())),
            DbValue::StringArray(value) => Ok(query.bind::<Array<Text>, _>(value.clone())),
            DbValue::NumberArray(value) => Ok(query.bind::<Array<BigInt>, _>(value.clone())),
            DbValue::Record(_) | DbValue::RecordArray(_) => Err(RustAuthError::Adapter(
                "joined records cannot be bound as SQL values".to_owned(),
            )),
            DbValue::Null => bind_null(query, param),
        }
    }

    fn bind_null<'f>(
        query: BoxedSqlQuery<'f, Pg, SqlQuery>,
        param: &SqlParam,
    ) -> Result<BoxedSqlQuery<'f, Pg, SqlQuery>, RustAuthError> {
        match param.field_type {
            DbFieldType::String if param.generated_id == Some(IdGeneration::Uuid) => {
                Ok(query.bind::<Nullable<DieselUuid>, _>(None::<uuid::Uuid>))
            }
            DbFieldType::String => Ok(query.bind::<Nullable<Text>, _>(None::<String>)),
            DbFieldType::Number => Ok(query.bind::<Nullable<BigInt>, _>(None::<i64>)),
            DbFieldType::Boolean => Ok(query.bind::<Nullable<Bool>, _>(None::<bool>)),
            DbFieldType::Timestamp => {
                Ok(query.bind::<Nullable<Timestamptz>, _>(None::<OffsetDateTime>))
            }
            DbFieldType::Json => Ok(query.bind::<Nullable<Jsonb>, _>(None::<serde_json::Value>)),
            DbFieldType::StringArray => {
                Ok(query.bind::<Nullable<Array<Text>>, _>(None::<Vec<String>>))
            }
            DbFieldType::NumberArray => {
                Ok(query.bind::<Nullable<Array<BigInt>>, _>(None::<Vec<i64>>))
            }
        }
    }
}

#[cfg(feature = "mysql")]
mod mysql {
    use super::*;
    use diesel::mysql::Mysql;
    use diesel::query_builder::{BoxedSqlQuery, SqlQuery};
    use diesel::sql_query;
    use diesel::sql_types::{BigInt, Bool, Json, Nullable, Text, Timestamp};

    pub fn bind_mysql_params<'f>(
        sql: &str,
        params: &[SqlParam],
    ) -> Result<BoxedSqlQuery<'f, Mysql, SqlQuery>, RustAuthError> {
        let mut query = sql_query(sql).into_boxed::<Mysql>();
        for param in params {
            query = bind_one(query, param)?;
        }
        Ok(query)
    }

    fn bind_one<'f>(
        query: BoxedSqlQuery<'f, Mysql, SqlQuery>,
        param: &SqlParam,
    ) -> Result<BoxedSqlQuery<'f, Mysql, SqlQuery>, RustAuthError> {
        match &param.value {
            DbValue::String(value) => Ok(query.bind::<Text, _>(value.clone())),
            DbValue::Number(value) => Ok(query.bind::<BigInt, _>(*value)),
            DbValue::Boolean(value) => Ok(query.bind::<Bool, _>(*value)),
            DbValue::Timestamp(value) => Ok(query.bind::<Timestamp, _>(*value)),
            DbValue::Json(value) => Ok(query.bind::<Json, _>(value.clone())),
            DbValue::StringArray(value) => {
                let json = serde_json::Value::Array(
                    value
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                );
                Ok(query.bind::<Json, _>(json))
            }
            DbValue::NumberArray(value) => {
                let json = serde_json::Value::Array(
                    value.iter().copied().map(serde_json::Value::from).collect(),
                );
                Ok(query.bind::<Json, _>(json))
            }
            DbValue::Record(_) | DbValue::RecordArray(_) => Err(RustAuthError::Adapter(
                "joined records cannot be bound as SQL values".to_owned(),
            )),
            DbValue::Null => bind_null(query, param),
        }
    }

    fn bind_null<'f>(
        query: BoxedSqlQuery<'f, Mysql, SqlQuery>,
        param: &SqlParam,
    ) -> Result<BoxedSqlQuery<'f, Mysql, SqlQuery>, RustAuthError> {
        match param.field_type {
            DbFieldType::String => Ok(query.bind::<Nullable<Text>, _>(None::<String>)),
            DbFieldType::Number => Ok(query.bind::<Nullable<BigInt>, _>(None::<i64>)),
            DbFieldType::Boolean => Ok(query.bind::<Nullable<Bool>, _>(None::<bool>)),
            DbFieldType::Timestamp => {
                Ok(query.bind::<Nullable<Timestamp>, _>(None::<OffsetDateTime>))
            }
            DbFieldType::Json | DbFieldType::StringArray | DbFieldType::NumberArray => {
                Ok(query.bind::<Nullable<Json>, _>(None::<serde_json::Value>))
            }
        }
    }
}
