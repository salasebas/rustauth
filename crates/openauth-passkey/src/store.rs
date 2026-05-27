use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, FindMany, FindOne, Update, Where,
};
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub public_key: String,
    pub user_id: String,
    #[serde(rename = "credentialID")]
    pub credential_id: String,
    pub counter: i64,
    pub device_type: String,
    pub backed_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aaguid: Option<String>,
    #[serde(skip)]
    pub webauthn_credential: Value,
}

#[derive(Clone, Copy)]
pub struct PasskeyStore<'a> {
    adapter: &'a dyn DbAdapter,
}

impl<'a> PasskeyStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub async fn list_by_user(&self, user_id: &str) -> Result<Vec<Passkey>, OpenAuthError> {
        self.adapter
            .find_many(
                FindMany::new("passkey")
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await?
            .into_iter()
            .map(passkey_from_record)
            .collect()
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<Passkey>, OpenAuthError> {
        self.adapter
            .find_one(FindOne::new("passkey").where_clause(id_where(id)))
            .await?
            .map(passkey_from_record)
            .transpose()
    }

    pub async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<Passkey>, OpenAuthError> {
        self.adapter
            .find_one(FindOne::new("passkey").where_clause(Where::new(
                "credential_id",
                DbValue::String(credential_id.to_owned()),
            )))
            .await?
            .map(passkey_from_record)
            .transpose()
    }

    pub async fn create(
        &self,
        user_id: &str,
        name: Option<String>,
        credential: crate::webauthn::VerifiedPasskeyCredential,
    ) -> Result<Passkey, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let record = self
            .adapter
            .create(
                Create::new("passkey")
                    .data("id", DbValue::String(generate_random_string(32)))
                    .data("name", optional_string(name))
                    .data("public_key", DbValue::String(credential.public_key))
                    .data("user_id", DbValue::String(user_id.to_owned()))
                    .data("credential_id", DbValue::String(credential.credential_id))
                    .data("counter", DbValue::Number(i64::from(credential.counter)))
                    .data("device_type", DbValue::String(credential.device_type))
                    .data("backed_up", DbValue::Boolean(credential.backed_up))
                    .data("transports", optional_string(credential.transports))
                    .data("created_at", DbValue::Timestamp(now))
                    .data("aaguid", optional_string(credential.aaguid))
                    .data("webauthn_credential", DbValue::Json(credential.credential))
                    .force_allow_id(),
            )
            .await?;
        passkey_from_record(record)
    }

    pub async fn update_name_for_user(
        &self,
        id: &str,
        user_id: &str,
        name: String,
    ) -> Result<Option<Passkey>, OpenAuthError> {
        self.adapter
            .update(
                Update::new("passkey")
                    .where_clause(id_where(id))
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                    .data("name", DbValue::String(name)),
            )
            .await?
            .map(passkey_from_record)
            .transpose()
    }

    pub async fn update_after_authentication(
        &self,
        id: &str,
        verification: crate::webauthn::VerifiedAuthentication,
    ) -> Result<Option<Passkey>, OpenAuthError> {
        let mut update = Update::new("passkey").where_clause(id_where(id)).data(
            "counter",
            DbValue::Number(i64::from(verification.new_counter)),
        );
        if let Some(credential) = verification.credential {
            update = update.data("webauthn_credential", DbValue::Json(credential));
        }
        self.adapter
            .update(update)
            .await?
            .map(passkey_from_record)
            .transpose()
    }

    pub async fn delete_for_user(&self, id: &str, user_id: &str) -> Result<bool, OpenAuthError> {
        let Some(passkey) = self.find_by_id(id).await? else {
            return Ok(false);
        };
        if passkey.user_id != user_id {
            return Ok(false);
        }
        self.adapter
            .delete(Delete::new("passkey").where_clause(id_where(id)))
            .await?;
        Ok(true)
    }
}

fn id_where(id: &str) -> Where {
    Where::new("id", DbValue::String(id.to_owned()))
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn passkey_from_record(record: DbRecord) -> Result<Passkey, OpenAuthError> {
    Ok(Passkey {
        id: required_string(&record, "id")?.to_owned(),
        name: optional_string_field(&record, "name")?,
        public_key: required_string(&record, "public_key")?.to_owned(),
        user_id: required_string(&record, "user_id")?.to_owned(),
        credential_id: required_string(&record, "credential_id")?.to_owned(),
        counter: required_number(&record, "counter")?,
        device_type: required_string(&record, "device_type")?.to_owned(),
        backed_up: required_bool(&record, "backed_up")?,
        transports: optional_string_field(&record, "transports")?,
        created_at: optional_timestamp(&record, "created_at")?,
        aaguid: optional_string_field(&record, "aaguid")?,
        webauthn_credential: match record.get("webauthn_credential") {
            Some(DbValue::Json(value)) => value.clone(),
            Some(DbValue::Null) | None => Value::Null,
            Some(_) => return Err(invalid_field("webauthn_credential", "json")),
        },
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

fn required_number(record: &DbRecord, field: &str) -> Result<i64, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Number(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "number")),
        None => Err(missing_field(field)),
    }
}

fn required_bool(record: &DbRecord, field: &str) -> Result<bool, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "boolean")),
        None => Err(missing_field(field)),
    }
}

fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("passkey record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("passkey record field `{field}` must be {expected}"))
}
