use rustauth_core::context::AuthContext;
use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::db::{
    DbAdapter, DbRecord, DbSchema, DbValue, Delete, FindMany, FindOne, SchemaTable, Update,
};
use rustauth_core::error::RustAuthError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

const PASSKEY_MODEL: &str = "passkey";

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

#[derive(Clone)]
pub struct PasskeyStore<'a> {
    adapter: &'a dyn DbAdapter,
    schema: DbSchema,
}

impl Passkey {
    /// Value for `excludeCredentials` during registration (full credential or legacy id).
    pub(crate) fn registration_exclude_value(&self) -> Value {
        if !self.webauthn_credential.is_null() {
            self.webauthn_credential.clone()
        } else {
            Value::String(self.credential_id.clone())
        }
    }

    /// Stored WebAuthn credential state for authentication ceremonies.
    ///
    /// Legacy rows without `webauthn_credential` JSON are rebuilt from the
    /// stored COSE public key and passkey metadata.
    pub(crate) fn authentication_credential_value(&self) -> Result<Option<Value>, RustAuthError> {
        if !self.webauthn_credential.is_null() {
            return Ok(Some(self.webauthn_credential.clone()));
        }
        crate::webauthn::legacy_passkey_credential_value(
            &self.credential_id,
            &self.public_key,
            self.counter,
            &self.device_type,
            self.backed_up,
            self.transports.as_deref(),
        )
        .map(Some)
    }
}

impl<'a> PasskeyStore<'a> {
    pub fn with_schema(adapter: &'a dyn DbAdapter, schema: DbSchema) -> Self {
        Self { adapter, schema }
    }

    pub fn from_context(context: &'a AuthContext) -> Result<Self, RustAuthError> {
        Ok(Self::with_schema(
            context.adapter_ref()?,
            context.db_schema.clone(),
        ))
    }

    /// Convenience alias for [`Self::from_context`].
    pub fn new(context: &'a AuthContext) -> Result<Self, RustAuthError> {
        Self::from_context(context)
    }

    fn passkeys(&self) -> Result<SchemaTable<'_>, RustAuthError> {
        SchemaTable::new(&self.schema, PASSKEY_MODEL)
    }

    fn parse_passkey(&self, record: DbRecord) -> Result<Passkey, RustAuthError> {
        passkey_from_record(self.passkeys()?.map_record(record)?)
    }

    pub async fn list_by_user(&self, user_id: &str) -> Result<Vec<Passkey>, RustAuthError> {
        let passkeys = self.passkeys()?;
        self.adapter
            .find_many(
                FindMany::new(passkeys.model()).where_clause(
                    passkeys.where_eq("user_id", DbValue::String(user_id.to_owned()))?,
                ),
            )
            .await?
            .into_iter()
            .map(|record| self.parse_passkey(record))
            .collect()
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<Passkey>, RustAuthError> {
        let passkeys = self.passkeys()?;
        self.adapter
            .find_one(
                FindOne::new(passkeys.model())
                    .where_clause(passkeys.where_eq("id", DbValue::String(id.to_owned()))?),
            )
            .await?
            .map(|record| self.parse_passkey(record))
            .transpose()
    }

    pub async fn find_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<Passkey>, RustAuthError> {
        let passkeys = self.passkeys()?;
        self.adapter
            .find_one(FindOne::new(passkeys.model()).where_clause(
                passkeys.where_eq("credential_id", DbValue::String(credential_id.to_owned()))?,
            ))
            .await?
            .map(|record| self.parse_passkey(record))
            .transpose()
    }

    pub async fn create(
        &self,
        user_id: &str,
        name: Option<String>,
        credential: crate::webauthn::VerifiedPasskeyCredential,
    ) -> Result<Passkey, RustAuthError> {
        let passkeys = self.passkeys()?;
        let now = OffsetDateTime::now_utc();
        let record = self
            .adapter
            .create(
                passkeys
                    .create()
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
        self.parse_passkey(record)
    }

    pub async fn update_name_for_user(
        &self,
        id: &str,
        user_id: &str,
        name: String,
    ) -> Result<Option<Passkey>, RustAuthError> {
        let passkeys = self.passkeys()?;
        self.adapter
            .update(
                Update::new(passkeys.model())
                    .where_clause(passkeys.where_eq("id", DbValue::String(id.to_owned()))?)
                    .where_clause(
                        passkeys.where_eq("user_id", DbValue::String(user_id.to_owned()))?,
                    )
                    .data("name", DbValue::String(name)),
            )
            .await?
            .map(|record| self.parse_passkey(record))
            .transpose()
    }

    pub async fn update_after_authentication(
        &self,
        id: &str,
        expected_counter: i64,
        verification: crate::webauthn::VerifiedAuthentication,
    ) -> Result<Option<Passkey>, RustAuthError> {
        let passkeys = self.passkeys()?;
        let mut update = Update::new(passkeys.model())
            .where_clause(passkeys.where_eq("id", DbValue::String(id.to_owned()))?)
            .where_clause(passkeys.where_eq("counter", DbValue::Number(expected_counter))?)
            .data(
                "counter",
                DbValue::Number(i64::from(verification.new_counter)),
            );
        if let Some(credential) = verification.credential {
            update = update.data("webauthn_credential", DbValue::Json(credential));
        }
        self.adapter
            .update(update)
            .await?
            .map(|record| self.parse_passkey(record))
            .transpose()
    }

    pub async fn delete_for_user(&self, id: &str, user_id: &str) -> Result<bool, RustAuthError> {
        let passkeys = self.passkeys()?;
        let Some(passkey) = self.find_by_id(id).await? else {
            return Ok(false);
        };
        if passkey.user_id != user_id {
            return Ok(false);
        }
        self.adapter
            .delete(
                Delete::new(passkeys.model())
                    .where_clause(passkeys.where_eq("id", DbValue::String(id.to_owned()))?),
            )
            .await?;
        Ok(true)
    }
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn passkey_from_record(record: DbRecord) -> Result<Passkey, RustAuthError> {
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

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

fn required_number(record: &DbRecord, field: &str) -> Result<i64, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Number(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "number")),
        None => Err(missing_field(field)),
    }
}

fn required_bool(record: &DbRecord, field: &str) -> Result<bool, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Boolean(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "boolean")),
        None => Err(missing_field(field)),
    }
}

fn optional_timestamp(
    record: &DbRecord,
    field: &str,
) -> Result<Option<OffsetDateTime>, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(Some(*value)),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "timestamp or null")),
    }
}

fn missing_field(field: &str) -> RustAuthError {
    RustAuthError::Adapter(format!("passkey record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> RustAuthError {
    RustAuthError::Adapter(format!("passkey record field `{field}` must be {expected}"))
}
