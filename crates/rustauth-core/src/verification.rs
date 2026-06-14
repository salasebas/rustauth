//! Database-backed verification token/value helpers.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, LazyLock, Mutex as StdMutex};

use time::OffsetDateTime;

use crate::context::AuthContext;
use crate::crypto::random::generate_random_string;
use crate::db::{
    auth_schema, AuthSchemaOptions, Create, DbAdapter, DbRecord, DbSchema, DbValue, Delete,
    DeleteMany, FindMany, SchemaTable, Sort, SortDirection, TransactionAdapter, Update,
    Verification, Where, WhereOperator,
};
use crate::error::RustAuthError;
use crate::options::{SecondaryStorage, StoreIdentifierOption, VerificationOptions};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

const VERIFICATION_MODEL: &str = "verification";
const DEFAULT_ID_LENGTH: usize = 32;
const VERIFICATION_FIELDS: [&str; 6] = [
    "id",
    "identifier",
    "value",
    "expires_at",
    "created_at",
    "updated_at",
];

fn default_auth_schema() -> &'static DbSchema {
    static SCHEMA: LazyLock<DbSchema> = LazyLock::new(|| auth_schema(AuthSchemaOptions::default()));
    &SCHEMA
}

fn database_verification_store<'a>(
    context: &'a AuthContext,
    options: &VerificationOptions,
) -> Result<DbVerificationStore<'a>, RustAuthError> {
    if context.secondary_storage().is_some()
        && context.db_schema.table(VERIFICATION_MODEL).is_none()
    {
        return Ok(DbVerificationStore::with_default_schema(
            context.adapter_ref()?,
            options.clone(),
        ));
    }
    DbVerificationStore::from_context(context)
}

/// Transform a verification identifier according to configured storage options.
pub async fn process_verification_identifier(
    options: &VerificationOptions,
    identifier: &str,
) -> Result<String, RustAuthError> {
    match options.store_identifier.resolve(identifier) {
        StoreIdentifierOption::Plain => Ok(identifier.to_owned()),
        StoreIdentifierOption::Hashed => Ok(hash_verification_identifier(identifier)),
        StoreIdentifierOption::Custom(hash_fn) => hash_fn(identifier.to_owned()).await,
    }
}

fn hash_verification_identifier(identifier: &str) -> String {
    hex::encode(Sha256::digest(identifier.as_bytes()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateVerificationInput {
    pub id: Option<String>,
    pub identifier: String,
    pub value: String,
    pub expires_at: OffsetDateTime,
}

impl CreateVerificationInput {
    pub fn new(
        identifier: impl Into<String>,
        value: impl Into<String>,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            id: None,
            identifier: identifier.into(),
            value: value.into(),
            expires_at,
        }
    }

    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateVerificationInput {
    pub value: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
}

impl UpdateVerificationInput {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    #[must_use]
    pub fn expires_at(mut self, expires_at: OffsetDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

#[derive(Clone)]
pub struct DbVerificationStore<'a> {
    adapter: &'a dyn DbAdapter,
    schema: DbSchema,
    options: VerificationOptions,
}

impl<'a> DbVerificationStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self::with_options(
            adapter,
            default_auth_schema().clone(),
            VerificationOptions::default(),
        )
    }

    pub fn from_context(context: &'a AuthContext) -> Result<Self, RustAuthError> {
        Ok(Self::with_options(
            context.adapter_ref()?,
            context.db_schema.clone(),
            context.options.verification.clone(),
        ))
    }

    pub fn with_options(
        adapter: &'a dyn DbAdapter,
        schema: DbSchema,
        options: VerificationOptions,
    ) -> Self {
        Self {
            adapter,
            schema,
            options,
        }
    }

    pub fn with_default_schema(adapter: &'a dyn DbAdapter, options: VerificationOptions) -> Self {
        Self::with_options(adapter, default_auth_schema().clone(), options)
    }

    pub(super) fn adapter(&self) -> &dyn DbAdapter {
        self.adapter
    }

    fn verifications(&self) -> Result<SchemaTable<'_>, RustAuthError> {
        SchemaTable::new(&self.schema, VERIFICATION_MODEL)
    }

    fn parse_verification(&self, record: DbRecord) -> Result<Verification, RustAuthError> {
        verification_from_record(self.verifications()?.map_record(record)?)
    }

    pub async fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> Result<Verification, RustAuthError> {
        let stored_identifier =
            process_verification_identifier(&self.options, &input.identifier).await?;
        let now = OffsetDateTime::now_utc();
        let id = input
            .id
            .unwrap_or_else(|| generate_random_string(DEFAULT_ID_LENGTH));

        let record = self
            .adapter
            .create(
                Create::new(VERIFICATION_MODEL)
                    .data("id", DbValue::String(id))
                    .data("identifier", DbValue::String(stored_identifier))
                    .data("value", DbValue::String(input.value))
                    .data("expires_at", DbValue::Timestamp(input.expires_at))
                    .data("created_at", DbValue::Timestamp(now))
                    .data("updated_at", DbValue::Timestamp(now))
                    .select(VERIFICATION_FIELDS)
                    .force_allow_id(),
            )
            .await?;

        self.parse_verification(record)
    }

    pub async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        if !self.options.disable_cleanup {
            self.delete_expired_verifications().await?;
        }

        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        let Some(record) = self
            .adapter
            .find_many(
                FindMany::new(VERIFICATION_MODEL)
                    .where_clause(identifier_where(&stored_identifier))
                    .sort_by(Sort::new("created_at", SortDirection::Desc))
                    .limit(1)
                    .select(VERIFICATION_FIELDS),
            )
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };

        let verification = self.parse_verification(record)?;
        if verification.expires_at <= OffsetDateTime::now_utc() {
            if !self.options.disable_cleanup {
                self.delete_expired_verifications().await?;
            }
            return Ok(None);
        }

        Ok(Some(verification))
    }

    pub async fn find_verification_including_expired(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        self.adapter
            .find_many(
                FindMany::new(VERIFICATION_MODEL)
                    .where_clause(identifier_where(&stored_identifier))
                    .sort_by(Sort::new("created_at", SortDirection::Desc))
                    .limit(1)
                    .select(VERIFICATION_FIELDS),
            )
            .await?
            .into_iter()
            .next()
            .map(|record| self.parse_verification(record))
            .transpose()
    }

    /// Atomically consumes a verification record if present.
    ///
    /// Parallel callers racing on the same identifier only observe a successful
    /// consume once: the delete is keyed by both identifier and row id so later
    /// attempts delete zero rows and return `None`.
    pub async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        let Some(record) = self
            .adapter
            .find_many(
                FindMany::new(VERIFICATION_MODEL)
                    .where_clause(identifier_where(&stored_identifier))
                    .sort_by(Sort::new("created_at", SortDirection::Desc))
                    .limit(1)
                    .select(VERIFICATION_FIELDS),
            )
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let verification = self.parse_verification(record)?;
        let deleted = self
            .adapter
            .delete_many(
                DeleteMany::new(VERIFICATION_MODEL)
                    .where_clause(identifier_where(&stored_identifier))
                    .where_clause(Where::new("id", DbValue::String(verification.id.clone()))),
            )
            .await?;
        if deleted == 0 {
            return Ok(None);
        }
        Ok(Some(verification))
    }

    /// Atomically updates a verification row only when its stored value is unchanged.
    ///
    /// Parallel callers racing on the same identifier can use this as a compare-and-swap
    /// boundary when incrementing attempt counters or other value-encoded state.
    pub async fn compare_and_update_verification_value(
        &self,
        identifier: &str,
        verification_id: &str,
        expected_value: &str,
        new_value: String,
    ) -> Result<Option<Verification>, RustAuthError> {
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        self.adapter
            .update(
                Update::new(VERIFICATION_MODEL)
                    .where_clause(identifier_where(&stored_identifier))
                    .where_clause(Where::new(
                        "id",
                        DbValue::String(verification_id.to_owned()),
                    ))
                    .where_clause(Where::new(
                        "value",
                        DbValue::String(expected_value.to_owned()),
                    ))
                    .data("value", DbValue::String(new_value))
                    .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?
            .map(|record| self.parse_verification(record))
            .transpose()
    }

    pub async fn update_verification(
        &self,
        identifier: &str,
        input: UpdateVerificationInput,
    ) -> Result<Option<Verification>, RustAuthError> {
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        let mut query =
            Update::new(VERIFICATION_MODEL).where_clause(identifier_where(&stored_identifier));

        if let Some(value) = input.value {
            query = query.data("value", DbValue::String(value));
        }
        if let Some(expires_at) = input.expires_at {
            query = query.data("expires_at", DbValue::Timestamp(expires_at));
        }
        query = query.data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()));

        self.adapter
            .update(query)
            .await?
            .map(|record| self.parse_verification(record))
            .transpose()
    }

    pub async fn delete_verification(&self, identifier: &str) -> Result<(), RustAuthError> {
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        self.adapter
            .delete(
                Delete::new(VERIFICATION_MODEL).where_clause(identifier_where(&stored_identifier)),
            )
            .await
    }

    /// Remove and return an active verification, if one exists.
    ///
    /// This enforces single-use semantics for challenge-like tokens: concurrent
    /// callers only observe the stored value once.
    pub async fn take_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        if self.adapter.capabilities().supports_transactions {
            let options = self.options.clone();
            let schema = self.schema.clone();
            let identifier = identifier.to_owned();
            let taken = Arc::new(Mutex::new(None));
            let taken_capture = Arc::clone(&taken);
            self.adapter
                .transaction(Box::new(move |transaction: TransactionAdapter<'_>| {
                    let taken = Arc::clone(&taken_capture);
                    let options = options.clone();
                    let schema = schema.clone();
                    let identifier = identifier.clone();
                    Box::pin(async move {
                        let store = DbVerificationStore::with_options(
                            transaction.as_ref(),
                            schema,
                            options,
                        );
                        if let Some(verification) = store.find_verification(&identifier).await? {
                            if verification.expires_at > OffsetDateTime::now_utc() {
                                store.delete_verification(&identifier).await?;
                                *taken.lock().await = Some(verification);
                            }
                        }
                        Ok(())
                    })
                }))
                .await?;
            return Ok(taken.lock().await.take());
        }

        let take_lock = verification_take_lock(self.adapter, &stored_identifier)?;
        let _guard = take_lock.lock().await;
        let Some(verification) = self.find_verification(identifier).await? else {
            return Ok(None);
        };
        self.delete_verification(identifier).await?;
        Ok(Some(verification))
    }

    pub async fn take_verification_including_expired(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        self.consume_verification_including_expired(identifier)
            .await
    }

    pub async fn delete_expired_verifications(&self) -> Result<u64, RustAuthError> {
        if self.options.disable_cleanup {
            return Ok(0);
        }
        self.adapter
            .delete_many(
                DeleteMany::new(VERIFICATION_MODEL).where_clause(
                    Where::new("expires_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
                        .operator(WhereOperator::Lt),
                ),
            )
            .await
    }
}

/// Verification store that uses configured secondary storage when present.
#[derive(Clone)]
pub struct VerificationStore<'a> {
    database: DbVerificationStore<'a>,
    secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    options: VerificationOptions,
}

impl<'a> VerificationStore<'a> {
    pub fn new(context: &'a AuthContext) -> Result<Self, RustAuthError> {
        let options = context.options.verification.clone();
        Ok(Self {
            database: database_verification_store(context, &options)?,
            secondary_storage: context.secondary_storage(),
            options,
        })
    }

    pub async fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> Result<Verification, RustAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.create_verification(input).await;
        };
        let stored_identifier =
            process_verification_identifier(&self.options, &input.identifier).await?;
        let now = OffsetDateTime::now_utc();
        let verification = Verification {
            id: input
                .id
                .unwrap_or_else(|| generate_random_string(DEFAULT_ID_LENGTH)),
            identifier: stored_identifier,
            value: input.value,
            expires_at: input.expires_at,
            created_at: now,
            updated_at: now,
        };
        storage
            .set(
                &verification_key(&verification.identifier),
                serialize_verification(&verification)?,
                ttl_seconds(verification.expires_at),
            )
            .await?;
        Ok(verification)
    }

    pub async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.find_verification(identifier).await;
        };
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        let Some(verification) = self
            .find_secondary_verification(storage.as_ref(), &stored_identifier)
            .await?
        else {
            return Ok(None);
        };
        if verification.expires_at <= OffsetDateTime::now_utc() {
            storage
                .delete(&verification_key(&stored_identifier))
                .await?;
            return Ok(None);
        }
        Ok(Some(verification))
    }

    pub async fn find_verification_including_expired(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self
                .database
                .find_verification_including_expired(identifier)
                .await;
        };
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        self.find_secondary_verification(storage.as_ref(), &stored_identifier)
            .await
    }

    pub async fn update_verification(
        &self,
        identifier: &str,
        input: UpdateVerificationInput,
    ) -> Result<Option<Verification>, RustAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.update_verification(identifier, input).await;
        };
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        let Some(mut verification) = self
            .find_secondary_verification(storage.as_ref(), &stored_identifier)
            .await?
        else {
            return Ok(None);
        };
        if let Some(value) = input.value {
            verification.value = value;
        }
        if let Some(expires_at) = input.expires_at {
            verification.expires_at = expires_at;
        }
        verification.updated_at = OffsetDateTime::now_utc();
        storage
            .set(
                &verification_key(&stored_identifier),
                serialize_verification(&verification)?,
                ttl_seconds(verification.expires_at),
            )
            .await?;
        Ok(Some(verification))
    }

    pub async fn delete_verification(&self, identifier: &str) -> Result<(), RustAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.delete_verification(identifier).await;
        };
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        storage.delete(&verification_key(&stored_identifier)).await
    }

    pub async fn take_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.take_verification(identifier).await;
        };
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        let Some(raw) = storage.take(&verification_key(&stored_identifier)).await? else {
            return Ok(None);
        };
        let verification = deserialize_verification(&raw)?;
        if verification.expires_at <= OffsetDateTime::now_utc() {
            return Ok(None);
        }
        Ok(Some(verification))
    }

    pub async fn take_verification_including_expired(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        self.consume_verification_including_expired(identifier)
            .await
    }

    /// Remove and return a verification without filtering on expiry.
    ///
    /// Parallel callers only observe a successful consume once. Prefer this over
    /// [`Self::take_verification_including_expired`] when the name should match
    /// database-only call sites.
    pub async fn consume_verification_including_expired(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self
                .database
                .consume_verification_including_expired(identifier)
                .await;
        };
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        let Some(raw) = storage.take(&verification_key(&stored_identifier)).await? else {
            return Ok(None);
        };
        deserialize_verification(&raw).map(Some)
    }

    /// Atomically updates a verification value only when its stored payload is unchanged.
    pub async fn compare_and_update_verification_value(
        &self,
        identifier: &str,
        verification_id: &str,
        expected_value: &str,
        new_value: String,
    ) -> Result<Option<Verification>, RustAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self
                .database
                .compare_and_update_verification_value(
                    identifier,
                    verification_id,
                    expected_value,
                    new_value,
                )
                .await;
        };
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        let take_lock = verification_take_lock(self.database.adapter(), &stored_identifier)?;
        let _guard = take_lock.lock().await;
        let key = verification_key(&stored_identifier);
        let Some(raw) = storage.get(&key).await? else {
            return Ok(None);
        };
        let verification = deserialize_verification(&raw)?;
        if verification.id != verification_id || verification.value != expected_value {
            return Ok(None);
        }
        let mut updated = verification;
        updated.value = new_value;
        updated.updated_at = OffsetDateTime::now_utc();
        storage
            .set(
                &key,
                serialize_verification(&updated)?,
                ttl_seconds(updated.expires_at),
            )
            .await?;
        Ok(Some(updated))
    }

    pub async fn delete_expired_verifications(&self) -> Result<u64, RustAuthError> {
        if self.options.disable_cleanup {
            return Ok(0);
        }
        let Some(_storage) = &self.secondary_storage else {
            return self.database.delete_expired_verifications().await;
        };
        Ok(0)
    }

    async fn find_secondary_verification(
        &self,
        storage: &dyn SecondaryStorage,
        stored_identifier: &str,
    ) -> Result<Option<Verification>, RustAuthError> {
        storage
            .get(&verification_key(stored_identifier))
            .await?
            .map(|value| deserialize_verification(&value))
            .transpose()
    }
}

static VERIFICATION_TAKE_LOCKS: LazyLock<StdMutex<HashMap<u64, Arc<Mutex<()>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

fn verification_take_lock(
    adapter: &dyn DbAdapter,
    stored_identifier: &str,
) -> Result<Arc<Mutex<()>>, RustAuthError> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (adapter as *const dyn DbAdapter).hash(&mut hasher);
    stored_identifier.hash(&mut hasher);
    let key = hasher.finish();
    let mut table = VERIFICATION_TAKE_LOCKS
        .lock()
        .map_err(|_| RustAuthError::LockPoisoned {
            context: "verification take lock table",
        })?;
    Ok(table
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone())
}

fn identifier_where(identifier: &str) -> Where {
    Where::new("identifier", DbValue::String(identifier.to_owned()))
}

fn verification_from_record(record: DbRecord) -> Result<Verification, RustAuthError> {
    Ok(Verification {
        id: required_string(&record, "id")?.to_owned(),
        identifier: required_string(&record, "identifier")?.to_owned(),
        value: required_string(&record, "value")?.to_owned(),
        expires_at: required_timestamp(&record, "expires_at")?,
        created_at: required_timestamp(&record, "created_at")?,
        updated_at: required_timestamp(&record, "updated_at")?,
    })
}

fn verification_key(identifier: &str) -> String {
    format!("verification:{identifier}")
}

fn serialize_verification(verification: &Verification) -> Result<String, RustAuthError> {
    serde_json::to_string(verification).map_err(|error| RustAuthError::Serialization {
        context: "serializing verification record",
        message: error.to_string(),
    })
}

fn deserialize_verification(value: &str) -> Result<Verification, RustAuthError> {
    serde_json::from_str(value).map_err(|error| RustAuthError::Serialization {
        context: "deserializing verification record",
        message: error.to_string(),
    })
}

fn ttl_seconds(expires_at: OffsetDateTime) -> Option<u64> {
    let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
    Some(u64::try_from(seconds.max(0)).unwrap_or(0))
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, RustAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

fn missing_field(field: &str) -> RustAuthError {
    RustAuthError::MissingRecordField {
        record: "verification",
        field: field.to_owned(),
    }
}

fn invalid_field(field: &str, expected: &'static str) -> RustAuthError {
    RustAuthError::InvalidRecordField {
        record: "verification",
        field: field.to_owned(),
        expected,
    }
}
