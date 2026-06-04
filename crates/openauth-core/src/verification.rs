//! Database-backed verification token/value helpers.

use time::OffsetDateTime;

use crate::context::AuthContext;
use crate::crypto::random::generate_random_string;
use crate::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, Sort, SortDirection,
    Update, Verification, Where, WhereOperator,
};
use crate::error::OpenAuthError;
use crate::options::{SecondaryStorage, StoreIdentifierOption, VerificationOptions};
use sha2::{Digest, Sha256};
use std::sync::Arc;

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

/// Transform a verification identifier according to configured storage options.
pub async fn process_verification_identifier(
    options: &VerificationOptions,
    identifier: &str,
) -> Result<String, OpenAuthError> {
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
    options: VerificationOptions,
}

impl<'a> DbVerificationStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self::with_options(adapter, VerificationOptions::default())
    }

    pub fn with_options(adapter: &'a dyn DbAdapter, options: VerificationOptions) -> Self {
        Self { adapter, options }
    }

    pub async fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> Result<Verification, OpenAuthError> {
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

        verification_from_record(record)
    }

    pub async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, OpenAuthError> {
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

        let verification = verification_from_record(record)?;
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
    ) -> Result<Option<Verification>, OpenAuthError> {
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
            .map(verification_from_record)
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
    ) -> Result<Option<Verification>, OpenAuthError> {
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
        let verification = verification_from_record(record)?;
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

    pub async fn update_verification(
        &self,
        identifier: &str,
        input: UpdateVerificationInput,
    ) -> Result<Option<Verification>, OpenAuthError> {
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
            .map(verification_from_record)
            .transpose()
    }

    pub async fn delete_verification(&self, identifier: &str) -> Result<(), OpenAuthError> {
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        self.adapter
            .delete(
                Delete::new(VERIFICATION_MODEL).where_clause(identifier_where(&stored_identifier)),
            )
            .await
    }

    pub async fn delete_expired_verifications(&self) -> Result<u64, OpenAuthError> {
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
    pub fn new(adapter: &'a dyn DbAdapter, context: &AuthContext) -> Self {
        let options = context.options.verification.clone();
        Self {
            database: DbVerificationStore::with_options(adapter, options.clone()),
            secondary_storage: context.secondary_storage(),
            options,
        }
    }

    pub async fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> Result<Verification, OpenAuthError> {
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
    ) -> Result<Option<Verification>, OpenAuthError> {
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
    ) -> Result<Option<Verification>, OpenAuthError> {
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
    ) -> Result<Option<Verification>, OpenAuthError> {
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

    pub async fn delete_verification(&self, identifier: &str) -> Result<(), OpenAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.delete_verification(identifier).await;
        };
        let stored_identifier = process_verification_identifier(&self.options, identifier).await?;
        storage.delete(&verification_key(&stored_identifier)).await
    }

    pub async fn delete_expired_verifications(&self) -> Result<u64, OpenAuthError> {
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
    ) -> Result<Option<Verification>, OpenAuthError> {
        storage
            .get(&verification_key(stored_identifier))
            .await?
            .map(|value| deserialize_verification(&value))
            .transpose()
    }
}

fn identifier_where(identifier: &str) -> Where {
    Where::new("identifier", DbValue::String(identifier.to_owned()))
}

fn verification_from_record(record: DbRecord) -> Result<Verification, OpenAuthError> {
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

fn serialize_verification(verification: &Verification) -> Result<String, OpenAuthError> {
    serde_json::to_string(verification).map_err(|error| OpenAuthError::Serialization {
        context: "serializing verification record",
        message: error.to_string(),
    })
}

fn deserialize_verification(value: &str) -> Result<Verification, OpenAuthError> {
    serde_json::from_str(value).map_err(|error| OpenAuthError::Serialization {
        context: "deserializing verification record",
        message: error.to_string(),
    })
}

fn ttl_seconds(expires_at: OffsetDateTime) -> Option<u64> {
    let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
    Some(u64::try_from(seconds.max(0)).unwrap_or(0))
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn required_timestamp(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        Some(_) => Err(invalid_field(field, "timestamp")),
        None => Err(missing_field(field)),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::MissingRecordField {
        record: "verification",
        field: field.to_owned(),
    }
}

fn invalid_field(field: &str, expected: &'static str) -> OpenAuthError {
    OpenAuthError::InvalidRecordField {
        record: "verification",
        field: field.to_owned(),
        expected,
    }
}
