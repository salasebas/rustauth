//! Database-backed verification token/value helpers.

use time::OffsetDateTime;

use crate::crypto::random::generate_random_string;
use crate::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, Sort, SortDirection,
    Update, Verification, Where, WhereOperator,
};
use crate::error::OpenAuthError;

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

#[derive(Clone, Copy)]
pub struct DbVerificationStore<'a> {
    adapter: &'a dyn DbAdapter,
}

impl<'a> DbVerificationStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub async fn create_verification(
        &self,
        input: CreateVerificationInput,
    ) -> Result<Verification, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let id = input
            .id
            .unwrap_or_else(|| generate_random_string(DEFAULT_ID_LENGTH));

        let record = self
            .adapter
            .create(
                Create::new(VERIFICATION_MODEL)
                    .data("id", DbValue::String(id))
                    .data("identifier", DbValue::String(input.identifier))
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
        self.delete_expired_verifications().await?;

        let Some(record) = self
            .adapter
            .find_many(
                FindMany::new(VERIFICATION_MODEL)
                    .where_clause(identifier_where(identifier))
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
            self.delete_expired_verifications().await?;
            return Ok(None);
        }

        Ok(Some(verification))
    }

    pub async fn find_verification_including_expired(
        &self,
        identifier: &str,
    ) -> Result<Option<Verification>, OpenAuthError> {
        self.adapter
            .find_many(
                FindMany::new(VERIFICATION_MODEL)
                    .where_clause(identifier_where(identifier))
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

    pub async fn update_verification(
        &self,
        identifier: &str,
        input: UpdateVerificationInput,
    ) -> Result<Option<Verification>, OpenAuthError> {
        let mut query = Update::new(VERIFICATION_MODEL).where_clause(identifier_where(identifier));

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
        self.adapter
            .delete(Delete::new(VERIFICATION_MODEL).where_clause(identifier_where(identifier)))
            .await
    }

    pub async fn delete_expired_verifications(&self) -> Result<u64, OpenAuthError> {
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
    OpenAuthError::Adapter(format!("verification record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!(
        "verification record field `{field}` must be {expected}"
    ))
}
