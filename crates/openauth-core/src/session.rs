//! Database-backed session lifecycle helpers.

use time::OffsetDateTime;

use crate::crypto::random::generate_random_string;
use crate::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, Session, Update,
    Where,
};
use crate::error::OpenAuthError;

const SESSION_MODEL: &str = "session";
const SESSION_FIELDS: [&str; 8] = [
    "id",
    "user_id",
    "expires_at",
    "token",
    "ip_address",
    "user_agent",
    "created_at",
    "updated_at",
];
const DEFAULT_SESSION_ID_LENGTH: usize = 32;
const DEFAULT_SESSION_TOKEN_LENGTH: usize = 32;

/// Input for creating a persisted session.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateSessionInput {
    pub id: Option<String>,
    pub user_id: String,
    pub expires_at: OffsetDateTime,
    pub token: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub additional_fields: DbRecord,
}

impl CreateSessionInput {
    pub fn new(user_id: impl Into<String>, expires_at: OffsetDateTime) -> Self {
        Self {
            id: None,
            user_id: user_id.into(),
            expires_at,
            token: None,
            ip_address: None,
            user_agent: None,
            additional_fields: DbRecord::new(),
        }
    }

    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    #[must_use]
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    #[must_use]
    pub fn ip_address(mut self, ip_address: impl Into<String>) -> Self {
        self.ip_address = Some(ip_address.into());
        self
    }

    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    #[must_use]
    pub fn additional_fields(mut self, additional_fields: DbRecord) -> Self {
        self.additional_fields = additional_fields;
        self
    }
}

/// Session store backed by the OpenAuth adapter contract.
#[derive(Clone, Copy)]
pub struct DbSessionStore<'a> {
    adapter: &'a dyn DbAdapter,
}

impl<'a> DbSessionStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub async fn create_session(
        &self,
        input: CreateSessionInput,
    ) -> Result<Session, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let id = input
            .id
            .unwrap_or_else(|| generate_random_string(DEFAULT_SESSION_ID_LENGTH));
        let token = input
            .token
            .unwrap_or_else(|| generate_random_string(DEFAULT_SESSION_TOKEN_LENGTH));

        let mut query = Create::new(SESSION_MODEL)
            .data("id", DbValue::String(id))
            .data("user_id", DbValue::String(input.user_id))
            .data("expires_at", DbValue::Timestamp(input.expires_at))
            .data("token", DbValue::String(token))
            .data("ip_address", optional_string(input.ip_address))
            .data("user_agent", optional_string(input.user_agent))
            .data("created_at", DbValue::Timestamp(now))
            .data("updated_at", DbValue::Timestamp(now))
            .select(SESSION_FIELDS)
            .force_allow_id();
        for (field, value) in input.additional_fields {
            query = query.data(field, value);
        }

        let record = self.adapter.create(query).await?;

        session_from_record(record)
    }

    pub async fn find_session(&self, token: &str) -> Result<Option<Session>, OpenAuthError> {
        let Some(session) = self.find_session_including_expired(token).await? else {
            return Ok(None);
        };

        if session.expires_at <= OffsetDateTime::now_utc() {
            return Ok(None);
        }

        Ok(Some(session))
    }

    pub async fn find_session_including_expired(
        &self,
        token: &str,
    ) -> Result<Option<Session>, OpenAuthError> {
        self.adapter
            .find_one(
                FindOne::new(SESSION_MODEL)
                    .where_clause(token_where(token))
                    .select(SESSION_FIELDS),
            )
            .await?
            .map(session_from_record)
            .transpose()
    }

    pub async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Option<Session>, OpenAuthError> {
        let record = self
            .adapter
            .update(
                Update::new(SESSION_MODEL)
                    .where_clause(token_where(token))
                    .data("expires_at", DbValue::Timestamp(expires_at))
                    .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
            )
            .await?;

        record.map(session_from_record).transpose()
    }

    pub async fn delete_session(&self, token: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(Delete::new(SESSION_MODEL).where_clause(token_where(token)))
            .await
    }

    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<u64, OpenAuthError> {
        self.adapter
            .delete_many(
                DeleteMany::new(SESSION_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await
    }

    pub async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        self.adapter
            .find_many(
                FindMany::new(SESSION_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                    .select(SESSION_FIELDS),
            )
            .await?
            .into_iter()
            .map(session_from_record)
            .filter_map(|result| match result {
                Ok(session) if session.expires_at > now => Some(Ok(session)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn token_where(token: &str) -> Where {
    Where::new("token", DbValue::String(token.to_owned()))
}

fn session_from_record(record: DbRecord) -> Result<Session, OpenAuthError> {
    Ok(Session {
        id: required_string(&record, "id")?.to_owned(),
        user_id: required_string(&record, "user_id")?.to_owned(),
        expires_at: required_timestamp(&record, "expires_at")?,
        token: required_string(&record, "token")?.to_owned(),
        ip_address: optional_string_field(&record, "ip_address")?,
        user_agent: optional_string_field(&record, "user_agent")?,
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

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
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
    OpenAuthError::Adapter(format!("session record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("session record field `{field}` must be {expected}"))
}
