//! Database-backed session lifecycle helpers.

use time::OffsetDateTime;

use crate::context::AuthContext;
use crate::crypto::random::generate_random_string;
use crate::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, Session, Update,
    UpdateMany, Where, WhereOperator,
};
use crate::error::OpenAuthError;
use crate::options::SecondaryStorage;
use std::sync::Arc;

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
    pub fn additional_fields_with(mut self, additional_fields: DbRecord) -> Self {
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

    pub async fn find_sessions<I, S>(&self, tokens: I) -> Result<Vec<Session>, OpenAuthError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let tokens = tokens
            .into_iter()
            .map(|token| token.as_ref().to_owned())
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        let now = OffsetDateTime::now_utc();
        self.adapter
            .find_many(
                FindMany::new(SESSION_MODEL)
                    .where_clause(
                        Where::new("token", DbValue::StringArray(tokens))
                            .operator(WhereOperator::In),
                    )
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

    pub async fn refresh_user_sessions(&self, user_id: &str) -> Result<u64, OpenAuthError> {
        self.adapter
            .update_many(
                UpdateMany::new(SESSION_MODEL)
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                    .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc())),
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

/// Session store that uses configured secondary storage when present.
#[derive(Clone)]
pub struct SessionStore<'a> {
    database: DbSessionStore<'a>,
    secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    store_session_in_database: bool,
    preserve_session_in_database: bool,
}

impl<'a> SessionStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter, context: &AuthContext) -> Self {
        Self::with_storage(
            adapter,
            context.secondary_storage(),
            context.options.session.store_session_in_database,
            context.options.session.preserve_session_in_database,
        )
    }

    pub fn with_storage(
        adapter: &'a dyn DbAdapter,
        secondary_storage: Option<Arc<dyn SecondaryStorage>>,
        store_session_in_database: bool,
        preserve_session_in_database: bool,
    ) -> Self {
        Self {
            database: DbSessionStore::new(adapter),
            secondary_storage,
            store_session_in_database,
            preserve_session_in_database,
        }
    }

    pub async fn create_session(
        &self,
        input: CreateSessionInput,
    ) -> Result<Session, OpenAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.create_session(input).await;
        };
        let session = if self.store_session_in_database {
            self.database.create_session(input).await?
        } else {
            session_from_input(input)
        };
        self.set_secondary_session(storage.as_ref(), &session)
            .await?;
        self.add_user_session_token(storage.as_ref(), &session)
            .await?;
        Ok(session)
    }

    pub async fn find_session(&self, token: &str) -> Result<Option<Session>, OpenAuthError> {
        let Some(session) = self.find_session_including_expired(token).await? else {
            return Ok(None);
        };
        if session.expires_at <= OffsetDateTime::now_utc() {
            self.delete_session(token).await?;
            return Ok(None);
        }
        Ok(Some(session))
    }

    pub async fn find_session_including_expired(
        &self,
        token: &str,
    ) -> Result<Option<Session>, OpenAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.find_session_including_expired(token).await;
        };
        match self.find_secondary_session(storage.as_ref(), token).await? {
            Some(session) => Ok(Some(session)),
            None if self.store_session_in_database => {
                self.database.find_session_including_expired(token).await
            }
            None => Ok(None),
        }
    }

    pub async fn find_sessions<I, S>(&self, tokens: I) -> Result<Vec<Session>, OpenAuthError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let tokens = tokens
            .into_iter()
            .map(|token| token.as_ref().to_owned())
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        let Some(storage) = &self.secondary_storage else {
            return self.database.find_sessions(tokens).await;
        };
        let now = OffsetDateTime::now_utc();
        let mut sessions = Vec::new();
        let mut missing_tokens = Vec::new();
        for token in tokens {
            let Some(session) = self
                .find_secondary_session(storage.as_ref(), &token)
                .await?
            else {
                missing_tokens.push(token);
                continue;
            };
            if session.expires_at > now {
                sessions.push(session);
            } else {
                storage.delete(&session_key(&token)).await?;
            }
        }
        if self.store_session_in_database && !missing_tokens.is_empty() {
            sessions.extend(self.database.find_sessions(missing_tokens).await?);
        }
        Ok(sessions)
    }

    pub async fn update_session_expiry(
        &self,
        token: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Option<Session>, OpenAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.update_session_expiry(token, expires_at).await;
        };
        let Some(mut session) = self.find_session_including_expired(token).await? else {
            return Ok(None);
        };
        session.expires_at = expires_at;
        session.updated_at = OffsetDateTime::now_utc();
        self.set_secondary_session(storage.as_ref(), &session)
            .await?;
        let tokens = self
            .user_session_tokens(storage.as_ref(), &session.user_id)
            .await?;
        self.set_user_session_tokens(storage.as_ref(), &session.user_id, &tokens)
            .await?;
        if self.store_session_in_database {
            let _updated = self
                .database
                .update_session_expiry(token, expires_at)
                .await?;
        }
        Ok(Some(session))
    }

    pub async fn delete_session(&self, token: &str) -> Result<(), OpenAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.delete_session(token).await;
        };
        if let Some(session) = self.find_secondary_session(storage.as_ref(), token).await? {
            self.remove_user_session_token(storage.as_ref(), &session.user_id, token)
                .await?;
        }
        storage.delete(&session_key(token)).await?;
        if self.store_session_in_database && !self.preserve_session_in_database {
            self.database.delete_session(token).await?;
        }
        Ok(())
    }

    pub async fn delete_user_sessions(&self, user_id: &str) -> Result<u64, OpenAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.delete_user_sessions(user_id).await;
        };
        let tokens = self.user_session_tokens(storage.as_ref(), user_id).await?;
        let mut deleted = 0;
        for token in &tokens {
            if self
                .find_secondary_session(storage.as_ref(), token)
                .await?
                .is_some()
            {
                deleted += 1;
            }
            storage.delete(&session_key(token)).await?;
        }
        storage.delete(&user_sessions_key(user_id)).await?;
        if self.store_session_in_database && !self.preserve_session_in_database {
            self.database.delete_user_sessions(user_id).await?;
        }
        Ok(deleted)
    }

    pub async fn refresh_user_sessions(&self, user_id: &str) -> Result<u64, OpenAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.refresh_user_sessions(user_id).await;
        };
        let tokens = self.user_session_tokens(storage.as_ref(), user_id).await?;
        let now = OffsetDateTime::now_utc();
        let mut refreshed = 0;
        for token in &tokens {
            let Some(mut session) = self.find_secondary_session(storage.as_ref(), token).await?
            else {
                continue;
            };
            if session.expires_at <= now {
                storage.delete(&session_key(&session.token)).await?;
                continue;
            }
            session.updated_at = now;
            self.set_secondary_session(storage.as_ref(), &session)
                .await?;
            refreshed += 1;
        }
        self.set_user_session_tokens(storage.as_ref(), user_id, &tokens)
            .await?;
        if self.store_session_in_database {
            self.database.refresh_user_sessions(user_id).await?;
        }
        Ok(refreshed)
    }

    pub async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, OpenAuthError> {
        let Some(storage) = &self.secondary_storage else {
            return self.database.list_user_sessions(user_id).await;
        };
        let tokens = self.user_session_tokens(storage.as_ref(), user_id).await?;
        let now = OffsetDateTime::now_utc();
        let mut sessions = Vec::new();
        let mut active_tokens = Vec::new();
        for token in tokens {
            let Some(session) = self
                .find_secondary_session(storage.as_ref(), &token)
                .await?
            else {
                continue;
            };
            if session.expires_at > now {
                active_tokens.push(token);
                sessions.push(session);
            } else {
                storage.delete(&session_key(&token)).await?;
            }
        }
        self.set_user_session_tokens(storage.as_ref(), user_id, &active_tokens)
            .await?;
        if sessions.is_empty() && self.store_session_in_database {
            return self.database.list_user_sessions(user_id).await;
        }
        Ok(sessions)
    }

    async fn set_secondary_session(
        &self,
        storage: &dyn SecondaryStorage,
        session: &Session,
    ) -> Result<(), OpenAuthError> {
        storage
            .set(
                &session_key(&session.token),
                serialize_session(session)?,
                ttl_seconds(session.expires_at),
            )
            .await
    }

    async fn find_secondary_session(
        &self,
        storage: &dyn SecondaryStorage,
        token: &str,
    ) -> Result<Option<Session>, OpenAuthError> {
        storage
            .get(&session_key(token))
            .await?
            .map(|value| deserialize_session(&value))
            .transpose()
    }

    async fn add_user_session_token(
        &self,
        storage: &dyn SecondaryStorage,
        session: &Session,
    ) -> Result<(), OpenAuthError> {
        let mut tokens = self
            .user_session_tokens(storage, &session.user_id)
            .await?
            .into_iter()
            .filter(|token| token != &session.token)
            .collect::<Vec<_>>();
        tokens.push(session.token.clone());
        self.set_user_session_tokens(storage, &session.user_id, &tokens)
            .await
    }

    async fn remove_user_session_token(
        &self,
        storage: &dyn SecondaryStorage,
        user_id: &str,
        token: &str,
    ) -> Result<(), OpenAuthError> {
        let tokens = self
            .user_session_tokens(storage, user_id)
            .await?
            .into_iter()
            .filter(|stored| stored != token)
            .collect::<Vec<_>>();
        self.set_user_session_tokens(storage, user_id, &tokens)
            .await
    }

    async fn user_session_tokens(
        &self,
        storage: &dyn SecondaryStorage,
        user_id: &str,
    ) -> Result<Vec<String>, OpenAuthError> {
        storage
            .get(&user_sessions_key(user_id))
            .await?
            .map(|value| deserialize_user_session_tokens(&value))
            .transpose()
            .map(|tokens| tokens.unwrap_or_default())
    }

    async fn set_user_session_tokens(
        &self,
        storage: &dyn SecondaryStorage,
        user_id: &str,
        tokens: &[String],
    ) -> Result<(), OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let mut active_tokens = Vec::with_capacity(tokens.len());
        let mut furthest_expiry = None;

        for token in tokens {
            let Some(session) = self.find_secondary_session(storage, token).await? else {
                continue;
            };
            if session.expires_at <= now {
                storage.delete(&session_key(token)).await?;
                continue;
            }
            active_tokens.push(token.clone());
            furthest_expiry = Some(match furthest_expiry {
                Some(current) if current >= session.expires_at => current,
                _ => session.expires_at,
            });
        }

        if active_tokens.is_empty() {
            return storage.delete(&user_sessions_key(user_id)).await;
        }

        let ttl = furthest_expiry.and_then(index_ttl_seconds);
        storage
            .set(
                &user_sessions_key(user_id),
                serialize_user_session_tokens(&active_tokens)?,
                ttl,
            )
            .await
    }
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn session_from_input(input: CreateSessionInput) -> Session {
    let now = OffsetDateTime::now_utc();
    Session {
        id: input
            .id
            .unwrap_or_else(|| generate_random_string(DEFAULT_SESSION_ID_LENGTH)),
        user_id: input.user_id,
        expires_at: input.expires_at,
        token: input
            .token
            .unwrap_or_else(|| generate_random_string(DEFAULT_SESSION_TOKEN_LENGTH)),
        ip_address: input.ip_address,
        user_agent: input.user_agent,
        created_at: now,
        updated_at: now,
    }
}

fn session_key(token: &str) -> String {
    format!("session:{token}")
}

fn user_sessions_key(user_id: &str) -> String {
    format!("session:user:{user_id}")
}

fn serialize_session(session: &Session) -> Result<String, OpenAuthError> {
    serde_json::to_string(session).map_err(|error| OpenAuthError::Serialization {
        context: "serializing session",
        message: error.to_string(),
    })
}

fn deserialize_session(value: &str) -> Result<Session, OpenAuthError> {
    serde_json::from_str(value).map_err(|error| OpenAuthError::Serialization {
        context: "deserializing session",
        message: error.to_string(),
    })
}

fn serialize_user_session_tokens(tokens: &[String]) -> Result<String, OpenAuthError> {
    serde_json::to_string(tokens).map_err(|error| OpenAuthError::Serialization {
        context: "serializing user session index",
        message: error.to_string(),
    })
}

fn deserialize_user_session_tokens(value: &str) -> Result<Vec<String>, OpenAuthError> {
    serde_json::from_str(value).map_err(|error| OpenAuthError::Serialization {
        context: "deserializing user session index",
        message: error.to_string(),
    })
}

fn ttl_seconds(expires_at: OffsetDateTime) -> Option<u64> {
    let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
    Some(u64::try_from(seconds.max(0)).unwrap_or(0))
}

fn index_ttl_seconds(expires_at: OffsetDateTime) -> Option<u64> {
    let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
    let ttl = u64::try_from(seconds.max(0)).unwrap_or(0);
    if ttl == 0 {
        None
    } else {
        Some(ttl)
    }
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
    OpenAuthError::MissingRecordField {
        record: "session",
        field: field.to_owned(),
    }
}

fn invalid_field(field: &str, expected: &'static str) -> OpenAuthError {
    OpenAuthError::InvalidRecordField {
        record: "session",
        field: field.to_owned(),
        expected,
    }
}
