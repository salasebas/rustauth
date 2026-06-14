use std::collections::HashMap;

use rustauth_core::db::{
    run_transaction_without_native_support, AdapterFuture, Count, Create, DbAdapter, DbRecord,
    DbValue, Delete, DeleteMany, FindMany, FindOne, TransactionCallback, Update, UpdateMany, Where,
    WhereOperator,
};
use rustauth_core::error::RustAuthError;
use rustauth_core::session::{CreateSessionInput, DbSessionStore};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

#[derive(Default)]
struct InMemorySessionAdapter {
    records: Mutex<HashMap<String, DbRecord>>,
    creates: Mutex<Vec<Create>>,
    updates: Mutex<Vec<Update>>,
    update_many: Mutex<Vec<UpdateMany>>,
    deletes: Mutex<Vec<Delete>>,
    delete_many: Mutex<Vec<DeleteMany>>,
}

impl InMemorySessionAdapter {
    async fn insert(&self, record: DbRecord) -> Result<(), RustAuthError> {
        let token = string_field(&record, "token")?;
        self.records.lock().await.insert(token.to_owned(), record);
        Ok(())
    }
}

impl DbAdapter for InMemorySessionAdapter {
    fn id(&self) -> &str {
        "memory-session"
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            self.creates.lock().await.push(query.clone());
            let token = string_field(&query.data, "token")?.to_owned();
            self.records.lock().await.insert(token, query.data.clone());
            Ok(query.data)
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            let token = token_filter(&query.where_clauses)?;
            Ok(self.records.lock().await.get(token).cloned())
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            if let Some(tokens) = token_in_filter(&query.where_clauses)? {
                return Ok(self
                    .records
                    .lock()
                    .await
                    .values()
                    .filter(|record| {
                        matches!(record.get("token"), Some(DbValue::String(value)) if tokens.iter().any(|token| token == value))
                    })
                    .cloned()
                    .collect());
            }
            let user_id = user_filter(&query.where_clauses)?;
            Ok(self
                .records
                .lock()
                .await
                .values()
                .filter(|record| {
                    matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                })
                .cloned()
                .collect())
        })
    }

    fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.updates.lock().await.push(query.clone());
            let token = token_filter(&query.where_clauses)?;
            let mut records = self.records.lock().await;
            let Some(record) = records.get_mut(token) else {
                return Ok(None);
            };

            for (key, value) in query.data {
                record.insert(key, value);
            }

            Ok(Some(record.clone()))
        })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.update_many.lock().await.push(query.clone());
            let user_id = user_filter(&query.where_clauses)?;
            let mut records = self.records.lock().await;
            let mut updated = 0;
            for record in records.values_mut() {
                if matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
                {
                    for (key, value) in &query.data {
                        record.insert(key.clone(), value.clone());
                    }
                    updated += 1;
                }
            }
            Ok(updated)
        })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.deletes.lock().await.push(query.clone());
            let token = token_filter(&query.where_clauses)?;
            self.records.lock().await.remove(token);
            Ok(())
        })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.delete_many.lock().await.push(query.clone());
            let user_id = user_filter(&query.where_clauses)?;
            let mut records = self.records.lock().await;
            let before = records.len();
            records.retain(|_, record| {
                !matches!(record.get("user_id"), Some(DbValue::String(value)) if value == user_id)
            });
            Ok((before - records.len()) as u64)
        })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        run_transaction_without_native_support(self, callback)
    }
}

#[tokio::test]
async fn db_session_store_creates_session_record() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    let store = DbSessionStore::new(&adapter);
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);

    let session = store
        .create_session(
            CreateSessionInput::new("user_1", expires_at)
                .id("session_1")
                .token("token_1")
                .ip_address("192.0.2.1")
                .user_agent("test-agent"),
        )
        .await?;

    assert_eq!(session.id, "session_1");
    assert_eq!(session.user_id, "user_1");
    assert_eq!(session.token, "token_1");
    assert_eq!(session.ip_address.as_deref(), Some("192.0.2.1"));
    assert_eq!(session.user_agent.as_deref(), Some("test-agent"));

    let creates = adapter.creates.lock().await;
    let Some(create) = creates.first() else {
        return Err(RustAuthError::Adapter("missing create query".to_owned()));
    };
    assert_eq!(create.model, "session");
    assert!(create.force_allow_id);
    assert_eq!(
        create.data.get("user_id"),
        Some(&DbValue::String("user_1".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn db_session_store_finds_valid_session_by_token() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
    adapter
        .insert(session_record("session_1", "user_1", "token_1", expires_at))
        .await?;

    let session = DbSessionStore::new(&adapter)
        .find_session("token_1")
        .await?;

    let Some(session) = session else {
        return Err(RustAuthError::Adapter("missing session".to_owned()));
    };
    assert_eq!(session.id, "session_1");
    assert_eq!(session.user_id, "user_1");
    assert_eq!(session.token, "token_1");
    assert_eq!(session.expires_at, expires_at);
    Ok(())
}

#[tokio::test]
async fn db_session_store_ignores_expired_sessions() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    adapter
        .insert(session_record(
            "session_1",
            "user_1",
            "token_1",
            OffsetDateTime::now_utc() - Duration::minutes(1),
        ))
        .await?;

    let session = DbSessionStore::new(&adapter)
        .find_session("token_1")
        .await?;

    assert!(session.is_none());
    Ok(())
}

#[tokio::test]
async fn db_session_store_updates_session_expiry() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    let old_expiry = OffsetDateTime::now_utc() + Duration::hours(1);
    let new_expiry = OffsetDateTime::now_utc() + Duration::hours(2);
    adapter
        .insert(session_record("session_1", "user_1", "token_1", old_expiry))
        .await?;

    let session = DbSessionStore::new(&adapter)
        .update_session_expiry("token_1", new_expiry)
        .await?;

    let Some(session) = session else {
        return Err(RustAuthError::Adapter("missing updated session".to_owned()));
    };
    assert_eq!(session.expires_at, new_expiry);

    let updates = adapter.updates.lock().await;
    let Some(update) = updates.first() else {
        return Err(RustAuthError::Adapter("missing update query".to_owned()));
    };
    assert_eq!(
        update.data.get("expires_at"),
        Some(&DbValue::Timestamp(new_expiry))
    );
    assert!(update.data.contains_key("updated_at"));
    Ok(())
}

#[tokio::test]
async fn db_session_store_deletes_session_by_token() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    adapter
        .insert(session_record(
            "session_1",
            "user_1",
            "token_1",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
        .await?;

    DbSessionStore::new(&adapter)
        .delete_session("token_1")
        .await?;

    assert!(adapter.records.lock().await.is_empty());
    let deletes = adapter.deletes.lock().await;
    let Some(delete) = deletes.first() else {
        return Err(RustAuthError::Adapter("missing delete query".to_owned()));
    };
    assert_eq!(delete.model, "session");
    assert_eq!(token_filter(&delete.where_clauses)?, "token_1");
    Ok(())
}

#[tokio::test]
async fn db_session_store_deletes_all_sessions_for_user() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
    adapter
        .insert(session_record("session_1", "user_1", "token_1", expires_at))
        .await?;
    adapter
        .insert(session_record("session_2", "user_1", "token_2", expires_at))
        .await?;
    adapter
        .insert(session_record("session_3", "user_2", "token_3", expires_at))
        .await?;

    let deleted = DbSessionStore::new(&adapter)
        .delete_user_sessions("user_1")
        .await?;

    assert_eq!(deleted, 2);
    assert_eq!(adapter.records.lock().await.len(), 1);
    let deletes = adapter.delete_many.lock().await;
    let Some(delete_many) = deletes.first() else {
        return Err(RustAuthError::Adapter(
            "missing delete many query".to_owned(),
        ));
    };
    assert_eq!(delete_many.model, "session");
    assert_eq!(user_filter(&delete_many.where_clauses)?, "user_1");
    Ok(())
}

#[tokio::test]
async fn db_session_store_refresh_user_sessions_bumps_updated_at() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
    let original = OffsetDateTime::now_utc() - Duration::hours(1);
    let mut first = session_record("session_1", "user_1", "token_1", expires_at);
    first.insert("updated_at".to_owned(), DbValue::Timestamp(original));
    let mut second = session_record("session_2", "user_1", "token_2", expires_at);
    second.insert("updated_at".to_owned(), DbValue::Timestamp(original));
    let mut other = session_record("session_3", "user_2", "token_3", expires_at);
    other.insert("updated_at".to_owned(), DbValue::Timestamp(original));
    adapter.insert(first).await?;
    adapter.insert(second).await?;
    adapter.insert(other).await?;

    let refreshed = DbSessionStore::new(&adapter)
        .refresh_user_sessions("user_1")
        .await?;

    assert_eq!(refreshed, 2);
    let records = adapter.records.lock().await;
    for token in ["token_1", "token_2"] {
        let updated = records
            .get(token)
            .and_then(|record| record.get("updated_at"))
            .ok_or_else(|| RustAuthError::Adapter("missing updated_at".to_owned()))?;
        assert!(matches!(updated, DbValue::Timestamp(value) if *value > original));
    }
    assert_eq!(
        records
            .get("token_3")
            .and_then(|record| record.get("updated_at")),
        Some(&DbValue::Timestamp(original))
    );
    let updates = adapter.update_many.lock().await;
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].model, "session");
    assert_eq!(user_filter(&updates[0].where_clauses)?, "user_1");
    Ok(())
}

#[tokio::test]
async fn db_session_store_lists_active_sessions_for_user() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    let active_expiry = OffsetDateTime::now_utc() + Duration::hours(1);
    adapter
        .insert(session_record(
            "session_1",
            "user_1",
            "token_1",
            active_expiry,
        ))
        .await?;
    adapter
        .insert(session_record(
            "session_2",
            "user_1",
            "token_2",
            OffsetDateTime::now_utc() - Duration::minutes(1),
        ))
        .await?;
    adapter
        .insert(session_record(
            "session_3",
            "user_2",
            "token_3",
            active_expiry,
        ))
        .await?;

    let sessions = DbSessionStore::new(&adapter)
        .list_user_sessions("user_1")
        .await?;

    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].token, "token_1");
    Ok(())
}

#[tokio::test]
async fn db_session_store_finds_sessions_by_tokens() -> Result<(), RustAuthError> {
    let adapter = InMemorySessionAdapter::default();
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
    adapter
        .insert(session_record("session_1", "user_1", "token_1", expires_at))
        .await?;
    adapter
        .insert(session_record("session_2", "user_1", "token_2", expires_at))
        .await?;
    adapter
        .insert(session_record("session_3", "user_1", "token_3", expires_at))
        .await?;

    let sessions = DbSessionStore::new(&adapter)
        .find_sessions(["token_3", "missing", "token_1"])
        .await?;

    assert_eq!(sessions.len(), 2);
    assert!(sessions.iter().any(|session| session.token == "token_1"));
    assert!(sessions.iter().any(|session| session.token == "token_3"));
    Ok(())
}

fn session_record(id: &str, user_id: &str, token: &str, expires_at: OffsetDateTime) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(id.to_owned()));
    record.insert("user_id".to_owned(), DbValue::String(user_id.to_owned()));
    record.insert("expires_at".to_owned(), DbValue::Timestamp(expires_at));
    record.insert("token".to_owned(), DbValue::String(token.to_owned()));
    record.insert("ip_address".to_owned(), DbValue::Null);
    record.insert("user_agent".to_owned(), DbValue::Null);
    record.insert(
        "created_at".to_owned(),
        DbValue::Timestamp(OffsetDateTime::now_utc()),
    );
    record.insert(
        "updated_at".to_owned(),
        DbValue::Timestamp(OffsetDateTime::now_utc()),
    );
    record
}

fn token_filter(where_clauses: &[Where]) -> Result<&str, RustAuthError> {
    string_filter(where_clauses, "token")
}

fn user_filter(where_clauses: &[Where]) -> Result<&str, RustAuthError> {
    string_filter(where_clauses, "user_id")
}

fn string_filter<'a>(where_clauses: &'a [Where], field: &str) -> Result<&'a str, RustAuthError> {
    where_clauses
        .iter()
        .find_map(|where_clause| {
            match (
                where_clause.field.as_str(),
                where_clause.operator,
                &where_clause.value,
            ) {
                (candidate, WhereOperator::Eq, DbValue::String(value)) if candidate == field => {
                    Some(value.as_str())
                }
                _ => None,
            }
        })
        .ok_or_else(|| RustAuthError::Adapter(format!("missing {field} filter")))
}

fn token_in_filter(where_clauses: &[Where]) -> Result<Option<Vec<String>>, RustAuthError> {
    where_clauses
        .iter()
        .find_map(|where_clause| {
            match (
                where_clause.field.as_str(),
                where_clause.operator,
                &where_clause.value,
            ) {
                ("token", WhereOperator::In, DbValue::StringArray(values)) => {
                    Some(Ok(values.clone()))
                }
                ("token", WhereOperator::In, _) => Some(Err(RustAuthError::Adapter(
                    "token IN filter must use string array".to_owned(),
                ))),
                _ => None,
            }
        })
        .transpose()
}

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, RustAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(RustAuthError::Adapter(format!(
            "missing string field `{field}`"
        ))),
    }
}
