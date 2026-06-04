use std::collections::HashMap;

use openauth_core::db::{
    run_transaction_without_native_support, AdapterFuture, Count, Create, DbAdapter, DbRecord,
    DbValue, Delete, DeleteMany, FindMany, FindOne, MemoryAdapter, SortDirection,
    TransactionCallback, Update, UpdateMany, Verification, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::VerificationOptions;
use openauth_core::verification::{
    process_verification_identifier, CreateVerificationInput, DbVerificationStore,
    UpdateVerificationInput,
};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

#[derive(Default)]
struct InMemoryVerificationAdapter {
    records: Mutex<HashMap<String, DbRecord>>,
    creates: Mutex<Vec<Create>>,
    finds: Mutex<Vec<FindMany>>,
    updates: Mutex<Vec<Update>>,
    deletes: Mutex<Vec<Delete>>,
    delete_many: Mutex<Vec<DeleteMany>>,
}

impl InMemoryVerificationAdapter {
    async fn insert(&self, verification: Verification) {
        self.records
            .lock()
            .await
            .insert(verification.id.clone(), verification_record(verification));
    }
}

impl DbAdapter for InMemoryVerificationAdapter {
    fn id(&self) -> &str {
        "memory-verification"
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            self.creates.lock().await.push(query.clone());
            let id = string_field(&query.data, "id")?.to_owned();
            self.records.lock().await.insert(id, query.data.clone());
            Ok(query.data)
        })
    }

    fn find_one<'a>(&'a self, _query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async { Ok(None) })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            self.finds.lock().await.push(query.clone());
            let identifier = string_filter(&query.where_clauses, "identifier")?;
            let mut records = self
                .records
                .lock()
                .await
                .values()
                .filter(|record| {
                    matches!(record.get("identifier"), Some(DbValue::String(value)) if value == identifier)
                })
                .cloned()
                .collect::<Vec<_>>();
            records.sort_by_key(|record| timestamp_field(record, "created_at").ok());
            if matches!(
                query.sort_by.as_ref().map(|sort| sort.direction),
                Some(SortDirection::Desc)
            ) {
                records.reverse();
            }
            if let Some(limit) = query.limit {
                records.truncate(limit);
            }
            Ok(records)
        })
    }

    fn count<'a>(&'a self, _query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.updates.lock().await.push(query.clone());
            let identifier = string_filter(&query.where_clauses, "identifier")?;
            let mut records = self.records.lock().await;
            let Some((_, record)) = records.iter_mut().find(|(_, record)| {
                matches!(record.get("identifier"), Some(DbValue::String(value)) if value == identifier)
            }) else {
                return Ok(None);
            };

            for (field, value) in query.data {
                record.insert(field, value);
            }
            Ok(Some(record.clone()))
        })
    }

    fn update_many<'a>(&'a self, _query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.deletes.lock().await.push(query.clone());
            let identifier = string_filter(&query.where_clauses, "identifier")?;
            self.records.lock().await.retain(|_, record| {
                !matches!(record.get("identifier"), Some(DbValue::String(value)) if value == identifier)
            });
            Ok(())
        })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.delete_many.lock().await.push(query.clone());
            let expires_at = timestamp_filter(&query.where_clauses, "expires_at")?;
            let mut records = self.records.lock().await;
            let before = records.len();
            records.retain(|_, record| {
                !matches!(record.get("expires_at"), Some(DbValue::Timestamp(value)) if value < expires_at)
            });
            Ok((before - records.len()) as u64)
        })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        run_transaction_without_native_support(self, callback)
    }
}

#[tokio::test]
async fn db_verification_store_creates_verification_value() -> Result<(), OpenAuthError> {
    let adapter = InMemoryVerificationAdapter::default();
    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);

    let verification = DbVerificationStore::new(&adapter)
        .create_verification(
            CreateVerificationInput::new("reset-password:token", "user_1", expires_at)
                .id("verification_1"),
        )
        .await?;

    assert_eq!(verification.id, "verification_1");
    assert_eq!(verification.identifier, "reset-password:token");
    assert_eq!(verification.value, "user_1");
    assert_eq!(verification.expires_at, expires_at);

    let creates = adapter.creates.lock().await;
    let Some(create) = creates.first() else {
        return Err(OpenAuthError::Adapter("missing create query".to_owned()));
    };
    assert_eq!(create.model, "verification");
    assert!(create.force_allow_id);
    Ok(())
}

#[tokio::test]
async fn db_verification_store_finds_latest_active_value() -> Result<(), OpenAuthError> {
    let adapter = InMemoryVerificationAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert(verification(
            "old",
            "token",
            "old-value",
            now - Duration::minutes(1),
            now,
        ))
        .await;
    adapter
        .insert(verification(
            "new",
            "token",
            "new-value",
            now,
            now + Duration::minutes(10),
        ))
        .await;

    let found = DbVerificationStore::new(&adapter)
        .find_verification("token")
        .await?;

    let Some(found) = found else {
        return Err(OpenAuthError::Adapter("missing verification".to_owned()));
    };
    assert_eq!(found.id, "new");
    assert_eq!(found.value, "new-value");

    let finds = adapter.finds.lock().await;
    let Some(find) = finds.first() else {
        return Err(OpenAuthError::Adapter("missing find query".to_owned()));
    };
    assert_eq!(find.model, "verification");
    assert_eq!(find.limit, Some(1));
    assert_eq!(
        find.sort_by.as_ref().map(|sort| sort.direction),
        Some(SortDirection::Desc)
    );
    Ok(())
}

#[tokio::test]
async fn db_verification_store_returns_none_for_expired_values_and_cleans_them(
) -> Result<(), OpenAuthError> {
    let adapter = InMemoryVerificationAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert(verification(
            "expired",
            "token",
            "value",
            now,
            now - Duration::seconds(1),
        ))
        .await;

    let found = DbVerificationStore::new(&adapter)
        .find_verification("token")
        .await?;

    assert!(found.is_none());
    assert!(adapter.records.lock().await.is_empty());
    assert_eq!(adapter.delete_many.lock().await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn db_verification_store_updates_by_identifier() -> Result<(), OpenAuthError> {
    let adapter = InMemoryVerificationAdapter::default();
    let now = OffsetDateTime::now_utc();
    let new_expiry = now + Duration::minutes(20);
    adapter
        .insert(verification(
            "verification_1",
            "token",
            "old",
            now,
            new_expiry,
        ))
        .await;

    let updated = DbVerificationStore::new(&adapter)
        .update_verification(
            "token",
            UpdateVerificationInput::new()
                .value("new")
                .expires_at(new_expiry),
        )
        .await?;

    let Some(updated) = updated else {
        return Err(OpenAuthError::Adapter("missing updated value".to_owned()));
    };
    assert_eq!(updated.value, "new");
    assert_eq!(updated.expires_at, new_expiry);
    assert!(adapter.updates.lock().await[0]
        .data
        .contains_key("updated_at"));
    Ok(())
}

#[tokio::test]
async fn consume_verification_including_expired_is_single_use_under_concurrency(
) -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let store = DbVerificationStore::new(&adapter);
    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    store
        .create_verification(CreateVerificationInput::new(
            "one-time-token:race",
            "session-token",
            expires_at,
        ))
        .await?;

    let store_a = store.clone();
    let store_b = store.clone();
    let (first, second) = tokio::join!(
        store_a.consume_verification_including_expired("one-time-token:race"),
        store_b.consume_verification_including_expired("one-time-token:race"),
    );
    let consumed = [first?, second?].into_iter().flatten().count();
    assert_eq!(
        consumed, 1,
        "parallel consume attempts must redeem the verification at most once"
    );
    Ok(())
}

#[tokio::test]
async fn db_verification_store_deletes_by_identifier() -> Result<(), OpenAuthError> {
    let adapter = InMemoryVerificationAdapter::default();
    let now = OffsetDateTime::now_utc();
    adapter
        .insert(verification(
            "verification_1",
            "token",
            "value",
            now,
            now + Duration::minutes(10),
        ))
        .await;

    DbVerificationStore::new(&adapter)
        .delete_verification("token")
        .await?;

    assert!(adapter.records.lock().await.is_empty());
    assert_eq!(adapter.deletes.lock().await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn db_verification_store_hashes_identifiers_when_configured() -> Result<(), OpenAuthError> {
    let adapter = InMemoryVerificationAdapter::default();
    let options = VerificationOptions::new().store_identifier_hashed();
    let store = DbVerificationStore::with_options(&adapter, options.clone());
    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    let identifier = "reset-password:token";

    let expected_identifier = process_verification_identifier(&options, identifier).await?;

    let verification = store
        .create_verification(CreateVerificationInput::new(
            identifier, "user_1", expires_at,
        ))
        .await?;

    assert_eq!(verification.identifier, expected_identifier);
    assert_ne!(verification.identifier, identifier);

    let creates = adapter.creates.lock().await;
    let Some(create) = creates.first() else {
        return Err(OpenAuthError::Adapter("missing create query".to_owned()));
    };
    assert_eq!(
        string_field(&create.data, "identifier")?,
        expected_identifier.as_str()
    );

    let found = store.find_verification(identifier).await?;
    let Some(found) = found else {
        return Err(OpenAuthError::Adapter("missing verification".to_owned()));
    };
    assert_eq!(found.identifier, expected_identifier);
    Ok(())
}

fn verification(
    id: &str,
    identifier: &str,
    value: &str,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Verification {
    Verification {
        id: id.to_owned(),
        identifier: identifier.to_owned(),
        value: value.to_owned(),
        expires_at,
        created_at,
        updated_at: created_at,
    }
}

fn verification_record(verification: Verification) -> DbRecord {
    let mut record = DbRecord::new();
    record.insert("id".to_owned(), DbValue::String(verification.id));
    record.insert(
        "identifier".to_owned(),
        DbValue::String(verification.identifier),
    );
    record.insert("value".to_owned(), DbValue::String(verification.value));
    record.insert(
        "expires_at".to_owned(),
        DbValue::Timestamp(verification.expires_at),
    );
    record.insert(
        "created_at".to_owned(),
        DbValue::Timestamp(verification.created_at),
    );
    record.insert(
        "updated_at".to_owned(),
        DbValue::Timestamp(verification.updated_at),
    );
    record
}

fn string_filter<'a>(where_clauses: &'a [Where], field: &str) -> Result<&'a str, OpenAuthError> {
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
        .ok_or_else(|| OpenAuthError::Adapter(format!("missing {field} filter")))
}

fn timestamp_filter<'a>(
    where_clauses: &'a [Where],
    field: &str,
) -> Result<&'a OffsetDateTime, OpenAuthError> {
    where_clauses
        .iter()
        .find_map(|where_clause| {
            match (
                where_clause.field.as_str(),
                where_clause.operator,
                &where_clause.value,
            ) {
                (candidate, WhereOperator::Lt, DbValue::Timestamp(value)) if candidate == field => {
                    Some(value)
                }
                _ => None,
            }
        })
        .ok_or_else(|| OpenAuthError::Adapter(format!("missing {field} timestamp filter")))
}

fn string_field<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing string field `{field}`"
        ))),
    }
}

fn timestamp_field(record: &DbRecord, field: &str) -> Result<OffsetDateTime, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::Timestamp(value)) => Ok(*value),
        _ => Err(OpenAuthError::Adapter(format!(
            "missing timestamp field `{field}`"
        ))),
    }
}
