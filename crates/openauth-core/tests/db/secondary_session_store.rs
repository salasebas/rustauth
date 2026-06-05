use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openauth_core::db::MemoryAdapter;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{SecondaryStorage, SecondaryStorageFuture};
use openauth_core::session::{CreateSessionInput, SessionStore};
use time::{Duration, OffsetDateTime};

#[derive(Default)]
struct TtlAwareSecondaryStorage {
    entries: Mutex<HashMap<String, StoredEntry>>,
}

#[derive(Clone)]
struct StoredEntry {
    value: String,
    expires_at: Option<OffsetDateTime>,
}

impl TtlAwareSecondaryStorage {
    fn purge_expired(&self) -> Result<(), OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OpenAuthError::Adapter("secondary storage mutex poisoned".to_owned()))?;
        entries.retain(|_, entry| match entry.expires_at {
            None => true,
            Some(expires_at) => expires_at > now,
        });
        Ok(())
    }

    fn get_entry(&self, key: &str) -> Result<Option<StoredEntry>, OpenAuthError> {
        self.purge_expired()?;
        let entries = self
            .entries
            .lock()
            .map_err(|_| OpenAuthError::Adapter("secondary storage mutex poisoned".to_owned()))?;
        Ok(entries.get(key).cloned())
    }

    fn ttl_for_key(&self, key: &str) -> Result<Option<u64>, OpenAuthError> {
        let Some(entry) = self.get_entry(key)? else {
            return Ok(None);
        };
        let Some(expires_at) = entry.expires_at else {
            return Ok(None);
        };
        let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
        Ok(Some(u64::try_from(seconds.max(0)).unwrap_or(0)))
    }

    fn has_key(&self, key: &str) -> Result<bool, OpenAuthError> {
        Ok(self.get_entry(key)?.is_some())
    }
}

impl SecondaryStorage for TtlAwareSecondaryStorage {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move { Ok(self.get_entry(key)?.map(|entry| entry.value)) })
    }

    fn set<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            let mut entries = self.entries.lock().map_err(|_| {
                OpenAuthError::Adapter("secondary storage mutex poisoned".to_owned())
            })?;
            let expires_at = match ttl_seconds {
                None => None,
                Some(0) => {
                    entries.remove(key);
                    return Ok(());
                }
                Some(seconds) => {
                    Some(OffsetDateTime::now_utc() + Duration::seconds(seconds as i64))
                }
            };
            entries.insert(key.to_owned(), StoredEntry { value, expires_at });
            Ok(())
        })
    }

    fn set_if_not_exists<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            self.purge_expired()?;
            {
                let entries = self.entries.lock().map_err(|_| {
                    OpenAuthError::Adapter("secondary storage mutex poisoned".to_owned())
                })?;
                if entries.contains_key(key) {
                    return Ok(false);
                }
            }
            self.set(key, value, ttl_seconds).await?;
            Ok(true)
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            self.entries
                .lock()
                .map_err(|_| OpenAuthError::Adapter("secondary storage mutex poisoned".to_owned()))?
                .remove(key);
            Ok(())
        })
    }

    fn take<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move {
            self.purge_expired()?;
            let mut entries = self.entries.lock().map_err(|_| {
                OpenAuthError::Adapter("secondary storage mutex poisoned".to_owned())
            })?;
            Ok(entries.remove(key).map(|entry| entry.value))
        })
    }
}

fn secondary_store(
    adapter: &MemoryAdapter,
    storage: Arc<TtlAwareSecondaryStorage>,
) -> SessionStore<'_> {
    SessionStore::with_storage(adapter, Some(storage), false, false)
}

fn user_index_key(user_id: &str) -> String {
    format!("session:user:{user_id}")
}

#[tokio::test]
async fn secondary_session_store_user_index_receives_ttl() -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(TtlAwareSecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let expires_at = OffsetDateTime::now_utc() + Duration::hours(2);

    store
        .create_session(
            CreateSessionInput::new("user_1", expires_at)
                .token("token_1")
                .id("session_1"),
        )
        .await?;

    let index_ttl = storage.ttl_for_key(&user_index_key("user_1"))?;
    let Some(index_ttl) = index_ttl else {
        return Err(OpenAuthError::Adapter(
            "expected user session index TTL".to_owned(),
        ));
    };
    assert!(index_ttl > 0);
    assert!(index_ttl <= 2 * 60 * 60);
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_user_index_ttl_tracks_latest_expiry() -> Result<(), OpenAuthError>
{
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(TtlAwareSecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let sooner = OffsetDateTime::now_utc() + Duration::hours(1);
    let later = OffsetDateTime::now_utc() + Duration::hours(3);

    store
        .create_session(
            CreateSessionInput::new("user_1", sooner)
                .token("token_soon")
                .id("session_soon"),
        )
        .await?;
    store
        .create_session(
            CreateSessionInput::new("user_1", later)
                .token("token_late")
                .id("session_late"),
        )
        .await?;

    let index_ttl = storage
        .ttl_for_key(&user_index_key("user_1"))?
        .ok_or_else(|| OpenAuthError::Adapter("missing user session index TTL".to_owned()))?;
    assert!(index_ttl > 2 * 60 * 60);
    assert!(index_ttl <= 3 * 60 * 60);
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_expired_user_index_is_removed() -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(TtlAwareSecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let expires_at = OffsetDateTime::now_utc() + Duration::seconds(1);

    store
        .create_session(
            CreateSessionInput::new("user_1", expires_at)
                .token("token_1")
                .id("session_1"),
        )
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    assert!(
        !storage.has_key(&user_index_key("user_1"))?,
        "expired user session index must not remain in secondary storage"
    );
    assert!(
        !storage.has_key("session:token_1")?,
        "expired session record must not remain in secondary storage"
    );
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_list_sessions_after_ttl_cleanup() -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(TtlAwareSecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let active_expiry = OffsetDateTime::now_utc() + Duration::hours(2);
    let short_expiry = OffsetDateTime::now_utc() + Duration::seconds(1);

    store
        .create_session(
            CreateSessionInput::new("user_1", active_expiry)
                .token("token_active")
                .id("session_active"),
        )
        .await?;
    store
        .create_session(
            CreateSessionInput::new("user_1", short_expiry)
                .token("token_short")
                .id("session_short"),
        )
        .await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let sessions = store.list_user_sessions("user_1").await?;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].token, "token_active");
    assert!(
        storage.has_key(&user_index_key("user_1"))?,
        "active user session index must remain while a session is active"
    );
    Ok(())
}

#[tokio::test]
async fn secondary_session_store_update_expiry_refreshes_user_index_ttl(
) -> Result<(), OpenAuthError> {
    let adapter = MemoryAdapter::new();
    let storage = Arc::new(TtlAwareSecondaryStorage::default());
    let store = secondary_store(&adapter, storage.clone());
    let initial_expiry = OffsetDateTime::now_utc() + Duration::minutes(30);
    let extended_expiry = OffsetDateTime::now_utc() + Duration::hours(4);

    store
        .create_session(
            CreateSessionInput::new("user_1", initial_expiry)
                .token("token_1")
                .id("session_1"),
        )
        .await?;

    let initial_ttl = storage
        .ttl_for_key(&user_index_key("user_1"))?
        .ok_or_else(|| OpenAuthError::Adapter("missing initial index TTL".to_owned()))?;

    store
        .update_session_expiry("token_1", extended_expiry)
        .await?;

    let refreshed_ttl = storage
        .ttl_for_key(&user_index_key("user_1"))?
        .ok_or_else(|| OpenAuthError::Adapter("missing refreshed index TTL".to_owned()))?;
    assert!(refreshed_ttl > initial_ttl);
    Ok(())
}
