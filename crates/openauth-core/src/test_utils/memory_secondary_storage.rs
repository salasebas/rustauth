use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use time::{Duration, OffsetDateTime};

use crate::error::OpenAuthError;
use crate::options::{SecondaryStorage, SecondaryStorageFuture};

#[derive(Debug, Clone, Default)]
pub struct MemorySecondaryStorageOptions {
    pub track_deletes: bool,
}

#[derive(Clone)]
struct StoredEntry {
    value: String,
    expires_at: Option<OffsetDateTime>,
    configured_ttl: Option<u64>,
}

#[derive(Clone)]
struct MemorySecondaryStorageState {
    entries: Arc<Mutex<HashMap<String, StoredEntry>>>,
    deleted: Arc<Mutex<Vec<String>>>,
    options: MemorySecondaryStorageOptions,
}

/// In-memory `SecondaryStorage` test double with TTL-aware contract semantics.
#[derive(Clone, Default)]
pub struct MemorySecondaryStorage {
    state: MemorySecondaryStorageState,
}

impl MemorySecondaryStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_options(options: MemorySecondaryStorageOptions) -> Self {
        Self {
            state: MemorySecondaryStorageState {
                entries: Arc::new(Mutex::new(HashMap::new())),
                deleted: Arc::new(Mutex::new(Vec::new())),
                options,
            },
        }
    }

    pub fn tracking_deletes() -> Self {
        Self::with_options(MemorySecondaryStorageOptions {
            track_deletes: true,
        })
    }

    pub fn value(&self, key: &str) -> Result<Option<String>, OpenAuthError> {
        Ok(self.get_entry(key)?.map(|entry| entry.value))
    }

    pub fn value_for(&self, key: &str) -> Option<String> {
        self.value(key).ok().flatten()
    }

    /// Remaining TTL in seconds for a stored key, if it has an expiry.
    pub fn ttl_for_key(&self, key: &str) -> Result<Option<u64>, OpenAuthError> {
        let Some(entry) = self.get_entry(key)? else {
            return Ok(None);
        };
        let Some(expires_at) = entry.expires_at else {
            return Ok(None);
        };
        let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
        Ok(Some(u64::try_from(seconds.max(0)).unwrap_or(0)))
    }

    /// Configured TTL passed to `set` / `set_if_not_exists`, if the key exists.
    pub fn ttl_for(&self, key: &str) -> Option<Option<u64>> {
        self.entries()
            .ok()
            .and_then(|entries| entries.get(key).map(|entry| entry.configured_ttl))
    }

    pub fn deleted_keys(&self) -> Vec<String> {
        self.state
            .deleted
            .lock()
            .map(|keys| keys.clone())
            .unwrap_or_default()
    }

    pub fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
        self.entries()
            .map(|entries| {
                entries
                    .keys()
                    .filter(|key| key.starts_with(prefix))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn has_key(&self, key: &str) -> Result<bool, OpenAuthError> {
        Ok(self.get_entry(key)?.is_some())
    }

    pub fn insert_raw(&self, key: impl Into<String>, value: impl Into<String>) {
        if let Ok(mut entries) = self.state.entries.lock() {
            entries.insert(
                key.into(),
                StoredEntry {
                    value: value.into(),
                    expires_at: None,
                    configured_ttl: None,
                },
            );
        }
    }

    pub fn remove_raw(&self, key: &str) {
        if let Ok(mut entries) = self.state.entries.lock() {
            entries.remove(key);
        }
    }

    fn entries(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, StoredEntry>>, OpenAuthError> {
        self.state
            .entries
            .lock()
            .map_err(|_| OpenAuthError::Adapter("secondary storage mutex poisoned".to_owned()))
    }

    fn purge_expired(&self) -> Result<(), OpenAuthError> {
        let now = OffsetDateTime::now_utc();
        let mut entries = self.entries()?;
        entries.retain(|_, entry| match entry.expires_at {
            None => true,
            Some(expires_at) => expires_at > now,
        });
        Ok(())
    }

    fn get_entry(&self, key: &str) -> Result<Option<StoredEntry>, OpenAuthError> {
        self.purge_expired()?;
        Ok(self.entries()?.get(key).cloned())
    }

    fn record_delete(&self, key: &str) {
        if !self.state.options.track_deletes {
            return;
        }
        if let Ok(mut deleted) = self.state.deleted.lock() {
            deleted.push(key.to_owned());
        }
    }
}

impl Default for MemorySecondaryStorageState {
    fn default() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            deleted: Arc::new(Mutex::new(Vec::new())),
            options: MemorySecondaryStorageOptions::default(),
        }
    }
}

impl SecondaryStorage for MemorySecondaryStorage {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move { self.value(key) })
    }

    fn set<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            let mut entries = self.entries()?;
            let expires_at = match ttl_seconds {
                None => None,
                Some(0) => {
                    entries.remove(key);
                    self.record_delete(key);
                    return Ok(());
                }
                Some(seconds) => {
                    Some(OffsetDateTime::now_utc() + Duration::seconds(seconds as i64))
                }
            };
            entries.insert(
                key.to_owned(),
                StoredEntry {
                    value,
                    expires_at,
                    configured_ttl: ttl_seconds,
                },
            );
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
            if ttl_seconds == Some(0) {
                return Ok(false);
            }
            self.purge_expired()?;
            {
                let entries = self.entries()?;
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
            let mut entries = self.entries()?;
            entries.remove(key);
            self.record_delete(key);
            Ok(())
        })
    }

    fn take<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move {
            self.purge_expired()?;
            let mut entries = self.entries()?;
            let value = entries.remove(key).map(|entry| entry.value);
            if value.is_some() {
                self.record_delete(key);
            }
            Ok(value)
        })
    }

    fn compare_and_set<'a>(
        &'a self,
        key: &'a str,
        expected: Option<String>,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            self.purge_expired()?;
            let mut entries = self.entries()?;
            if entries.get(key).map(|entry| entry.value.clone()) != expected {
                return Ok(false);
            }
            let expires_at = match ttl_seconds {
                None => None,
                Some(0) => {
                    entries.remove(key);
                    drop(entries);
                    self.record_delete(key);
                    return Ok(true);
                }
                Some(seconds) => {
                    Some(OffsetDateTime::now_utc() + Duration::seconds(seconds as i64))
                }
            };
            entries.insert(
                key.to_owned(),
                StoredEntry {
                    value,
                    expires_at,
                    configured_ttl: ttl_seconds,
                },
            );
            Ok(true)
        })
    }

    fn delete_if_value<'a>(
        &'a self,
        key: &'a str,
        expected: Option<String>,
    ) -> SecondaryStorageFuture<'a, bool> {
        Box::pin(async move {
            self.purge_expired()?;
            let Some(expected) = expected else {
                return Ok(false);
            };
            let mut entries = self.entries()?;
            if entries.get(key).map(|entry| entry.value.as_str()) != Some(expected.as_str()) {
                return Ok(false);
            }
            entries.remove(key);
            drop(entries);
            self.record_delete(key);
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_if_not_exists_ttl_zero_is_non_destructive() -> Result<(), OpenAuthError> {
        let storage = MemorySecondaryStorage::new();
        storage
            .set("existing", "original".to_owned(), Some(60))
            .await?;
        assert!(
            !storage
                .set_if_not_exists("existing", "ignored".to_owned(), Some(0))
                .await?
        );
        assert_eq!(storage.get("existing").await?.as_deref(), Some("original"));

        assert!(
            !storage
                .set_if_not_exists("absent", "ignored".to_owned(), Some(0))
                .await?
        );
        assert_eq!(storage.get("absent").await?, None);
        Ok(())
    }
}
