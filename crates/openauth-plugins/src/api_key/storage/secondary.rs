use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::Poll;

use openauth_core::error::OpenAuthError;
use openauth_core::options::SecondaryStorage;
use time::OffsetDateTime;
use tokio::sync::Mutex as AsyncMutex;

use super::keys::{storage_key_by_hash, storage_key_by_id, storage_key_by_reference};
use super::listing::{list_from_secondary_storage, ListOptions, ListResult};
use super::ApiKeyStore;
use crate::api_key::models::ApiKeyRecord;

const STORAGE_CONCURRENCY: usize = 10;
type StorageFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, OpenAuthError>> + Send + 'a>>;

/// Returns the in-process lock guarding read/modify/write mutations of a single
/// `api-key:by-ref:*` listing index entry.
///
/// The generic [`SecondaryStorage`] contract only exposes get/set/delete, so it
/// cannot make the "read the id vector, edit it, write it back" sequence atomic
/// on its own. Without serialization, concurrent creates/deletes for the same
/// reference can read the same starting vector and overwrite each other, leaving
/// live keys absent from `/api-key/list`. Locks are keyed by the concrete
/// storage key and dropped once idle. This protects a single process only;
/// cross-process deployments still require a secondary-storage backend with
/// atomic collection semantics.
fn ref_index_lock(ref_key: &str) -> Arc<AsyncMutex<()>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Weak<AsyncMutex<()>>>>> = OnceLock::new();
    let mut registry = REGISTRY
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(lock) = registry.get(ref_key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(AsyncMutex::new(()));
    registry.insert(ref_key.to_owned(), Arc::downgrade(&lock));
    // Drop entries whose locks are no longer held to keep the registry bounded.
    registry.retain(|_, weak| weak.strong_count() > 0);
    lock
}

impl ApiKeyStore<'_> {
    pub(super) async fn list_secondary(
        &self,
        reference_id: &str,
        options: ListOptions,
    ) -> Result<ListResult, OpenAuthError> {
        let Some(storage) = self.secondary_storage() else {
            return Ok(ListResult {
                api_keys: Vec::new(),
                total: 0,
            });
        };
        list_from_secondary_storage(&*storage, reference_id, &options).await
    }

    pub(super) async fn set_secondary(&self, api_key: &ApiKeyRecord) -> Result<(), OpenAuthError> {
        let Some(storage) = self.secondary_storage() else {
            return Err(OpenAuthError::Adapter(
                "secondary storage is required for API key secondary-storage mode".to_owned(),
            ));
        };
        set_secondary(&*storage, api_key, self.options.fallback_to_database).await
    }

    pub(super) async fn delete_secondary(
        &self,
        api_key: &ApiKeyRecord,
    ) -> Result<(), OpenAuthError> {
        let Some(storage) = self.secondary_storage() else {
            return Err(OpenAuthError::Adapter(
                "secondary storage is required for API key secondary-storage mode".to_owned(),
            ));
        };
        storage.delete(&storage_key_by_hash(&api_key.key)).await?;
        storage.delete(&storage_key_by_id(&api_key.id)).await?;
        let ref_key = storage_key_by_reference(&api_key.reference_id);
        if self.options.fallback_to_database {
            storage.delete(&ref_key).await?;
        } else {
            let ref_lock = ref_index_lock(&ref_key);
            let _guard = ref_lock.lock().await;
            if let Some(raw) = storage.get(&ref_key).await? {
                let mut ids = serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default();
                ids.retain(|id| id != &api_key.id);
                if ids.is_empty() {
                    storage.delete(&ref_key).await?;
                } else {
                    storage
                        .set(
                            &ref_key,
                            serde_json::to_string(&ids)
                                .map_err(|error| OpenAuthError::Adapter(error.to_string()))?,
                            None,
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }
}

pub(super) async fn get_secondary_bounded(
    storage: &dyn SecondaryStorage,
    ids: Vec<String>,
) -> Result<Vec<ApiKeyRecord>, OpenAuthError> {
    let mut ids = ids.into_iter();
    let mut in_flight: Vec<StorageFuture<'_, Option<ApiKeyRecord>>> = Vec::new();
    fill_secondary_gets(storage, &mut ids, &mut in_flight);
    let mut api_keys = Vec::new();
    while !in_flight.is_empty() {
        let result = poll_next_ready(&mut in_flight).await?;
        if let Some(api_key) = result {
            api_keys.push(api_key);
        }
        fill_secondary_gets(storage, &mut ids, &mut in_flight);
    }
    Ok(api_keys)
}

fn fill_secondary_gets<'a>(
    storage: &'a dyn SecondaryStorage,
    ids: &mut std::vec::IntoIter<String>,
    in_flight: &mut Vec<StorageFuture<'a, Option<ApiKeyRecord>>>,
) {
    while in_flight.len() < STORAGE_CONCURRENCY {
        let Some(id) = ids.next() else {
            break;
        };
        in_flight.push(Box::pin(async move {
            get_secondary(storage, &storage_key_by_id(&id)).await
        }));
    }
}

pub(super) async fn set_secondary_bounded(
    storage: &dyn SecondaryStorage,
    api_keys: &[ApiKeyRecord],
    fallback_to_database: bool,
) -> Result<(), OpenAuthError> {
    let mut api_keys = api_keys.iter();
    let mut in_flight: Vec<StorageFuture<'_, ()>> = Vec::new();
    fill_secondary_sets(storage, &mut api_keys, fallback_to_database, &mut in_flight);
    while !in_flight.is_empty() {
        poll_next_ready(&mut in_flight).await?;
        fill_secondary_sets(storage, &mut api_keys, fallback_to_database, &mut in_flight);
    }
    Ok(())
}

fn fill_secondary_sets<'a>(
    storage: &'a dyn SecondaryStorage,
    api_keys: &mut std::slice::Iter<'a, ApiKeyRecord>,
    fallback_to_database: bool,
    in_flight: &mut Vec<StorageFuture<'a, ()>>,
) {
    while in_flight.len() < STORAGE_CONCURRENCY {
        let Some(api_key) = api_keys.next() else {
            break;
        };
        in_flight.push(Box::pin(async move {
            set_secondary(storage, api_key, fallback_to_database).await
        }));
    }
}

async fn poll_next_ready<'a, T>(
    in_flight: &mut Vec<StorageFuture<'a, T>>,
) -> Result<T, OpenAuthError> {
    std::future::poll_fn(|context| {
        let mut index = 0;
        while index < in_flight.len() {
            if let Poll::Ready(result) = in_flight[index].as_mut().poll(context) {
                drop(in_flight.swap_remove(index));
                return Poll::Ready(result);
            }
            index += 1;
        }
        Poll::Pending
    })
    .await
}

async fn set_secondary(
    storage: &dyn SecondaryStorage,
    api_key: &ApiKeyRecord,
    fallback_to_database: bool,
) -> Result<(), OpenAuthError> {
    let ttl = ttl_seconds(api_key);
    let serialized = serde_json::to_string(api_key)
        .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
    storage
        .set(&storage_key_by_hash(&api_key.key), serialized.clone(), ttl)
        .await?;
    storage
        .set(&storage_key_by_id(&api_key.id), serialized, ttl)
        .await?;
    let ref_key = storage_key_by_reference(&api_key.reference_id);
    if fallback_to_database {
        storage.delete(&ref_key).await?;
        return Ok(());
    }
    let ref_lock = ref_index_lock(&ref_key);
    let _guard = ref_lock.lock().await;
    let mut ids = match storage.get(&ref_key).await? {
        Some(raw) => serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default(),
        None => Vec::new(),
    };
    if !ids.iter().any(|id| id == &api_key.id) {
        ids.push(api_key.id.clone());
    }
    storage
        .set(
            &ref_key,
            serde_json::to_string(&ids)
                .map_err(|error| OpenAuthError::Adapter(error.to_string()))?,
            None,
        )
        .await
}

pub(super) async fn get_secondary(
    storage: &dyn SecondaryStorage,
    key: &str,
) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
    let Some(raw) = storage.get(key).await? else {
        return Ok(None);
    };
    Ok(serde_json::from_str::<ApiKeyRecord>(&raw).ok())
}

fn ttl_seconds(api_key: &ApiKeyRecord) -> Option<u64> {
    let expires_at = api_key.expires_at?;
    let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
    u64::try_from(seconds).ok().filter(|seconds| *seconds > 0)
}
