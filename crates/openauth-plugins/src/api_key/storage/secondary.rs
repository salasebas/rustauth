use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use openauth_core::error::OpenAuthError;
use openauth_core::options::SecondaryStorage;
use time::OffsetDateTime;

use super::keys::{storage_key_by_hash, storage_key_by_id, storage_key_by_reference};
use super::listing::{list_from_secondary_storage, ListOptions, ListResult};
use super::ApiKeyStore;
use crate::api_key::models::ApiKeyRecord;

const STORAGE_CONCURRENCY: usize = 10;
type StorageFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, OpenAuthError>> + Send + 'a>>;

const REF_INDEX_MAX_CAS_ATTEMPTS: usize = 32;

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
            mutate_ref_index(storage.as_ref(), &ref_key, |ids| {
                ids.retain(|id| id != &api_key.id);
            })
            .await?;
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
    mutate_ref_index(storage, &ref_key, |ids| {
        if !ids.iter().any(|id| id == &api_key.id) {
            ids.push(api_key.id.clone());
        }
    })
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

pub(super) async fn mutate_ref_index<F>(
    storage: &dyn SecondaryStorage,
    ref_key: &str,
    mutate: F,
) -> Result<(), OpenAuthError>
where
    F: Fn(&mut Vec<String>),
{
    for _ in 0..REF_INDEX_MAX_CAS_ATTEMPTS {
        let expected = storage.get(ref_key).await?;
        let mut ids = expected
            .as_deref()
            .and_then(|raw| serde_json::from_str::<Vec<String>>(raw).ok())
            .unwrap_or_default();
        mutate(&mut ids);
        if ids.is_empty() {
            if storage.delete_if_value(ref_key, expected).await? {
                return Ok(());
            }
        } else {
            let next = serde_json::to_string(&ids)
                .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
            if storage
                .compare_and_set(ref_key, expected, next, None)
                .await?
            {
                return Ok(());
            }
        }
        tokio::task::yield_now().await;
    }
    Err(OpenAuthError::Adapter(
        "api key secondary-storage reference index update conflicted too many times".to_owned(),
    ))
}
