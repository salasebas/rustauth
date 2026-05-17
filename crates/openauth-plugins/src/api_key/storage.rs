use std::cmp::Ordering;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{
    Count, Create, DbAdapter, DbValue, Delete, DeleteMany, FindMany, FindOne, Sort, SortDirection,
    Update, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use openauth_core::options::SecondaryStorage;
use time::OffsetDateTime;

use super::models::{record_from_db, ApiKeyRecord, API_KEY_FIELDS};
use super::options::{ApiKeyConfiguration, ApiKeyStorageMode};
use super::API_KEY_MODEL;

const DEFAULT_ID_LENGTH: usize = 32;
const STORAGE_CONCURRENCY: usize = 10;
type StorageFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, OpenAuthError>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOptions {
    pub config_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_direction: SortDirection,
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            config_id: None,
            limit: None,
            offset: None,
            sort_by: None,
            sort_direction: SortDirection::Asc,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListResult {
    pub api_keys: Vec<ApiKeyRecord>,
    pub total: u64,
}

pub struct ApiKeyStore<'a> {
    context: &'a AuthContext,
    adapter: Option<Arc<dyn DbAdapter>>,
    options: &'a ApiKeyConfiguration,
}

impl<'a> ApiKeyStore<'a> {
    pub fn new(context: &'a AuthContext, options: &'a ApiKeyConfiguration) -> Self {
        Self {
            context,
            adapter: context.adapter(),
            options,
        }
    }

    pub async fn create(&self, mut api_key: ApiKeyRecord) -> Result<ApiKeyRecord, OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => self.create_database(api_key).await,
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                let created = self.create_database(api_key).await?;
                self.set_secondary(&created).await?;
                Ok(created)
            }
            ApiKeyStorageMode::SecondaryStorage => {
                api_key.id = generate_random_string(DEFAULT_ID_LENGTH);
                self.set_secondary(&api_key).await?;
                Ok(api_key)
            }
        }
    }

    pub async fn get_by_hash(
        &self,
        hashed_key: &str,
    ) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => self.get_database("key", hashed_key).await,
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                if let Some(storage) = self.secondary_storage() {
                    if let Some(api_key) =
                        get_secondary(&*storage, &storage_key_by_hash(hashed_key)).await?
                    {
                        return Ok(Some(api_key));
                    }
                }
                let api_key = self.get_database("key", hashed_key).await?;
                if let Some(api_key) = &api_key {
                    self.set_secondary(api_key).await?;
                }
                Ok(api_key)
            }
            ApiKeyStorageMode::SecondaryStorage => {
                let Some(storage) = self.secondary_storage() else {
                    return Ok(None);
                };
                get_secondary(&*storage, &storage_key_by_hash(hashed_key)).await
            }
        }
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => self.get_database("id", id).await,
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                if let Some(storage) = self.secondary_storage() {
                    if let Some(api_key) = get_secondary(&*storage, &storage_key_by_id(id)).await? {
                        return Ok(Some(api_key));
                    }
                }
                let api_key = self.get_database("id", id).await?;
                if let Some(api_key) = &api_key {
                    self.set_secondary(api_key).await?;
                }
                Ok(api_key)
            }
            ApiKeyStorageMode::SecondaryStorage => {
                let Some(storage) = self.secondary_storage() else {
                    return Ok(None);
                };
                get_secondary(&*storage, &storage_key_by_id(id)).await
            }
        }
    }

    pub async fn update(
        &self,
        api_key: &ApiKeyRecord,
    ) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => self.update_database(api_key).await,
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                let updated = self.update_database(api_key).await?;
                if let Some(updated) = &updated {
                    self.set_secondary(updated).await?;
                }
                Ok(updated)
            }
            ApiKeyStorageMode::SecondaryStorage => {
                self.set_secondary(api_key).await?;
                Ok(Some(api_key.clone()))
            }
        }
    }

    pub async fn delete(&self, api_key: &ApiKeyRecord) -> Result<(), OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => self.delete_database(&api_key.id).await,
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                self.delete_secondary(api_key).await?;
                self.delete_database(&api_key.id).await
            }
            ApiKeyStorageMode::SecondaryStorage => self.delete_secondary(api_key).await,
        }
    }

    pub async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, OpenAuthError> {
        let Some(adapter) = &self.adapter else {
            return Ok(0);
        };
        adapter
            .delete_many(
                DeleteMany::new(API_KEY_MODEL)
                    .where_clause(
                        Where::new("expires_at", DbValue::Timestamp(now))
                            .operator(WhereOperator::Lt),
                    )
                    .where_clause(
                        Where::new("expires_at", DbValue::Null).operator(WhereOperator::Ne),
                    ),
            )
            .await
    }

    pub async fn list(
        &self,
        reference_id: &str,
        list_options: ListOptions,
    ) -> Result<ListResult, OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => self.list_database(reference_id, list_options).await,
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                if let Some(storage) = self.secondary_storage() {
                    let cached =
                        list_from_secondary_storage(&*storage, reference_id, &list_options).await?;
                    if cached.total > 0 {
                        return Ok(cached);
                    }
                }
                let result = self
                    .list_database(reference_id, list_options.clone())
                    .await?;
                if let Some(storage) = self.secondary_storage() {
                    set_secondary_bounded(
                        &*storage,
                        &result.api_keys,
                        self.options.fallback_to_database,
                    )
                    .await?;
                    storage
                        .set(
                            &storage_key_by_reference(reference_id),
                            serde_json::to_string(
                                &result
                                    .api_keys
                                    .iter()
                                    .map(|api_key| api_key.id.clone())
                                    .collect::<Vec<_>>(),
                            )
                            .map_err(|error| OpenAuthError::Adapter(error.to_string()))?,
                            None,
                        )
                        .await?;
                }
                Ok(result)
            }
            ApiKeyStorageMode::SecondaryStorage => {
                self.list_secondary(reference_id, list_options).await
            }
        }
    }

    async fn create_database(&self, api_key: ApiKeyRecord) -> Result<ApiKeyRecord, OpenAuthError> {
        let adapter = self.required_adapter()?;
        let mut query = Create::new(API_KEY_MODEL).force_allow_id();
        for (field, value) in api_key.to_record() {
            query = query.data(field, value);
        }
        adapter
            .create(query.select(API_KEY_FIELDS))
            .await
            .and_then(record_from_db)
    }

    async fn get_database(
        &self,
        field: &str,
        value: &str,
    ) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        let Some(adapter) = &self.adapter else {
            return Ok(None);
        };
        adapter
            .find_one(
                FindOne::new(API_KEY_MODEL)
                    .where_clause(Where::new(field, DbValue::String(value.to_owned())))
                    .select(API_KEY_FIELDS),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    async fn update_database(
        &self,
        api_key: &ApiKeyRecord,
    ) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        let adapter = self.required_adapter()?;
        let mut data = api_key.to_record();
        data.shift_remove("id");
        adapter
            .update(Update {
                model: API_KEY_MODEL.to_owned(),
                where_clauses: vec![Where::new("id", DbValue::String(api_key.id.clone()))],
                data,
            })
            .await?
            .map(record_from_db)
            .transpose()
    }

    async fn delete_database(&self, id: &str) -> Result<(), OpenAuthError> {
        let Some(adapter) = &self.adapter else {
            return Ok(());
        };
        adapter
            .delete(
                Delete::new(API_KEY_MODEL)
                    .where_clause(Where::new("id", DbValue::String(id.to_owned()))),
            )
            .await
    }

    async fn list_database(
        &self,
        reference_id: &str,
        options: ListOptions,
    ) -> Result<ListResult, OpenAuthError> {
        let adapter = self.required_adapter()?;
        let mut find = FindMany::new(API_KEY_MODEL)
            .where_clause(Where::new(
                "reference_id",
                DbValue::String(reference_id.to_owned()),
            ))
            .select(API_KEY_FIELDS);
        if let Some(limit) = options.limit {
            find = find.limit(limit);
        }
        if let Some(offset) = options.offset {
            find = find.offset(offset);
        }
        if let Some(sort_by) = options.sort_by {
            find = find.sort_by(Sort::new(sort_by, options.sort_direction));
        }
        if let Some(config_id) = &options.config_id {
            find = find.where_clause(Where::new("config_id", DbValue::String(config_id.clone())));
        }
        let api_keys = adapter
            .find_many(find)
            .await?
            .into_iter()
            .map(record_from_db)
            .collect::<Result<Vec<_>, _>>()?;
        let mut count = Count::new(API_KEY_MODEL).where_clause(Where::new(
            "reference_id",
            DbValue::String(reference_id.to_owned()),
        ));
        if let Some(config_id) = options.config_id {
            count = count.where_clause(Where::new("config_id", DbValue::String(config_id)));
        }
        let total = adapter.count(count).await?;
        Ok(ListResult { api_keys, total })
    }

    async fn list_secondary(
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

    async fn set_secondary(&self, api_key: &ApiKeyRecord) -> Result<(), OpenAuthError> {
        let Some(storage) = self.secondary_storage() else {
            return Err(OpenAuthError::Adapter(
                "secondary storage is required for API key secondary-storage mode".to_owned(),
            ));
        };
        set_secondary(&*storage, api_key, self.options.fallback_to_database).await
    }

    async fn delete_secondary(&self, api_key: &ApiKeyRecord) -> Result<(), OpenAuthError> {
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
        } else if let Some(raw) = storage.get(&ref_key).await? {
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
        Ok(())
    }

    fn secondary_storage(&self) -> Option<Arc<dyn SecondaryStorage>> {
        self.options
            .custom_storage
            .clone()
            .or_else(|| self.context.secondary_storage())
    }

    fn required_adapter(&self) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
        self.adapter.clone().ok_or_else(|| {
            OpenAuthError::Adapter("api-key plugin requires a database adapter".to_owned())
        })
    }
}

async fn list_from_secondary_storage(
    storage: &dyn SecondaryStorage,
    reference_id: &str,
    options: &ListOptions,
) -> Result<ListResult, OpenAuthError> {
    let Some(ids) = storage.get(&storage_key_by_reference(reference_id)).await? else {
        return Ok(ListResult {
            api_keys: Vec::new(),
            total: 0,
        });
    };
    let ids = serde_json::from_str::<Vec<String>>(&ids).unwrap_or_default();
    let mut api_keys = get_secondary_bounded(storage, ids).await?;
    if let Some(config_id) = &options.config_id {
        api_keys.retain(|api_key| &api_key.config_id == config_id);
    }
    if let Some(sort_by) = &options.sort_by {
        api_keys.sort_by(|left, right| compare_api_keys(left, right, sort_by));
        if options.sort_direction == SortDirection::Desc {
            api_keys.reverse();
        }
    }
    let total = api_keys.len() as u64;
    let offset = options.offset.unwrap_or(0);
    let iter = api_keys.into_iter().skip(offset);
    let api_keys = match options.limit {
        Some(limit) => iter.take(limit).collect(),
        None => iter.collect(),
    };
    Ok(ListResult { api_keys, total })
}

async fn get_secondary_bounded(
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

async fn set_secondary_bounded(
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

async fn get_secondary(
    storage: &dyn SecondaryStorage,
    key: &str,
) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
    storage
        .get(key)
        .await?
        .map(|raw| serde_json::from_str::<ApiKeyRecord>(&raw))
        .transpose()
        .map_err(|error| OpenAuthError::Adapter(error.to_string()))
}

fn ttl_seconds(api_key: &ApiKeyRecord) -> Option<u64> {
    let expires_at = api_key.expires_at?;
    let seconds = (expires_at - OffsetDateTime::now_utc()).whole_seconds();
    u64::try_from(seconds).ok().filter(|seconds| *seconds > 0)
}

fn storage_key_by_hash(hashed_key: &str) -> String {
    format!("api-key:{hashed_key}")
}

fn storage_key_by_id(id: &str) -> String {
    format!("api-key:by-id:{id}")
}

fn storage_key_by_reference(reference_id: &str) -> String {
    format!("api-key:by-ref:{reference_id}")
}

fn compare_api_keys(left: &ApiKeyRecord, right: &ApiKeyRecord, field: &str) -> Ordering {
    match field {
        "createdAt" | "created_at" => left.created_at.cmp(&right.created_at),
        "updatedAt" | "updated_at" => left.updated_at.cmp(&right.updated_at),
        "name" => left.name.cmp(&right.name),
        "expiresAt" | "expires_at" => left.expires_at.cmp(&right.expires_at),
        _ => left.id.cmp(&right.id),
    }
}
