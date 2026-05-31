use openauth_core::db::{Count, DbValue, FindMany, Sort, SortDirection, Where};
use openauth_core::error::OpenAuthError;

use super::keys::{compare_api_keys, storage_key_by_reference};
use super::secondary::{get_secondary_bounded, set_secondary_bounded};
use super::ApiKeyStore;
use crate::api_key::models::{record_from_db, ApiKeyRecord, API_KEY_FIELDS};
use crate::api_key::options::ApiKeyStorageMode;
use crate::api_key::API_KEY_MODEL;

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

impl ApiKeyStore<'_> {
    pub async fn list(
        &self,
        reference_id: &str,
        list_options: ListOptions,
    ) -> Result<ListResult, OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => self.list_database(reference_id, list_options).await,
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                // When revalidation is enabled the database is the source of
                // truth: skip the cache-first shortcut so revoked or
                // out-of-band-edited keys are not served from a stale cache.
                if !self.options.revalidate_secondary_against_database {
                    if let Some(storage) = self.secondary_storage() {
                        let cached =
                            list_from_secondary_storage(&*storage, reference_id, &list_options)
                                .await?;
                        if cached.total > 0 {
                            return Ok(cached);
                        }
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

    pub(super) async fn list_database(
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
}

pub(super) async fn list_from_secondary_storage(
    storage: &dyn openauth_core::options::SecondaryStorage,
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
