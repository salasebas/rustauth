mod database;
mod keys;
mod listing;
mod secondary;

use std::sync::Arc;

use openauth_core::context::AuthContext;
use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{DbAdapter, DbValue, Update, Where};
use openauth_core::error::OpenAuthError;
use openauth_core::options::SecondaryStorage;
use time::OffsetDateTime;

use super::models::ApiKeyRecord;
use super::options::{ApiKeyConfiguration, ApiKeyStorageMode};

pub(super) use listing::ListOptions;

const DEFAULT_ID_LENGTH: usize = 32;

pub struct ApiKeyStore<'a> {
    pub(super) context: &'a AuthContext,
    pub(super) adapter: Option<Arc<dyn DbAdapter>>,
    pub(super) options: &'a ApiKeyConfiguration,
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
                        secondary::get_secondary(&*storage, &keys::storage_key_by_hash(hashed_key))
                            .await?
                    {
                        if self.options.revalidate_secondary_against_database {
                            return self.revalidate_cache_hit(api_key, "key", hashed_key).await;
                        }
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
                secondary::get_secondary(&*storage, &keys::storage_key_by_hash(hashed_key)).await
            }
        }
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => self.get_database("id", id).await,
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                if let Some(storage) = self.secondary_storage() {
                    if let Some(api_key) =
                        secondary::get_secondary(&*storage, &keys::storage_key_by_id(id)).await?
                    {
                        if self.options.revalidate_secondary_against_database {
                            return self.revalidate_cache_hit(api_key, "id", id).await;
                        }
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
                secondary::get_secondary(&*storage, &keys::storage_key_by_id(id)).await
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

    pub async fn update_if_unchanged(
        &self,
        api_key: &ApiKeyRecord,
        expected_updated_at: OffsetDateTime,
    ) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        match self.options.storage {
            ApiKeyStorageMode::Database => {
                self.update_database_if_unchanged(api_key, expected_updated_at)
                    .await
            }
            ApiKeyStorageMode::SecondaryStorage if self.options.fallback_to_database => {
                let updated = self
                    .update_database_if_unchanged(api_key, expected_updated_at)
                    .await?;
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

    pub async fn migrate_metadata_if_needed(&self, api_key: &mut ApiKeyRecord) {
        if !api_key.needs_metadata_migration()
            || matches!(self.options.storage, ApiKeyStorageMode::SecondaryStorage)
                && !self.options.fallback_to_database
        {
            return;
        }
        let Some(metadata) = api_key.normalized_metadata() else {
            return;
        };
        let Some(adapter) = &self.adapter else {
            api_key.metadata = Some(metadata);
            return;
        };
        let update = Update::new(super::API_KEY_MODEL)
            .where_clause(Where::new("id", DbValue::String(api_key.id.clone())))
            .data("metadata", DbValue::Json(metadata.clone()));
        if adapter.update(update).await.is_ok() {
            api_key.metadata = Some(metadata);
        }
    }

    /// Reconcile a secondary-storage cache hit against the database.
    ///
    /// Only used when `revalidate_secondary_against_database` is enabled. A row
    /// that is absent from the database is treated as revoked (the stale cache
    /// entry is purged and `None` is returned); a database record with a newer
    /// `updated_at` refreshes the cache and supersedes the cached copy.
    async fn revalidate_cache_hit(
        &self,
        cached: ApiKeyRecord,
        field: &str,
        value: &str,
    ) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        match self.get_database(field, value).await? {
            None => {
                self.delete_secondary(&cached).await?;
                Ok(None)
            }
            Some(fresh) => {
                if fresh.updated_at > cached.updated_at {
                    self.set_secondary(&fresh).await?;
                    Ok(Some(fresh))
                } else {
                    Ok(Some(cached))
                }
            }
        }
    }

    pub(super) fn secondary_storage(&self) -> Option<Arc<dyn SecondaryStorage>> {
        self.options
            .custom_storage
            .clone()
            .or_else(|| self.context.secondary_storage())
    }

    pub(super) fn required_adapter(&self) -> Result<Arc<dyn DbAdapter>, OpenAuthError> {
        self.adapter.clone().ok_or_else(|| {
            OpenAuthError::Adapter("api-key plugin requires a database adapter".to_owned())
        })
    }
}
