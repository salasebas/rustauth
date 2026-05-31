use openauth_core::db::{
    Create, DbValue, Delete, DeleteMany, FindMany, FindOne, Update, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use time::OffsetDateTime;

use super::ApiKeyStore;
use crate::api_key::models::{record_from_db, ApiKeyRecord, API_KEY_FIELDS};
use crate::api_key::options::ApiKeyStorageMode;
use crate::api_key::API_KEY_MODEL;

impl ApiKeyStore<'_> {
    pub async fn delete_expired(&self, now: OffsetDateTime) -> Result<u64, OpenAuthError> {
        let Some(adapter) = &self.adapter else {
            return Ok(0);
        };
        // In secondary-storage fallback mode a database-only delete would leave
        // the hash/id/ref cache entries behind, so the expired key would keep
        // resolving from the cache. Evict each expired key from the cache first
        // to keep cleanup consistent with the plugin's own delete path.
        if matches!(self.options.storage, ApiKeyStorageMode::SecondaryStorage)
            && self.options.fallback_to_database
            && self.secondary_storage().is_some()
        {
            for api_key in self.find_expired(now).await? {
                self.delete_secondary(&api_key).await?;
            }
        }
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

    pub(super) async fn find_expired(
        &self,
        now: OffsetDateTime,
    ) -> Result<Vec<ApiKeyRecord>, OpenAuthError> {
        let Some(adapter) = &self.adapter else {
            return Ok(Vec::new());
        };
        adapter
            .find_many(
                FindMany::new(API_KEY_MODEL)
                    .where_clause(
                        Where::new("expires_at", DbValue::Timestamp(now))
                            .operator(WhereOperator::Lt),
                    )
                    .where_clause(
                        Where::new("expires_at", DbValue::Null).operator(WhereOperator::Ne),
                    )
                    .select(API_KEY_FIELDS),
            )
            .await?
            .into_iter()
            .map(record_from_db)
            .collect()
    }

    pub(super) async fn create_database(
        &self,
        api_key: ApiKeyRecord,
    ) -> Result<ApiKeyRecord, OpenAuthError> {
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

    pub(super) async fn get_database(
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

    pub(super) async fn update_database(
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

    pub(super) async fn update_database_if_unchanged(
        &self,
        api_key: &ApiKeyRecord,
        expected_updated_at: OffsetDateTime,
    ) -> Result<Option<ApiKeyRecord>, OpenAuthError> {
        let adapter = self.required_adapter()?;
        let mut data = api_key.to_record();
        data.shift_remove("id");
        adapter
            .update(Update {
                model: API_KEY_MODEL.to_owned(),
                where_clauses: vec![
                    Where::new("id", DbValue::String(api_key.id.clone())),
                    Where::new("updated_at", DbValue::Timestamp(expected_updated_at)),
                ],
                data,
            })
            .await?
            .map(record_from_db)
            .transpose()
    }

    pub(super) async fn delete_database(&self, id: &str) -> Result<(), OpenAuthError> {
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
}
