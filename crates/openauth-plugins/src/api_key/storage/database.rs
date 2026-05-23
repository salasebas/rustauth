use openauth_core::db::{
    Create, DbValue, Delete, DeleteMany, FindOne, Update, Where, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use time::OffsetDateTime;

use super::ApiKeyStore;
use crate::api_key::models::{record_from_db, ApiKeyRecord, API_KEY_FIELDS};
use crate::api_key::API_KEY_MODEL;

impl ApiKeyStore<'_> {
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
