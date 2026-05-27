//! Adapter-backed SCIM storage helpers.

use openauth_core::crypto::random::generate_random_string;
use openauth_core::db::{
    Create, DbAdapter, DbRecord, DbValue, Delete, FindMany, FindOne, Update, Where,
};
use openauth_core::error::OpenAuthError;
use serde::{Deserialize, Serialize};

use crate::schema::SCIM_PROVIDER_MODEL;

const SCIM_PROVIDER_FIELDS: [&str; 5] =
    ["id", "providerId", "scimToken", "organizationId", "userId"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimProviderRecord {
    pub id: String,
    pub provider_id: String,
    pub scim_token: String,
    pub organization_id: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateScimProviderInput {
    pub provider_id: String,
    pub scim_token: String,
    pub organization_id: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Clone, Copy)]
pub struct ScimProviderStore<'a> {
    adapter: &'a dyn DbAdapter,
}

impl<'a> ScimProviderStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub async fn create(
        &self,
        input: CreateScimProviderInput,
    ) -> Result<ScimProviderRecord, OpenAuthError> {
        let record = self
            .adapter
            .create(
                Create::new(SCIM_PROVIDER_MODEL)
                    .data("id", DbValue::String(generate_random_string(32)))
                    .data("providerId", DbValue::String(input.provider_id))
                    .data("scimToken", DbValue::String(input.scim_token))
                    .data("organizationId", optional_string(input.organization_id))
                    .data("userId", optional_string(input.user_id))
                    .select(SCIM_PROVIDER_FIELDS)
                    .force_allow_id(),
            )
            .await?;

        record_from_db(record)
    }

    pub async fn list(&self) -> Result<Vec<ScimProviderRecord>, OpenAuthError> {
        self.adapter
            .find_many(FindMany::new(SCIM_PROVIDER_MODEL).select(SCIM_PROVIDER_FIELDS))
            .await?
            .into_iter()
            .map(record_from_db)
            .collect()
    }

    pub async fn list_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<ScimProviderRecord>, OpenAuthError> {
        self.adapter
            .find_many(
                FindMany::new(SCIM_PROVIDER_MODEL)
                    .where_clause(Where::new("userId", DbValue::String(user_id.to_owned())))
                    .select(SCIM_PROVIDER_FIELDS),
            )
            .await?
            .into_iter()
            .map(record_from_db)
            .collect()
    }

    pub async fn find_by_provider_id(
        &self,
        provider_id: &str,
    ) -> Result<Option<ScimProviderRecord>, OpenAuthError> {
        self.adapter
            .find_one(
                FindOne::new(SCIM_PROVIDER_MODEL)
                    .where_clause(provider_id_where(provider_id))
                    .select(SCIM_PROVIDER_FIELDS),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    pub async fn find_by_organization_id(
        &self,
        organization_id: &str,
    ) -> Result<Option<ScimProviderRecord>, OpenAuthError> {
        self.adapter
            .find_one(
                FindOne::new(SCIM_PROVIDER_MODEL)
                    .where_clause(Where::new(
                        "organizationId",
                        DbValue::String(organization_id.to_owned()),
                    ))
                    .select(SCIM_PROVIDER_FIELDS),
            )
            .await?
            .map(record_from_db)
            .transpose()
    }

    pub async fn delete(&self, provider_id: &str) -> Result<(), OpenAuthError> {
        self.adapter
            .delete(Delete::new(SCIM_PROVIDER_MODEL).where_clause(provider_id_where(provider_id)))
            .await
    }

    pub async fn upsert(
        &self,
        input: CreateScimProviderInput,
    ) -> Result<ScimProviderRecord, OpenAuthError> {
        if self
            .find_by_provider_id(&input.provider_id)
            .await?
            .is_some()
        {
            self.update(input).await
        } else {
            self.create(input).await
        }
    }

    async fn update(
        &self,
        input: CreateScimProviderInput,
    ) -> Result<ScimProviderRecord, OpenAuthError> {
        self.adapter
            .update(
                Update::new(SCIM_PROVIDER_MODEL)
                    .where_clause(provider_id_where(&input.provider_id))
                    .data("scimToken", DbValue::String(input.scim_token))
                    .data("organizationId", optional_string(input.organization_id))
                    .data("userId", optional_string(input.user_id)),
            )
            .await?;
        self.find_by_provider_id(&input.provider_id)
            .await?
            .ok_or_else(|| {
                OpenAuthError::Adapter(format!(
                    "SCIM provider `{}` was not found after update",
                    input.provider_id
                ))
            })
    }
}

fn provider_id_where(provider_id: &str) -> Where {
    Where::new("providerId", DbValue::String(provider_id.to_owned()))
}

fn optional_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}

fn record_from_db(record: DbRecord) -> Result<ScimProviderRecord, OpenAuthError> {
    Ok(ScimProviderRecord {
        id: required_string(&record, "id")?.to_owned(),
        provider_id: required_string(&record, "providerId")?.to_owned(),
        scim_token: required_string(&record, "scimToken")?.to_owned(),
        organization_id: optional_string_field(&record, "organizationId")?,
        user_id: optional_string_field(&record, "userId")?,
    })
}

fn required_string<'a>(record: &'a DbRecord, field: &str) -> Result<&'a str, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(value),
        Some(_) => Err(invalid_field(field, "string")),
        None => Err(missing_field(field)),
    }
}

fn optional_string_field(record: &DbRecord, field: &str) -> Result<Option<String>, OpenAuthError> {
    match record.get(field) {
        Some(DbValue::String(value)) => Ok(Some(value.to_owned())),
        Some(DbValue::Null) | None => Ok(None),
        Some(_) => Err(invalid_field(field, "string or null")),
    }
}

fn missing_field(field: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("SCIM provider record is missing `{field}`"))
}

fn invalid_field(field: &str, expected: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!(
        "SCIM provider record field `{field}` must be {expected}"
    ))
}
