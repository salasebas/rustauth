use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::db::{
    Count, Create, DbRecord, DbValue, Delete, FindMany, FindOne, Update, Where,
};
use rustauth_core::error::RustAuthError;
use time::OffsetDateTime;

use super::{id_where, OrganizationStore, ID_LENGTH};
use crate::organization::record::organization_role_from_record;
use crate::organization::OrganizationRoleRecord;

impl<'a> OrganizationStore<'a> {
    pub async fn create_organization_role(
        &self,
        organization_id: &str,
        role: &str,
        permission: serde_json::Value,
        additional_fields: DbRecord,
    ) -> Result<OrganizationRoleRecord, RustAuthError> {
        let now = OffsetDateTime::now_utc();
        let mut create = Create::new("organization_role")
            .data("id", DbValue::String(generate_random_string(ID_LENGTH)))
            .data(
                "organization_id",
                DbValue::String(organization_id.to_owned()),
            )
            .data("role", DbValue::String(role.to_owned()))
            .data("permission", DbValue::Json(permission))
            .data("created_at", DbValue::Timestamp(now))
            .data("updated_at", DbValue::Timestamp(now))
            .force_allow_id();
        for (field, value) in additional_fields {
            create = create.data(field, value);
        }
        let record = self.adapter().create(create).await?;
        organization_role_from_record(&record)
    }

    pub async fn organization_role_by_id(
        &self,
        id: &str,
    ) -> Result<Option<OrganizationRoleRecord>, RustAuthError> {
        self.adapter()
            .find_one(FindOne::new("organization_role").where_clause(id_where(id)))
            .await?
            .map(|record| organization_role_from_record(&record))
            .transpose()
    }

    pub async fn organization_role_by_name(
        &self,
        organization_id: &str,
        role: &str,
    ) -> Result<Option<OrganizationRoleRecord>, RustAuthError> {
        self.adapter()
            .find_one(
                FindOne::new("organization_role")
                    .where_clause(Where::new(
                        "organization_id",
                        DbValue::String(organization_id.to_owned()),
                    ))
                    .where_clause(Where::new("role", DbValue::String(role.to_owned()))),
            )
            .await?
            .map(|record| organization_role_from_record(&record))
            .transpose()
    }

    pub async fn organization_roles(
        &self,
        organization_id: &str,
    ) -> Result<Vec<OrganizationRoleRecord>, RustAuthError> {
        self.adapter()
            .find_many(FindMany::new("organization_role").where_clause(Where::new(
                "organization_id",
                DbValue::String(organization_id.to_owned()),
            )))
            .await?
            .iter()
            .map(organization_role_from_record)
            .collect()
    }

    pub async fn count_organization_roles(
        &self,
        organization_id: &str,
    ) -> Result<u64, RustAuthError> {
        self.adapter()
            .count(Count::new("organization_role").where_clause(Where::new(
                "organization_id",
                DbValue::String(organization_id.to_owned()),
            )))
            .await
    }

    pub async fn update_organization_role(
        &self,
        id: &str,
        role: Option<&str>,
        permission: Option<serde_json::Value>,
        additional_fields: DbRecord,
    ) -> Result<Option<OrganizationRoleRecord>, RustAuthError> {
        let mut update = Update::new("organization_role")
            .where_clause(id_where(id))
            .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()));
        if let Some(role) = role {
            update = update.data("role", DbValue::String(role.to_owned()));
        }
        if let Some(permission) = permission {
            update = update.data("permission", DbValue::Json(permission));
        }
        for (field, value) in additional_fields {
            update = update.data(field, value);
        }
        self.adapter()
            .update(update)
            .await?
            .map(|record| organization_role_from_record(&record))
            .transpose()
    }

    pub async fn delete_organization_role(&self, id: &str) -> Result<(), RustAuthError> {
        self.adapter()
            .delete(Delete::new("organization_role").where_clause(id_where(id)))
            .await
    }
}
