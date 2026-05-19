use std::collections::BTreeSet;

use openauth_core::context::AuthContext;
use openauth_core::db::{DbAdapter, DbRecord, DbValue, FindMany, FindOne, Where, WhereOperator};
use openauth_core::error::OpenAuthError;

use crate::SsoProviderRecord;

const ADMIN_ROLES: [&str; 2] = ["owner", "admin"];

pub async fn accessible_providers(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    user_id: &str,
    providers: Vec<SsoProviderRecord>,
) -> Result<Vec<SsoProviderRecord>, OpenAuthError> {
    if !context.has_plugin("organization") {
        return Ok(providers
            .into_iter()
            .filter(|provider| provider.user_id == user_id)
            .collect());
    }

    let organization_ids = providers
        .iter()
        .filter_map(|provider| provider.organization_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let admin_org_ids = admin_organization_ids(adapter, user_id, &organization_ids).await?;

    Ok(providers
        .into_iter()
        .filter(|provider| {
            if let Some(organization_id) = &provider.organization_id {
                admin_org_ids.contains(organization_id)
            } else {
                provider.user_id == user_id
            }
        })
        .collect())
}

pub async fn can_manage_provider(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    user_id: &str,
    provider: &SsoProviderRecord,
) -> Result<bool, OpenAuthError> {
    let Some(organization_id) = &provider.organization_id else {
        return Ok(provider.user_id == user_id);
    };
    if !context.has_plugin("organization") {
        return Ok(provider.user_id == user_id);
    }
    is_org_admin(adapter, user_id, organization_id).await
}

pub async fn can_register_for_organization(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    user_id: &str,
    organization_id: &str,
) -> Result<bool, OpenAuthError> {
    if !context.has_plugin("organization") {
        return Ok(true);
    }
    is_org_member(adapter, user_id, organization_id).await
}

pub async fn can_verify_provider_domain(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    user_id: &str,
    provider: &SsoProviderRecord,
) -> Result<bool, OpenAuthError> {
    if provider.user_id == user_id {
        return Ok(true);
    }
    let Some(organization_id) = &provider.organization_id else {
        return Ok(false);
    };
    if !context.has_plugin("organization") {
        return Ok(false);
    }
    is_org_member(adapter, user_id, organization_id).await
}

pub async fn organization_id_by_slug(
    context: &AuthContext,
    adapter: &dyn DbAdapter,
    slug: &str,
) -> Result<Option<String>, OpenAuthError> {
    if !context.has_plugin("organization") {
        return Ok(None);
    }
    adapter
        .find_one(
            FindOne::new("organization")
                .where_clause(Where::new("slug", DbValue::String(slug.to_owned()))),
        )
        .await?
        .map(|record| match record.get("id") {
            Some(DbValue::String(id)) => Ok(id.clone()),
            _ => Err(OpenAuthError::Adapter(
                "organization field `id` has invalid type".to_owned(),
            )),
        })
        .transpose()
}

async fn is_org_member(
    adapter: &dyn DbAdapter,
    user_id: &str,
    organization_id: &str,
) -> Result<bool, OpenAuthError> {
    Ok(adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )),
        )
        .await?
        .is_some())
}

async fn is_org_admin(
    adapter: &dyn DbAdapter,
    user_id: &str,
    organization_id: &str,
) -> Result<bool, OpenAuthError> {
    let Some(member) = adapter
        .find_one(
            FindOne::new("member")
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                .where_clause(Where::new(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )),
        )
        .await?
    else {
        return Ok(false);
    };
    member_has_admin_role(&member)
}

async fn admin_organization_ids(
    adapter: &dyn DbAdapter,
    user_id: &str,
    organization_ids: &[String],
) -> Result<BTreeSet<String>, OpenAuthError> {
    if organization_ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let members = adapter
        .find_many(
            FindMany::new("member")
                .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned())))
                .where_clause(
                    Where::new(
                        "organization_id",
                        DbValue::StringArray(organization_ids.to_vec()),
                    )
                    .operator(WhereOperator::In),
                ),
        )
        .await?;
    let mut admin_org_ids = BTreeSet::new();
    for member in members {
        if member_has_admin_role(&member)? {
            if let Some(DbValue::String(organization_id)) = member.get("organization_id") {
                admin_org_ids.insert(organization_id.clone());
            }
        }
    }
    Ok(admin_org_ids)
}

fn member_has_admin_role(member: &DbRecord) -> Result<bool, OpenAuthError> {
    let Some(DbValue::String(role)) = member.get("role") else {
        return Err(OpenAuthError::Adapter(
            "organization member field `role` has invalid type".to_owned(),
        ));
    };
    Ok(role
        .split(',')
        .map(str::trim)
        .any(|role| ADMIN_ROLES.contains(&role)))
}
