use rustauth_core::db::{DbAdapter, User};
use rustauth_core::error::RustAuthError;

use super::additional_fields;
use super::hooks::{AfterAddMember, BeforeAddMember, MemberHookData};
use super::options::OrganizationOptions;
use super::permissions::is_known_static_role;
use super::store::OrganizationStore;
use super::Member;

#[derive(Debug, Clone)]
pub struct ProvisionOrganizationMemberInput<'a> {
    pub organization_id: &'a str,
    pub user: &'a User,
    pub role: &'a str,
}

/// Provision an organization membership through the same server-side
/// semantics used by the organization plugin routes.
pub async fn provision_organization_member(
    adapter: &dyn DbAdapter,
    options: &OrganizationOptions,
    input: ProvisionOrganizationMemberInput<'_>,
) -> Result<Option<Member>, RustAuthError> {
    let store = OrganizationStore::new(adapter);
    if store
        .member_by_org_user(input.organization_id, &input.user.id)
        .await?
        .is_some()
    {
        return Ok(None);
    }
    if super::limits::membership_limit_reached(options, &store, input.organization_id, input.user)
        .await?
    {
        return Err(RustAuthError::Api(
            "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED".to_owned(),
        ));
    }
    let Some(organization) = store.organization_by_id(input.organization_id).await? else {
        return Err(RustAuthError::Api("ORGANIZATION_NOT_FOUND".to_owned()));
    };
    let mut member_data = MemberHookData {
        organization_id: input.organization_id.to_owned(),
        user_id: input.user.id.clone(),
        role: super::permissions::parse_roles(input.role),
    };
    if !roles_exist(&store, input.organization_id, &member_data.role, options).await? {
        return Err(RustAuthError::Api("ROLE_NOT_FOUND".to_owned()));
    }
    if let Some(hook) = &options.hooks.before_add_member {
        member_data = hook(&BeforeAddMember {
            organization: organization.clone(),
            user: input.user.clone(),
            member: member_data,
        })?;
    }
    if member_data.organization_id != input.organization_id || member_data.user_id != input.user.id
    {
        return Err(RustAuthError::Api("INVALID_REQUEST_BODY".to_owned()));
    }
    if !roles_exist(&store, input.organization_id, &member_data.role, options).await? {
        return Err(RustAuthError::Api("ROLE_NOT_FOUND".to_owned()));
    }
    let mut member = store
        .create_member(
            &member_data.organization_id,
            &member_data.user_id,
            &member_data.role,
            rustauth_core::db::DbRecord::new(),
        )
        .await?;
    additional_fields::retain_returned(
        &mut member.additional_fields,
        &options.schema.member.additional_fields,
    );
    if let Some(hook) = &options.hooks.after_add_member {
        hook(&AfterAddMember {
            organization,
            member: member.clone(),
            user: input.user.clone(),
        })?;
    }
    Ok(Some(member))
}

async fn roles_exist(
    store: &OrganizationStore<'_>,
    organization_id: &str,
    roles: &str,
    options: &OrganizationOptions,
) -> Result<bool, RustAuthError> {
    for role in roles
        .split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
    {
        if is_known_static_role(role, options) {
            continue;
        }
        if !options.dynamic_access_control.enabled {
            return Ok(false);
        }
        if store
            .organization_role_by_name(organization_id, role)
            .await?
            .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}
