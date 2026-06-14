use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use rustauth_core::error::RustAuthError;
use serde::Deserialize;

use crate::organization::additional_fields;
use crate::organization::hooks::{
    AfterAddMember, AfterRemoveMember, AfterUpdateMemberRole, BeforeAddMember, BeforeRemoveMember,
    BeforeUpdateMemberRole, MemberHookData,
};
use crate::organization::http;
use crate::organization::models::Member;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::{has_permission, OrganizationPermission};
use crate::organization::store::OrganizationStore;

use super::input::RoleInput;
use super::validation::{is_last_owner, owners, require_session, roles_exist};

pub fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    vec![
        add_member(options.clone()),
        remove_member(options.clone()),
        update_member_role(options.clone()),
        super::members_leave::leave(options.clone()),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddMemberBody {
    user_id: String,
    role: RoleInput,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
}

fn add_member(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/add-member",
        Method::POST,
        super::metadata::options(
            "organizationAddMember",
            vec![
                super::metadata::string("userId"),
                super::metadata::optional_string("organizationId"),
                super::metadata::optional_string("teamId"),
            ],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = http::current_session(&context, &request, &store).await?;
                let body: serde_json::Value = http::body(&request)?;
                let input: AddMemberBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::create_values(
                    &options.schema.member.additional_fields,
                    body.as_object().ok_or_else(|| {
                        RustAuthError::Api("request body must be an object".to_owned())
                    })?,
                )?;
                if input.team_id.is_some() && !options.teams.enabled {
                    return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                }
                let organization_id = super::resolve_organization_id(
                    input.organization_id,
                    session
                        .as_ref()
                        .and_then(|session| session.active_organization_id.as_deref()),
                );
                let Some(organization_id) = organization_id else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let Some(actor) = session else {
                    return http::error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized");
                };
                let Some(actor_member) = store
                    .member_by_org_user(&organization_id, &actor.user.id)
                    .await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                };
                if !has_permission(
                    &actor_member.role,
                    &options,
                    OrganizationPermission::MemberCreate,
                ) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
                    );
                }
                let Some(user) = store.user_by_id(&input.user_id).await? else {
                    return http::error(
                        StatusCode::BAD_REQUEST,
                        "USER_NOT_FOUND",
                        "User not found",
                    );
                };
                if store
                    .member_by_org_user(&organization_id, &user.id)
                    .await?
                    .is_some()
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
                    );
                }
                if crate::organization::limits::membership_limit_reached(
                    &options,
                    &store,
                    &organization_id,
                    &user,
                )
                .await?
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
                    );
                }
                let Some(organization) = store.organization_by_id(&organization_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                let mut member_data = MemberHookData {
                    organization_id: organization_id.clone(),
                    user_id: user.id.clone(),
                    role: input.role.normalized(),
                };
                if !roles_exist(&store, &organization_id, &member_data.role, &options).await? {
                    return http::organization_error(StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
                }
                if let Some(hook) = &options.hooks.before_add_member {
                    member_data = hook(&BeforeAddMember {
                        organization: organization.clone(),
                        user: user.clone(),
                        member: member_data,
                    })?;
                }
                if member_data.organization_id != organization_id || member_data.user_id != user.id
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_REQUEST_BODY",
                    );
                }
                if !roles_exist(&store, &organization_id, &member_data.role, &options).await? {
                    return http::organization_error(StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
                }
                let mut member = store
                    .create_member(
                        &member_data.organization_id,
                        &member_data.user_id,
                        &member_data.role,
                        additional_fields,
                    )
                    .await?;
                retain_returned_member_fields(&mut member, &options);
                if let Some(team_id) = input.team_id.as_deref() {
                    let Some(team) = store.team_by_id(team_id).await? else {
                        return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                    };
                    if team.organization_id != organization_id {
                        return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                    }
                    if let Some(max) = options.teams.maximum_members_per_team {
                        if store.count_team_members(&team.id).await? as usize >= max {
                            return http::organization_error(
                                StatusCode::FORBIDDEN,
                                "TEAM_MEMBER_LIMIT_REACHED",
                            );
                        }
                    }
                    store
                        .create_team_member(&team.id, &user.id, rustauth_core::db::DbRecord::new())
                        .await?;
                }
                if let Some(hook) = &options.hooks.after_add_member {
                    hook(&AfterAddMember {
                        organization,
                        member: member.clone(),
                        user,
                    })?;
                }
                http::json(StatusCode::OK, &member)
            }
        },
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveMemberBody {
    member_id_or_email: String,
    #[serde(default)]
    organization_id: Option<String>,
}

fn remove_member(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/remove-member",
        Method::POST,
        super::metadata::options(
            "organizationRemoveMember",
            vec![
                super::metadata::string("memberIdOrEmail"),
                super::metadata::optional_string("organizationId"),
            ],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let input: RemoveMemberBody = http::body(&request)?;
                let Some(organization_id) = super::resolve_organization_id(
                    input.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let Some(actor_member) = store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                };
                let target = if input.member_id_or_email.contains('@') {
                    store
                        .member_by_email(&organization_id, &input.member_id_or_email)
                        .await?
                } else {
                    store.member_by_id(&input.member_id_or_email).await?
                };
                let Some(target) = target else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                };
                if target.organization_id != organization_id {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                }
                if is_last_owner(&store, &organization_id, &target, &options).await? {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
                    );
                }
                if !has_permission(
                    &actor_member.role,
                    &options,
                    OrganizationPermission::MemberDelete,
                ) {
                    return http::organization_error(
                        StatusCode::UNAUTHORIZED,
                        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",
                    );
                }
                let Some(organization) = store.organization_by_id(&organization_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                if let Some(hook) = &options.hooks.before_remove_member {
                    hook(&BeforeRemoveMember {
                        organization: organization.clone(),
                        member: target.clone(),
                        user: session.user.clone(),
                    })?;
                }
                if options.teams.enabled {
                    store
                        .delete_team_members_for_user(&target.organization_id, &target.user_id)
                        .await?;
                }
                store.delete_member(&target.id).await?;
                if let Some(hook) = &options.hooks.after_remove_member {
                    hook(&AfterRemoveMember {
                        organization,
                        member: target.clone(),
                        user: session.user.clone(),
                    })?;
                }
                let cookies = if target.user_id == session.user.id
                    && session.active_organization_id.as_deref() == Some(&target.organization_id)
                {
                    store
                        .set_active_organization(&session.session.token, None)
                        .await?;
                    if options.teams.enabled {
                        store.set_active_team(&session.session.token, None).await?;
                    }
                    http::refreshed_session_cookies(&context, &session.session, &session.user)?
                } else {
                    Vec::new()
                };
                http::json_with_cookies(
                    StatusCode::OK,
                    &serde_json::json!({ "member": target }),
                    cookies,
                )
            }
        },
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateMemberRoleBody {
    member_id: String,
    role: RoleInput,
    #[serde(default)]
    organization_id: Option<String>,
}

fn update_member_role(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/update-member-role",
        Method::POST,
        super::metadata::options(
            "organizationUpdateMemberRole",
            vec![
                super::metadata::string("memberId"),
                super::metadata::optional_string("organizationId"),
            ],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let body: serde_json::Value = http::body(&request)?;
                let input: UpdateMemberRoleBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::update_values(
                    &options.schema.member.additional_fields,
                    body.as_object().ok_or_else(|| {
                        RustAuthError::Api("request body must be an object".to_owned())
                    })?,
                )?;
                let Some(organization_id) = super::resolve_organization_id(
                    input.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let Some(actor_member) = store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                };
                let Some(target) = store.member_by_id(&input.member_id).await? else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                };
                if target.organization_id != organization_id {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
                    );
                }
                let mut next_role = input.role.normalized();
                if !roles_exist(&store, &organization_id, &next_role, &options).await? {
                    return http::organization_error(StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
                }
                if !actor_member
                    .role
                    .split(',')
                    .any(|role| role.trim() == options.creator_role)
                    && (target
                        .role
                        .split(',')
                        .any(|role| role.trim() == options.creator_role)
                        || next_role
                            .split(',')
                            .any(|role| role.trim() == options.creator_role))
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
                    );
                }
                if target.user_id == session.user.id
                    && target
                        .role
                        .split(',')
                        .any(|role| role.trim() == options.creator_role)
                    && !next_role
                        .split(',')
                        .any(|role| role.trim() == options.creator_role)
                    && owners(&store, &organization_id, &options).await? <= 1
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER",
                    );
                }
                if !has_permission(
                    &actor_member.role,
                    &options,
                    OrganizationPermission::MemberUpdate,
                ) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
                    );
                }
                let Some(organization) = store.organization_by_id(&organization_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                if let Some(hook) = &options.hooks.before_update_member_role {
                    next_role = hook(&BeforeUpdateMemberRole {
                        organization: organization.clone(),
                        member: target.clone(),
                        new_role: next_role,
                        user: session.user.clone(),
                    })?
                    .role;
                    if !roles_exist(&store, &organization_id, &next_role, &options).await? {
                        return http::organization_error(StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
                    }
                    if target.user_id == session.user.id
                        && target
                            .role
                            .split(',')
                            .any(|role| role.trim() == options.creator_role)
                        && !next_role
                            .split(',')
                            .any(|role| role.trim() == options.creator_role)
                        && owners(&store, &organization_id, &options).await? <= 1
                    {
                        return http::organization_error(
                            StatusCode::BAD_REQUEST,
                            "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER",
                        );
                    }
                }
                match store
                    .update_member_role(&target.id, &next_role, additional_fields)
                    .await?
                {
                    Some(mut member) => {
                        retain_returned_member_fields(&mut member, &options);
                        if let Some(hook) = &options.hooks.after_update_member_role {
                            hook(&AfterUpdateMemberRole {
                                organization,
                                member: member.clone(),
                                previous_role: target.role,
                                user: session.user.clone(),
                            })?;
                        }
                        http::json(StatusCode::OK, &member)
                    }
                    None => http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND"),
                }
            }
        },
    )
}

fn retain_returned_member_fields(member: &mut Member, options: &OrganizationOptions) {
    additional_fields::retain_returned(
        &mut member.additional_fields,
        &options.schema.member.additional_fields,
    );
}

fn json_body_error(error: serde_json::Error) -> RustAuthError {
    RustAuthError::Api(error.to_string())
}
