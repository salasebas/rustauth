use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use rustauth_core::error::RustAuthError;
use serde::Deserialize;

use crate::organization::additional_fields;
use crate::organization::hooks::{
    AfterAddTeamMember, AfterRemoveTeamMember, BeforeAddTeamMember, BeforeRemoveTeamMember,
    TeamMemberHookData,
};
use crate::organization::http;
use crate::organization::models::TeamMember;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::{has_permission, OrganizationPermission};
use crate::organization::store::OrganizationStore;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamMemberBody {
    team_id: String,
    user_id: String,
}

pub(super) fn add_team_member(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/add-team-member",
        Method::POST,
        super::metadata::options(
            "organizationAddTeamMember",
            vec![
                super::metadata::string("teamId"),
                super::metadata::string("userId"),
            ],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let body: serde_json::Value = http::body(&request)?;
                let input: TeamMemberBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::create_values(
                    &options.schema.team_member.additional_fields,
                    body.as_object().ok_or_else(|| {
                        RustAuthError::Api("request body must be an object".to_owned())
                    })?,
                )?;
                let Some(team) = store.team_by_id(&input.team_id).await? else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                };
                let actor = require_member(&store, &team.organization_id, &session.user.id).await?;
                if !has_permission(&actor.role, &options, OrganizationPermission::TeamUpdate) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER",
                    );
                }
                require_member(&store, &team.organization_id, &input.user_id).await?;
                if let Some(max) = options.teams.maximum_members_per_team {
                    if store.count_team_members(&team.id).await? as usize >= max {
                        return http::organization_error(
                            StatusCode::FORBIDDEN,
                            "TEAM_MEMBER_LIMIT_REACHED",
                        );
                    }
                }
                if let Some(existing) = store.team_member(&team.id, &input.user_id).await? {
                    let mut existing = existing;
                    retain_returned_team_member_fields(&mut existing, &options);
                    return http::json(StatusCode::OK, &existing);
                }
                let Some(organization) = store.organization_by_id(&team.organization_id).await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                let mut team_member_data = TeamMemberHookData {
                    team_id: team.id.clone(),
                    user_id: input.user_id.clone(),
                };
                if let Some(hook) = &options.hooks.before_add_team_member {
                    team_member_data = hook(&BeforeAddTeamMember {
                        organization: organization.clone(),
                        team: team.clone(),
                        team_member: team_member_data,
                        user: session.user.clone(),
                    })?;
                }
                if team_member_data.team_id != team.id || team_member_data.user_id != input.user_id
                {
                    return http::error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_REQUEST_BODY",
                        "Invalid request body",
                    );
                }
                let mut team_member = store
                    .create_team_member(
                        &team_member_data.team_id,
                        &team_member_data.user_id,
                        additional_fields,
                    )
                    .await?;
                retain_returned_team_member_fields(&mut team_member, &options);
                if let Some(hook) = &options.hooks.after_add_team_member {
                    hook(&AfterAddTeamMember {
                        organization,
                        team,
                        team_member: team_member.clone(),
                        user: session.user,
                    })?;
                }
                http::json(StatusCode::OK, &team_member)
            }
        },
    )
}

pub(super) fn remove_team_member(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/remove-team-member",
        Method::POST,
        super::metadata::options(
            "organizationRemoveTeamMember",
            vec![
                super::metadata::string("teamId"),
                super::metadata::string("userId"),
            ],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let input: TeamMemberBody = http::body(&request)?;
                let Some(team) = store.team_by_id(&input.team_id).await? else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                };
                let actor = require_member(&store, &team.organization_id, &session.user.id).await?;
                if !has_permission(&actor.role, &options, OrganizationPermission::TeamUpdate) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER",
                    );
                }
                let Some(team_member) = store.team_member(&team.id, &input.user_id).await? else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                };
                let Some(organization) = store.organization_by_id(&team.organization_id).await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                if let Some(hook) = &options.hooks.before_remove_team_member {
                    hook(&BeforeRemoveTeamMember {
                        organization: organization.clone(),
                        team: team.clone(),
                        team_member: team_member.clone(),
                        user: session.user.clone(),
                    })?;
                }
                store.delete_team_member(&team.id, &input.user_id).await?;
                if let Some(hook) = &options.hooks.after_remove_team_member {
                    hook(&AfterRemoveTeamMember {
                        organization,
                        team,
                        team_member,
                        user: session.user,
                    })?;
                }
                http::json(StatusCode::OK, &serde_json::json!({ "status": true }))
            }
        },
    )
}

pub(super) fn retain_returned_team_member_fields(
    team_member: &mut TeamMember,
    options: &OrganizationOptions,
) {
    additional_fields::retain_returned(
        &mut team_member.additional_fields,
        &options.schema.team_member.additional_fields,
    );
}

fn json_body_error(error: serde_json::Error) -> RustAuthError {
    RustAuthError::Api(error.to_string())
}

async fn require_session(
    context: &rustauth_core::context::AuthContext,
    request: &rustauth_core::api::ApiRequest,
    store: &OrganizationStore<'_>,
) -> Result<http::CurrentSession, RustAuthError> {
    http::current_session(context, request, store)
        .await?
        .ok_or_else(|| RustAuthError::Api("Unauthorized".to_owned()))
}

async fn require_member(
    store: &OrganizationStore<'_>,
    organization_id: &str,
    user_id: &str,
) -> Result<crate::organization::Member, RustAuthError> {
    store
        .member_by_org_user(organization_id, user_id)
        .await?
        .ok_or_else(|| RustAuthError::Api("Member not found".to_owned()))
}
