use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use rustauth_core::error::RustAuthError;
use serde::Deserialize;

use crate::organization::additional_fields;
use crate::organization::hooks::{
    AfterCreateTeam, AfterDeleteTeam, AfterUpdateTeam, BeforeCreateTeam, BeforeDeleteTeam,
    BeforeUpdateTeam, TeamHookData,
};
use crate::organization::http;
use crate::organization::models::Team;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::{has_permission, OrganizationPermission};
use crate::organization::store::OrganizationStore;

pub fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    if !options.teams.enabled {
        return Vec::new();
    }
    vec![
        create_team(options.clone()),
        remove_team(options.clone()),
        update_team(options.clone()),
        set_active_team(options.clone()),
        super::team_members::add_team_member(options.clone()),
        super::team_members::remove_team_member(options),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamBody {
    name: String,
    #[serde(default)]
    organization_id: Option<String>,
}

fn create_team(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/create-team",
        Method::POST,
        super::metadata::options(
            "organizationCreateTeam",
            vec![
                super::metadata::string("name"),
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
                let input: TeamBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::create_values(
                    &options.schema.team.additional_fields,
                    body.as_object().ok_or_else(|| {
                        RustAuthError::Api("request body must be an object".to_owned())
                    })?,
                )?;
                if input.name.trim().is_empty() {
                    return http::error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_REQUEST_BODY",
                        "Invalid request body",
                    );
                }
                let Some(organization_id) = super::resolve_organization_id(
                    input.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let actor = require_member(&store, &organization_id, &session.user.id).await?;
                if !has_permission(&actor.role, &options, OrganizationPermission::TeamCreate) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
                    );
                }
                if let Some(max) = options.teams.maximum_teams {
                    if store.teams_for_organization(&organization_id).await?.len() >= max {
                        return http::organization_error(
                            StatusCode::BAD_REQUEST,
                            "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
                        );
                    }
                }
                let Some(organization) = store.organization_by_id(&organization_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                let mut team_data = TeamHookData {
                    organization_id: organization_id.clone(),
                    name: input.name.trim().to_owned(),
                };
                if let Some(hook) = &options.hooks.before_create_team {
                    team_data = hook(&BeforeCreateTeam {
                        organization: organization.clone(),
                        team: team_data,
                        user: session.user.clone(),
                    })?;
                }
                if team_data.organization_id != organization_id || team_data.name.trim().is_empty()
                {
                    return http::error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_REQUEST_BODY",
                        "Invalid request body",
                    );
                }
                let mut team = store
                    .create_team(&organization_id, team_data.name.trim(), additional_fields)
                    .await?;
                retain_returned_team_fields(&mut team, &options);
                store
                    .create_team_member(
                        &team.id,
                        &session.user.id,
                        rustauth_core::db::DbRecord::new(),
                    )
                    .await?;
                if let Some(hook) = &options.hooks.after_create_team {
                    hook(&AfterCreateTeam {
                        organization,
                        team: team.clone(),
                        user: session.user,
                    })?;
                }
                http::json(StatusCode::OK, &team)
            }
        },
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamIdBody {
    team_id: String,
    #[serde(default)]
    organization_id: Option<String>,
}

fn remove_team(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/remove-team",
        Method::POST,
        super::metadata::options(
            "organizationRemoveTeam",
            vec![
                super::metadata::string("teamId"),
                super::metadata::optional_string("organizationId"),
            ],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let input: TeamIdBody = http::body(&request)?;
                let Some(team) = store.team_by_id(&input.team_id).await? else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                };
                let organization_id = input
                    .organization_id
                    .unwrap_or_else(|| team.organization_id.clone());
                if team.organization_id != organization_id {
                    return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                }
                let actor = require_member(&store, &organization_id, &session.user.id).await?;
                if !has_permission(&actor.role, &options, OrganizationPermission::TeamDelete) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
                    );
                }
                if !options.teams.allow_removing_all_teams
                    && store.teams_for_organization(&organization_id).await?.len() <= 1
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "UNABLE_TO_REMOVE_LAST_TEAM",
                    );
                }
                let Some(organization) = store.organization_by_id(&organization_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                if let Some(hook) = &options.hooks.before_delete_team {
                    hook(&BeforeDeleteTeam {
                        organization: organization.clone(),
                        team: team.clone(),
                        user: session.user.clone(),
                    })?;
                }
                let cookies = if session.active_team_id.as_deref() == Some(&team.id) {
                    store.set_active_team(&session.session.token, None).await?;
                    http::refreshed_session_cookies(&context, &session.session, &session.user)?
                } else {
                    Vec::new()
                };
                store.delete_team(&team.id).await?;
                if let Some(hook) = &options.hooks.after_delete_team {
                    hook(&AfterDeleteTeam {
                        organization,
                        team: team.clone(),
                        user: session.user,
                    })?;
                }
                http::json_with_cookies(
                    StatusCode::OK,
                    &serde_json::json!({ "team": team }),
                    cookies,
                )
            }
        },
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTeamBody {
    team_id: String,
    name: String,
}

fn update_team(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/update-team",
        Method::POST,
        super::metadata::options(
            "organizationUpdateTeam",
            vec![
                super::metadata::string("teamId"),
                super::metadata::string("name"),
            ],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let body: serde_json::Value = http::body(&request)?;
                let input: UpdateTeamBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::update_values(
                    &options.schema.team.additional_fields,
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
                        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM",
                    );
                }
                let Some(organization) = store.organization_by_id(&team.organization_id).await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                let mut updates = TeamHookData {
                    organization_id: team.organization_id.clone(),
                    name: input.name.trim().to_owned(),
                };
                if let Some(hook) = &options.hooks.before_update_team {
                    updates = hook(&BeforeUpdateTeam {
                        organization: organization.clone(),
                        team: team.clone(),
                        updates,
                        user: session.user.clone(),
                    })?;
                }
                if updates.organization_id != team.organization_id || updates.name.trim().is_empty()
                {
                    return http::error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_REQUEST_BODY",
                        "Invalid request body",
                    );
                }
                let mut updated = store
                    .update_team(&team.id, updates.name.trim(), additional_fields)
                    .await?;
                if let Some(team) = &mut updated {
                    retain_returned_team_fields(team, &options);
                }
                if let Some(hook) = &options.hooks.after_update_team {
                    hook(&AfterUpdateTeam {
                        organization,
                        team: updated.clone(),
                        user: session.user,
                    })?;
                }
                http::json(StatusCode::OK, &updated)
            }
        },
    )
}

fn set_active_team(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/set-active-team",
        Method::POST,
        super::metadata::options(
            "organizationSetActiveTeam",
            vec![super::metadata::string("teamId")],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let input: TeamIdBody = http::body(&request)?;
                let Some(team) = store.team_by_id(&input.team_id).await? else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                };
                require_member(&store, &team.organization_id, &session.user.id).await?;
                if store
                    .team_member(&team.id, &session.user.id)
                    .await?
                    .is_none()
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
                    );
                }
                store
                    .set_active_team(&session.session.token, Some(&team.id))
                    .await?;
                let mut team = team;
                retain_returned_team_fields(&mut team, &options);
                http::json_with_cookies(
                    StatusCode::OK,
                    &team,
                    http::refreshed_session_cookies(&context, &session.session, &session.user)?,
                )
            }
        },
    )
}

pub(super) fn retain_returned_team_fields(team: &mut Team, options: &OrganizationOptions) {
    additional_fields::retain_returned(
        &mut team.additional_fields,
        &options.schema.team.additional_fields,
    );
}

fn json_body_error(error: serde_json::Error) -> RustAuthError {
    RustAuthError::Api(error.to_string())
}

async fn require_session(
    context: &rustauth_core::context::AuthContext,
    request: &rustauth_core::api::ApiRequest,
    store: &OrganizationStore<'_>,
) -> Result<http::CurrentSession, rustauth_core::error::RustAuthError> {
    http::current_session(context, request, store)
        .await?
        .ok_or_else(|| rustauth_core::error::RustAuthError::Api("Unauthorized".to_owned()))
}

async fn require_member(
    store: &OrganizationStore<'_>,
    organization_id: &str,
    user_id: &str,
) -> Result<crate::organization::Member, rustauth_core::error::RustAuthError> {
    store
        .member_by_org_user(organization_id, user_id)
        .await?
        .ok_or_else(|| rustauth_core::error::RustAuthError::Api("Member not found".to_owned()))
}
