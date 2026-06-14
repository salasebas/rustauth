use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};

use crate::organization::http;
use crate::organization::options::OrganizationOptions;
use crate::organization::store::OrganizationStore;

use super::team_members::retain_returned_team_member_fields;
use super::teams::retain_returned_team_fields;

pub(super) fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    if !options.teams.enabled {
        return Vec::new();
    }
    vec![
        list_teams(options.clone()),
        list_user_teams(options.clone()),
        list_team_members(options),
    ]
}

fn list_teams(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/list-teams",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationListTeams"),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let Some(organization_id) = session.active_organization_id else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                require_member(&store, &organization_id, &session.user.id).await?;
                let mut teams = store.teams_for_organization(&organization_id).await?;
                for team in &mut teams {
                    retain_returned_team_fields(team, &options);
                }
                http::json(StatusCode::OK, &teams)
            }
        },
    )
}

fn list_user_teams(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/list-user-teams",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationListUserTeams"),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let mut teams = Vec::new();
                for organization in store.organizations_for_user(&session.user.id).await? {
                    for team in store.teams_for_organization(&organization.id).await? {
                        if store
                            .team_member(&team.id, &session.user.id)
                            .await?
                            .is_some()
                        {
                            let mut team = team;
                            retain_returned_team_fields(&mut team, &options);
                            teams.push(team);
                        }
                    }
                }
                http::json(StatusCode::OK, &teams)
            }
        },
    )
}

fn list_team_members(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/list-team-members",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationListTeamMembers"),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let Some(team_id) = query_param(&request, "teamId")
                    .or_else(|| query_param(&request, "team_id"))
                    .or_else(|| session.active_team_id.clone())
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM",
                    );
                };
                let Some(team) = store.team_by_id(&team_id).await? else {
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
                        "YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM",
                    );
                }
                let mut members = store.team_members(&team.id).await?;
                for member in &mut members {
                    retain_returned_team_member_fields(member, &options);
                }
                http::json(StatusCode::OK, &members)
            }
        },
    )
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

fn query_param(request: &rustauth_core::api::ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
    })
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
