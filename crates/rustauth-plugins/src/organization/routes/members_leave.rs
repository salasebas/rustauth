use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};
use serde::Deserialize;

use crate::organization::hooks::{AfterRemoveMember, BeforeRemoveMember};
use crate::organization::http;
use crate::organization::options::OrganizationOptions;
use crate::organization::store::OrganizationStore;

use super::validation::{is_last_owner, require_session};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeaveBody {
    #[serde(default)]
    organization_id: Option<String>,
}

pub(super) fn leave(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/leave",
        Method::POST,
        AuthEndpointOptions::new().operation_id("organizationLeave"),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let body: LeaveBody = http::body(&request)?;
                let Some(organization_id) = super::resolve_organization_id(
                    body.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let Some(member) = store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                };
                if is_last_owner(&store, &organization_id, &member, &options).await? {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
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
                        member: member.clone(),
                        user: session.user.clone(),
                    })?;
                }
                if options.teams.enabled {
                    store
                        .delete_team_members_for_user(&organization_id, &session.user.id)
                        .await?;
                }
                store.delete_member(&member.id).await?;
                if let Some(hook) = &options.hooks.after_remove_member {
                    hook(&AfterRemoveMember {
                        organization,
                        member: member.clone(),
                        user: session.user.clone(),
                    })?;
                }
                let cookies = if session.active_organization_id.as_deref() == Some(&organization_id)
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
                    &serde_json::json!({ "member": member }),
                    cookies,
                )
            }
        },
    )
}
