use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::organization::hooks::{
    AfterAcceptInvitation, AfterCancelInvitation, AfterRejectInvitation, BeforeAcceptInvitation,
    BeforeCancelInvitation, BeforeRejectInvitation,
};
use crate::organization::http;
use crate::organization::models::InvitationStatus;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::{has_permission, OrganizationPermission};
use crate::organization::store::OrganizationStore;

use super::validation::require_session;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InvitationIdBody {
    invitation_id: String,
}

pub(super) fn accept_invitation(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/accept-invitation",
        Method::POST,
        super::metadata::options(
            "organizationAcceptInvitation",
            vec![super::metadata::string("invitationId")],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let input: InvitationIdBody = http::body(&request)?;
                let Some(invitation) = store.invitation_by_id(&input.invitation_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "INVITATION_NOT_FOUND",
                    );
                };
                if invitation.status != InvitationStatus::Pending
                    || invitation.expires_at < OffsetDateTime::now_utc()
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "INVITATION_NOT_FOUND",
                    );
                }
                if invitation.email.to_lowercase() != session.user.email.to_lowercase() {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
                    );
                }
                if options.require_email_verification_on_invitation && !session.user.email_verified
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
                    );
                }
                if store.count_members(&invitation.organization_id).await? as usize
                    >= options.membership_limit
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
                    );
                }
                if store
                    .member_by_org_user(&invitation.organization_id, &session.user.id)
                    .await?
                    .is_some()
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
                    );
                }
                let invitation_team_ids = if options.teams.enabled {
                    invitation
                        .team_id
                        .as_deref()
                        .map(parse_team_ids)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                for team_id in &invitation_team_ids {
                    let Some(team) = store.team_by_id(team_id).await? else {
                        return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                    };
                    if team.organization_id != invitation.organization_id {
                        return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                    }
                    if let Some(max) = options.teams.maximum_members_per_team {
                        if store.count_team_members(team_id).await? as usize >= max {
                            return http::organization_error(
                                StatusCode::FORBIDDEN,
                                "TEAM_MEMBER_LIMIT_REACHED",
                            );
                        }
                    }
                }
                let Some(organization) = store
                    .organization_by_id(&invitation.organization_id)
                    .await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                if let Some(hook) = &options.hooks.before_accept_invitation {
                    hook(&BeforeAcceptInvitation {
                        organization: organization.clone(),
                        invitation: invitation.clone(),
                        user: session.user.clone(),
                    })?;
                }
                let accepted = store
                    .update_invitation_status(&invitation.id, InvitationStatus::Accepted)
                    .await?;
                let member = store
                    .create_member(
                        &invitation.organization_id,
                        &session.user.id,
                        &invitation.role,
                        openauth_core::db::DbRecord::new(),
                    )
                    .await?;
                if options.teams.enabled {
                    for team_id in invitation_team_ids {
                        if store
                            .team_member(&team_id, &session.user.id)
                            .await?
                            .is_none()
                        {
                            store
                                .create_team_member(
                                    &team_id,
                                    &session.user.id,
                                    openauth_core::db::DbRecord::new(),
                                )
                                .await?;
                        }
                    }
                }
                if let (Some(hook), Some(accepted)) =
                    (&options.hooks.after_accept_invitation, accepted.clone())
                {
                    hook(&AfterAcceptInvitation {
                        organization,
                        invitation: accepted,
                        member: member.clone(),
                        user: session.user.clone(),
                    })?;
                }
                store
                    .set_active_organization(
                        &session.session.token,
                        Some(&invitation.organization_id),
                    )
                    .await?;
                http::json_with_cookies(
                    StatusCode::OK,
                    &serde_json::json!({ "invitation": accepted, "member": member }),
                    http::refreshed_session_cookies(context, &session.session, &session.user)?,
                )
            })
        },
    )
}

fn parse_team_ids(team_ids: &str) -> Vec<String> {
    team_ids
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) fn reject_invitation(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/reject-invitation",
        Method::POST,
        super::metadata::options(
            "organizationRejectInvitation",
            vec![super::metadata::string("invitationId")],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let input: InvitationIdBody = http::body(&request)?;
                let Some(invitation) = store.invitation_by_id(&input.invitation_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "INVITATION_NOT_FOUND",
                    );
                };
                if invitation.email.to_lowercase() != session.user.email.to_lowercase() {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION",
                    );
                }
                if options.require_email_verification_on_invitation && !session.user.email_verified
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
                    );
                }
                let Some(organization) = store
                    .organization_by_id(&invitation.organization_id)
                    .await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                if let Some(hook) = &options.hooks.before_reject_invitation {
                    hook(&BeforeRejectInvitation {
                        organization: organization.clone(),
                        invitation: invitation.clone(),
                        user: session.user.clone(),
                    })?;
                }
                let rejected = store
                    .update_invitation_status(&invitation.id, InvitationStatus::Rejected)
                    .await?;
                if let (Some(hook), Some(rejected)) =
                    (&options.hooks.after_reject_invitation, rejected.clone())
                {
                    hook(&AfterRejectInvitation {
                        organization,
                        invitation: rejected,
                        user: session.user,
                    })?;
                }
                http::json(
                    StatusCode::OK,
                    &serde_json::json!({ "invitation": rejected, "member": null }),
                )
            })
        },
    )
}

pub(super) fn cancel_invitation(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/cancel-invitation",
        Method::POST,
        super::metadata::options(
            "organizationCancelInvitation",
            vec![super::metadata::string("invitationId")],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let input: InvitationIdBody = http::body(&request)?;
                let Some(invitation) = store.invitation_by_id(&input.invitation_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "INVITATION_NOT_FOUND",
                    );
                };
                let Some(actor_member) = store
                    .member_by_org_user(&invitation.organization_id, &session.user.id)
                    .await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                };
                if !has_permission(
                    &actor_member.role,
                    &options,
                    OrganizationPermission::InvitationCancel,
                ) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION",
                    );
                }
                let Some(organization) = store
                    .organization_by_id(&invitation.organization_id)
                    .await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                if let Some(hook) = &options.hooks.before_cancel_invitation {
                    hook(&BeforeCancelInvitation {
                        organization: organization.clone(),
                        invitation: invitation.clone(),
                        cancelled_by: session.user.clone(),
                    })?;
                }
                let canceled = store
                    .update_invitation_status(&invitation.id, InvitationStatus::Canceled)
                    .await?;
                if let (Some(hook), Some(canceled)) =
                    (&options.hooks.after_cancel_invitation, canceled.clone())
                {
                    hook(&AfterCancelInvitation {
                        organization,
                        invitation: canceled,
                        cancelled_by: session.user,
                    })?;
                }
                http::json(
                    StatusCode::OK,
                    &serde_json::json!({ "invitation": canceled }),
                )
            })
        },
    )
}
