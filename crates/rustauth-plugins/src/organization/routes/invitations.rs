use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use rustauth_core::error::RustAuthError;
use rustauth_core::outbound::dispatch_outbound;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::organization::additional_fields;
use crate::organization::hooks::{
    AfterCreateInvitation, BeforeCreateInvitation, InvitationHookData,
};
use crate::organization::http;
use crate::organization::models::{Invitation, InvitationStatus};
use crate::organization::options::{InvitationEmail, OrganizationOptions};
use crate::organization::permissions::{has_permission, OrganizationPermission};
use crate::organization::store::{CreateInvitationInput, OrganizationStore};

use super::input::RoleInput;
use super::validation::{require_session, roles_exist, valid_email};

pub fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    vec![
        create_invitation(options.clone()),
        super::invitation_actions::accept_invitation(options.clone()),
        super::invitation_actions::reject_invitation(options.clone()),
        super::invitation_actions::cancel_invitation(options.clone()),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteBody {
    email: String,
    role: RoleInput,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    resend: bool,
}

fn create_invitation(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/invite-member",
        Method::POST,
        super::metadata::options(
            "organizationInviteMember",
            vec![
                super::metadata::string("email"),
                super::metadata::optional_string("organizationId"),
                super::metadata::optional_string("teamId"),
                super::metadata::optional_bool("resend"),
            ],
        ),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let body: serde_json::Value = http::body(&request)?;
                let input: InviteBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::create_values(
                    &options.schema.invitation.additional_fields,
                    body.as_object().ok_or_else(|| {
                        RustAuthError::Api("request body must be an object".to_owned())
                    })?,
                )?;
                if input.team_id.is_some() && !options.teams.enabled {
                    return http::organization_error(StatusCode::BAD_REQUEST, "TEAM_NOT_FOUND");
                }
                let Some(organization_id) = super::resolve_organization_id(
                    input.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                let mut email = input.email.trim().to_lowercase();
                if !valid_email(&email) {
                    return http::error(StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email");
                }
                let Some(actor_member) = store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                };
                if !has_permission(
                    &actor_member.role,
                    &options,
                    OrganizationPermission::InvitationCreate,
                ) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
                    );
                }
                let mut role = input.role.normalized();
                for role in role
                    .split(',')
                    .map(str::trim)
                    .filter(|role| !role.is_empty())
                {
                    if !roles_exist(&store, &organization_id, role, &options).await? {
                        return http::error(
                            StatusCode::BAD_REQUEST,
                            "ROLE_NOT_FOUND",
                            &format!(
                                "{}: {role}",
                                crate::organization::errors::message("ROLE_NOT_FOUND")
                            ),
                        );
                    }
                    if role == options.creator_role
                        && !actor_member
                            .role
                            .split(',')
                            .any(|actor_role| actor_role.trim() == options.creator_role)
                    {
                        return http::organization_error(
                            StatusCode::FORBIDDEN,
                            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
                        );
                    }
                }
                if store
                    .member_by_email(&organization_id, &email)
                    .await?
                    .is_some()
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
                    );
                }
                let mut expires_at = OffsetDateTime::now_utc() + options.invitation_expires_in;
                let Some(organization) = store.organization_by_id(&organization_id).await? else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                let mut team_id = input.team_id;
                if let Some(hook) = &options.hooks.before_create_invitation {
                    let invitation = hook(&BeforeCreateInvitation {
                        organization: organization.clone(),
                        inviter: session.user.clone(),
                        invitation: InvitationHookData {
                            organization_id: organization_id.clone(),
                            email,
                            role,
                            team_id,
                            inviter_id: session.user.id.clone(),
                            expires_at,
                        },
                    })?;
                    if invitation.organization_id != organization_id
                        || invitation.inviter_id != session.user.id
                    {
                        return http::organization_error(
                            StatusCode::BAD_REQUEST,
                            "INVALID_REQUEST_BODY",
                        );
                    }
                    email = invitation.email.trim().to_lowercase();
                    role = invitation.role;
                    team_id = invitation.team_id;
                    expires_at = invitation.expires_at;
                    if !valid_email(&email) {
                        return http::error(
                            StatusCode::BAD_REQUEST,
                            "INVALID_EMAIL",
                            "Invalid email",
                        );
                    }
                    for role in role
                        .split(',')
                        .map(str::trim)
                        .filter(|role| !role.is_empty())
                    {
                        if !roles_exist(&store, &organization_id, role, &options).await? {
                            return http::error(
                                StatusCode::BAD_REQUEST,
                                "ROLE_NOT_FOUND",
                                &format!(
                                    "{}: {role}",
                                    crate::organization::errors::message("ROLE_NOT_FOUND")
                                ),
                            );
                        }
                        if role == options.creator_role
                            && !actor_member
                                .role
                                .split(',')
                                .any(|actor_role| actor_role.trim() == options.creator_role)
                        {
                            return http::organization_error(
                                StatusCode::FORBIDDEN,
                                "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
                            );
                        }
                    }
                }
                if store
                    .member_by_email(&organization_id, &email)
                    .await?
                    .is_some()
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
                    );
                }
                if let Some(existing) = store
                    .pending_invitation_by_email(&organization_id, &email)
                    .await?
                {
                    if input.resend {
                        let mut invitation =
                            store.extend_invitation(&existing.id, expires_at).await?;
                        if let Some(invitation) = &mut invitation {
                            retain_returned_invitation_fields(invitation, &options);
                        }
                        return http::json(StatusCode::OK, &invitation);
                    }
                    if options.cancel_pending_invitations_on_re_invite {
                        store
                            .update_invitation_status(&existing.id, InvitationStatus::Canceled)
                            .await?;
                    } else {
                        return http::organization_error(
                            StatusCode::BAD_REQUEST,
                            "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
                        );
                    }
                }
                if store.pending_invitations(&organization_id).await?.len()
                    >= options.invitation_limit
                {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "INVITATION_LIMIT_REACHED",
                    );
                }
                if let Some(team_ids) = team_id.as_deref() {
                    for team_id in team_ids
                        .split(',')
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                    {
                        let Some(team) = store.team_by_id(team_id).await? else {
                            return http::organization_error(
                                StatusCode::BAD_REQUEST,
                                "TEAM_NOT_FOUND",
                            );
                        };
                        if team.organization_id != organization_id {
                            return http::organization_error(
                                StatusCode::BAD_REQUEST,
                                "TEAM_NOT_FOUND",
                            );
                        }
                    }
                }
                let mut invitation = store
                    .create_invitation(CreateInvitationInput {
                        organization_id: &organization_id,
                        email: &email,
                        role: &role,
                        team_id: team_id.as_deref(),
                        inviter_id: &session.user.id,
                        expires_at,
                        additional_fields,
                    })
                    .await?;
                retain_returned_invitation_fields(&mut invitation, &options);
                if let Some(send_email) = &options.send_invitation_email {
                    dispatch_outbound(
                        &context,
                        send_email(InvitationEmail {
                            id: invitation.id.clone(),
                            role: invitation.role.clone(),
                            email: invitation.email.clone(),
                            organization: organization.clone(),
                            invitation: invitation.clone(),
                            inviter: actor_member.clone(),
                        }),
                    );
                }
                if let Some(hook) = &options.hooks.after_create_invitation {
                    hook(&AfterCreateInvitation {
                        organization,
                        inviter: session.user,
                        invitation: invitation.clone(),
                    })?;
                }
                http::json(StatusCode::OK, &invitation)
            }
        },
    )
}

fn retain_returned_invitation_fields(invitation: &mut Invitation, options: &OrganizationOptions) {
    additional_fields::retain_returned(
        &mut invitation.additional_fields,
        &options.schema.invitation.additional_fields,
    );
}

fn json_body_error(error: serde_json::Error) -> RustAuthError {
    RustAuthError::Api(error.to_string())
}
