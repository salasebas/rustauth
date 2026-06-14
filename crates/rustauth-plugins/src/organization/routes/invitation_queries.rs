use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};

use crate::organization::additional_fields;
use crate::organization::http;
use crate::organization::models::Invitation;
use crate::organization::options::OrganizationOptions;
use crate::organization::store::OrganizationStore;

use super::validation::{query_param, require_session};

pub(super) fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    vec![
        get_invitation(options.clone()),
        list_invitations(options.clone()),
        list_user_invitations(options),
    ]
}

fn get_invitation(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/get-invitation",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationGetInvitation"),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let id =
                    query_param(&request, "id").or_else(|| query_param(&request, "invitationId"));
                let Some(id) = id else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "INVITATION_NOT_FOUND",
                    );
                };
                match store.invitation_by_id(&id).await? {
                    Some(mut invitation) => {
                        retain_returned_invitation_fields(&mut invitation, &options);
                        http::json(StatusCode::OK, &invitation)
                    }
                    None => {
                        http::organization_error(StatusCode::BAD_REQUEST, "INVITATION_NOT_FOUND")
                    }
                }
            }
        },
    )
}

fn list_invitations(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/list-invitations",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationListInvitations"),
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
                if store
                    .member_by_org_user(&organization_id, &session.user.id)
                    .await?
                    .is_none()
                {
                    return http::organization_error(StatusCode::BAD_REQUEST, "MEMBER_NOT_FOUND");
                }
                let mut invitations = store.invitations_for_organization(&organization_id).await?;
                for invitation in &mut invitations {
                    retain_returned_invitation_fields(invitation, &options);
                }
                http::json(StatusCode::OK, &invitations)
            }
        },
    )
}

fn list_user_invitations(options: OrganizationOptions) -> AsyncAuthEndpoint {
    let options = std::sync::Arc::new(options);
    create_auth_endpoint(
        "/organization/list-user-invitations",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationListUserInvitations"),
        move |context, request| {
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(&context, &request, &store).await?;
                let mut invitations = store
                    .invitations_for_email(&session.user.email.to_lowercase())
                    .await?;
                for invitation in &mut invitations {
                    retain_returned_invitation_fields(invitation, &options);
                }
                http::json(StatusCode::OK, &invitations)
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
