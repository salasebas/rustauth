use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use serde::Deserialize;

use crate::organization::hooks::{AfterDeleteOrganization, BeforeDeleteOrganization};
use crate::organization::http;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::{has_permission, OrganizationPermission};
use crate::organization::store::OrganizationStore;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationIdBody {
    organization_id: String,
}

pub(super) fn delete(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/delete",
        Method::POST,
        super::super::metadata::options(
            "organizationDelete",
            vec![super::super::metadata::string("organizationId")],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                if options.disable_organization_deletion {
                    return http::error(
                        StatusCode::NOT_FOUND,
                        "ORGANIZATION_DELETION_DISABLED",
                        "Organization deletion is disabled",
                    );
                }
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = match http::current_session(context, &request, &store).await? {
                    Some(session) => session,
                    None => {
                        return http::error(
                            StatusCode::UNAUTHORIZED,
                            "UNAUTHORIZED",
                            "Unauthorized",
                        );
                    }
                };
                let input: OrganizationIdBody = http::body(&request)?;
                let Some(member) = store
                    .member_by_org_user(&input.organization_id, &session.user.id)
                    .await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                    );
                };
                if !has_permission(
                    &member.role,
                    &options,
                    OrganizationPermission::OrganizationDelete,
                ) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
                    );
                }
                let Some(organization) = store.organization_by_id(&input.organization_id).await?
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ORGANIZATION_NOT_FOUND",
                    );
                };
                if let Some(hook) = &options.hooks.before_delete_organization {
                    hook(&BeforeDeleteOrganization {
                        organization: organization.clone(),
                        user: session.user.clone(),
                    })?;
                }
                let cookies =
                    if session.active_organization_id.as_deref() == Some(&input.organization_id) {
                        store
                            .set_active_organization(&session.session.token, None)
                            .await?;
                        store.set_active_team(&session.session.token, None).await?;
                        http::refreshed_session_cookies(context, &session.session, &session.user)?
                    } else {
                        Vec::new()
                    };
                store.delete_organization(&input.organization_id).await?;
                if let Some(hook) = &options.hooks.after_delete_organization {
                    hook(&AfterDeleteOrganization {
                        organization: organization.clone(),
                        user: session.user,
                    })?;
                }
                http::json_with_cookies(StatusCode::OK, &organization, cookies)
            })
        },
    )
}
