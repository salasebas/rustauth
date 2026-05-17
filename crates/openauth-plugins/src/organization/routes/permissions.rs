use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::organization::http;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::{
    has_permission, permission_value_has_permission, OrganizationPermission,
};
use crate::organization::store::OrganizationStore;

pub fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    vec![has_permission_endpoint(options)]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HasPermissionBody {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    permissions: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    permission: BTreeMap<String, Vec<String>>,
}

fn has_permission_endpoint(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/has-permission",
        Method::POST,
        super::metadata::options(
            "organizationHasPermission",
            vec![
                super::metadata::optional_object("permission"),
                super::metadata::optional_object("permissions"),
                super::metadata::optional_string("organizationId"),
            ],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = match http::current_session(context, &request, &store).await? {
                    Some(session) => session,
                    None => {
                        return http::error(
                            StatusCode::UNAUTHORIZED,
                            "UNAUTHORIZED",
                            "Unauthorized",
                        )
                    }
                };
                let input: HasPermissionBody = http::body(&request)?;
                let Some(organization_id) = super::resolve_organization_id(
                    input.organization_id,
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
                    return http::organization_error(
                        StatusCode::UNAUTHORIZED,
                        "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                    );
                };
                let permissions = if input.permissions.is_empty() {
                    input.permission
                } else {
                    input.permissions
                };
                let dynamic_roles = if options.dynamic_access_control.enabled {
                    store.organization_roles(&organization_id).await?
                } else {
                    Vec::new()
                };
                let success = permissions.into_iter().all(|(resource, actions)| {
                    actions.into_iter().all(|action| {
                        resolve_permission(&resource, &action)
                            .map(|permission| {
                                has_permission(&member.role, &options, permission)
                                    || member.role.split(',').map(str::trim).any(|role| {
                                        dynamic_roles.iter().any(|record| {
                                            record.role == role
                                                && permission_value_has_permission(
                                                    &record.permission,
                                                    permission,
                                                )
                                        })
                                    })
                            })
                            .unwrap_or(false)
                    })
                });
                http::json(
                    StatusCode::OK,
                    &serde_json::json!({ "error": null, "success": success }),
                )
            })
        },
    )
}

fn resolve_permission(resource: &str, action: &str) -> Option<OrganizationPermission> {
    match (resource, action) {
        ("organization", "update") => Some(OrganizationPermission::OrganizationUpdate),
        ("organization", "delete") => Some(OrganizationPermission::OrganizationDelete),
        ("member", "create") => Some(OrganizationPermission::MemberCreate),
        ("member", "update") => Some(OrganizationPermission::MemberUpdate),
        ("member", "delete") => Some(OrganizationPermission::MemberDelete),
        ("invitation", "create") => Some(OrganizationPermission::InvitationCreate),
        ("invitation", "cancel") => Some(OrganizationPermission::InvitationCancel),
        ("team", "create") => Some(OrganizationPermission::TeamCreate),
        ("team", "update") => Some(OrganizationPermission::TeamUpdate),
        ("team", "delete") => Some(OrganizationPermission::TeamDelete),
        ("ac", "create") => Some(OrganizationPermission::AcCreate),
        ("ac", "read") => Some(OrganizationPermission::AcRead),
        ("ac", "update") => Some(OrganizationPermission::AcUpdate),
        ("ac", "delete") => Some(OrganizationPermission::AcDelete),
        ("apiKey" | "api_key", "create") => Some(OrganizationPermission::ApiKeyCreate),
        ("apiKey" | "api_key", "read") => Some(OrganizationPermission::ApiKeyRead),
        ("apiKey" | "api_key", "update") => Some(OrganizationPermission::ApiKeyUpdate),
        ("apiKey" | "api_key", "delete") => Some(OrganizationPermission::ApiKeyDelete),
        _ => None,
    }
}
