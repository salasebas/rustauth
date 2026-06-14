use ::http::{Method, StatusCode};
use rustauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::organization::http;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::role_has_resource_action_with_dynamic;
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
    let options = std::sync::Arc::new(options);
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
            let options = std::sync::Arc::clone(&options);
            async move {
                let adapter = context.require_adapter()?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = match http::current_session(&context, &request, &store).await? {
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
                        role_has_resource_action_with_dynamic(
                            &member.role,
                            &options,
                            &dynamic_roles,
                            &resource,
                            &action,
                        )
                    })
                });
                http::json(
                    StatusCode::OK,
                    &serde_json::json!({ "error": null, "success": success }),
                )
            }
        },
    )
}
