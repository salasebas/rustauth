use ::http::{Method, StatusCode};
use openauth_core::api::{create_auth_endpoint, AsyncAuthEndpoint, AuthEndpointOptions};
use openauth_core::error::OpenAuthError;
use serde::Deserialize;

use crate::organization::additional_fields;
use crate::organization::http;
use crate::organization::options::OrganizationOptions;
use crate::organization::permissions::{has_permission, OrganizationPermission};
use crate::organization::store::OrganizationStore;
use crate::organization::OrganizationRoleRecord;

pub fn endpoints(options: OrganizationOptions) -> Vec<AsyncAuthEndpoint> {
    if !options.dynamic_access_control.enabled {
        return Vec::new();
    }
    vec![
        create_role(options.clone()),
        delete_role(options.clone()),
        list_roles(options.clone()),
        get_role(options.clone()),
        update_role(options),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleBody {
    #[serde(default)]
    organization_id: Option<String>,
    role: String,
    permission: serde_json::Value,
}

fn create_role(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/create-role",
        Method::POST,
        super::metadata::options(
            "organizationCreateRole",
            vec![
                super::metadata::string("role"),
                super::metadata::object("permission"),
                super::metadata::optional_string("organizationId"),
            ],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let body: serde_json::Value = http::body(&request)?;
                let input: RoleBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::create_values(
                    &options.schema.organization_role.additional_fields,
                    body.as_object().ok_or_else(|| {
                        OpenAuthError::Api("request body must be an object".to_owned())
                    })?,
                )?;
                let Some(organization_id) = super::resolve_organization_id(
                    input.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE",
                    );
                };
                let member = require_member(&store, &organization_id, &session.user.id).await?;
                if !has_permission(&member.role, &options, OrganizationPermission::AcCreate) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
                    );
                }
                let role = normalize_role(&input.role);
                if is_predefined_role(&role, &options) {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ROLE_NAME_IS_ALREADY_TAKEN",
                    );
                }
                if !valid_permission(&input.permission) {
                    return http::organization_error(StatusCode::BAD_REQUEST, "INVALID_RESOURCE");
                }
                if store
                    .organization_role_by_name(&organization_id, &role)
                    .await?
                    .is_some()
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ROLE_NAME_IS_ALREADY_TAKEN",
                    );
                }
                if let Some(max) = options
                    .dynamic_access_control
                    .maximum_roles_per_organization
                {
                    if store.count_organization_roles(&organization_id).await? as usize >= max {
                        return http::organization_error(StatusCode::BAD_REQUEST, "TOO_MANY_ROLES");
                    }
                }
                let mut role = store
                    .create_organization_role(
                        &organization_id,
                        &role,
                        input.permission,
                        additional_fields,
                    )
                    .await?;
                retain_returned_role_fields(&mut role, &options);
                http::json(StatusCode::OK, &role)
            })
        },
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoleRefBody {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    role_id: Option<String>,
    #[serde(default)]
    role: Option<String>,
}

fn delete_role(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/delete-role",
        Method::POST,
        super::metadata::options(
            "organizationDeleteRole",
            vec![
                super::metadata::optional_string("organizationId"),
                super::metadata::optional_string("roleId"),
                super::metadata::optional_string("role"),
            ],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let input: RoleRefBody = http::body(&request)?;
                let Some(organization_id) = super::resolve_organization_id(
                    input.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let member = require_member(&store, &organization_id, &session.user.id).await?;
                if !has_permission(&member.role, &options, OrganizationPermission::AcDelete) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
                    );
                }
                let Some(role) =
                    resolve_role(&store, &organization_id, input.role_id, input.role).await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
                };
                if is_predefined_role(&role.role, &options) {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "CANNOT_DELETE_A_PRE_DEFINED_ROLE",
                    );
                }
                for org_member in store.members(&organization_id).await? {
                    if org_member
                        .role
                        .split(',')
                        .any(|part| part.trim() == role.role)
                    {
                        return http::organization_error(
                            StatusCode::BAD_REQUEST,
                            "ROLE_IS_ASSIGNED_TO_MEMBERS",
                        );
                    }
                }
                store.delete_organization_role(&role.id).await?;
                http::json(StatusCode::OK, &serde_json::json!({ "role": role }))
            })
        },
    )
}

fn list_roles(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/list-roles",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationListRoles"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let Some(organization_id) =
                    query_param(&request, "organizationId").or(session.active_organization_id)
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let member = require_member(&store, &organization_id, &session.user.id).await?;
                if !has_permission(&member.role, &options, OrganizationPermission::AcRead) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
                    );
                }
                let mut roles = store.organization_roles(&organization_id).await?;
                for role in &mut roles {
                    retain_returned_role_fields(role, &options);
                }
                http::json(StatusCode::OK, &roles)
            })
        },
    )
}

fn get_role(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/get-role",
        Method::GET,
        AuthEndpointOptions::new().operation_id("organizationGetRole"),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let Some(organization_id) =
                    query_param(&request, "organizationId").or(session.active_organization_id)
                else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let member = require_member(&store, &organization_id, &session.user.id).await?;
                if !has_permission(&member.role, &options, OrganizationPermission::AcRead) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE",
                    );
                }
                let role_id = query_param(&request, "roleId");
                let role_name = query_param(&request, "role");
                let Some(mut role) =
                    resolve_role(&store, &organization_id, role_id, role_name).await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
                };
                retain_returned_role_fields(&mut role, &options);
                http::json(StatusCode::OK, &role)
            })
        },
    )
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateRoleBody {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    role_id: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    permission: Option<serde_json::Value>,
    #[serde(default)]
    new_role: Option<String>,
}

fn update_role(options: OrganizationOptions) -> AsyncAuthEndpoint {
    create_auth_endpoint(
        "/organization/update-role",
        Method::POST,
        super::metadata::options(
            "organizationUpdateRole",
            vec![
                super::metadata::optional_string("organizationId"),
                super::metadata::optional_string("roleId"),
                super::metadata::optional_string("role"),
                super::metadata::optional_string("newRole"),
                super::metadata::optional_object("permission"),
            ],
        ),
        move |context, request| {
            let options = options.clone();
            Box::pin(async move {
                let adapter = http::adapter(context)?;
                let store = OrganizationStore::new(adapter.as_ref());
                let session = require_session(context, &request, &store).await?;
                let body: serde_json::Value = http::body(&request)?;
                let input: UpdateRoleBody =
                    serde_json::from_value(body.clone()).map_err(json_body_error)?;
                let additional_fields = additional_fields::update_values(
                    &options.schema.organization_role.additional_fields,
                    body.as_object().ok_or_else(|| {
                        OpenAuthError::Api("request body must be an object".to_owned())
                    })?,
                )?;
                let Some(organization_id) = super::resolve_organization_id(
                    input.organization_id,
                    session.active_organization_id.as_deref(),
                ) else {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "NO_ACTIVE_ORGANIZATION",
                    );
                };
                let member = require_member(&store, &organization_id, &session.user.id).await?;
                if !has_permission(&member.role, &options, OrganizationPermission::AcUpdate) {
                    return http::organization_error(
                        StatusCode::FORBIDDEN,
                        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
                    );
                }
                let Some(role) =
                    resolve_role(&store, &organization_id, input.role_id, input.role).await?
                else {
                    return http::organization_error(StatusCode::BAD_REQUEST, "ROLE_NOT_FOUND");
                };
                if let Some(permission) = &input.permission {
                    if !valid_permission(permission) {
                        return http::organization_error(
                            StatusCode::BAD_REQUEST,
                            "INVALID_RESOURCE",
                        );
                    }
                }
                let new_role = input.new_role.as_deref().map(normalize_role);
                if new_role
                    .as_deref()
                    .is_some_and(|role| is_predefined_role(role, &options))
                {
                    return http::organization_error(
                        StatusCode::BAD_REQUEST,
                        "ROLE_NAME_IS_ALREADY_TAKEN",
                    );
                }
                if let Some(new_role) = new_role.as_deref() {
                    if store
                        .organization_role_by_name(&organization_id, new_role)
                        .await?
                        .is_some_and(|existing| existing.id != role.id)
                    {
                        return http::organization_error(
                            StatusCode::BAD_REQUEST,
                            "ROLE_NAME_IS_ALREADY_TAKEN",
                        );
                    }
                }
                let updated = store
                    .update_organization_role(
                        &role.id,
                        new_role.as_deref(),
                        input.permission,
                        additional_fields,
                    )
                    .await?;
                let mut updated = updated;
                if let Some(role) = &mut updated {
                    retain_returned_role_fields(role, &options);
                }
                http::json(StatusCode::OK, &updated)
            })
        },
    )
}

async fn resolve_role(
    store: &OrganizationStore<'_>,
    organization_id: &str,
    role_id: Option<String>,
    role: Option<String>,
) -> Result<Option<OrganizationRoleRecord>, openauth_core::error::OpenAuthError> {
    if let Some(role_id) = role_id {
        return store
            .organization_role_by_id(&role_id)
            .await
            .map(|role| role.filter(|role| role.organization_id == organization_id));
    }
    if let Some(role) = role {
        return store
            .organization_role_by_name(organization_id, &normalize_role(&role))
            .await;
    }
    Ok(None)
}

fn retain_returned_role_fields(role: &mut OrganizationRoleRecord, options: &OrganizationOptions) {
    additional_fields::retain_returned(
        &mut role.additional_fields,
        &options.schema.organization_role.additional_fields,
    );
}

fn json_body_error(error: serde_json::Error) -> OpenAuthError {
    OpenAuthError::Api(error.to_string())
}

fn normalize_role(role: &str) -> String {
    role.trim().to_lowercase()
}

fn is_predefined_role(role: &str, options: &OrganizationOptions) -> bool {
    role == options.creator_role || matches!(role, "owner" | "admin" | "member")
}

fn valid_permission(permission: &serde_json::Value) -> bool {
    let Some(object) = permission.as_object() else {
        return false;
    };
    object.iter().all(|(resource, actions)| {
        matches!(
            resource.as_str(),
            "organization" | "member" | "invitation" | "team" | "ac" | "apiKey" | "api_key"
        ) && actions
            .as_array()
            .is_some_and(|actions| actions.iter().all(serde_json::Value::is_string))
    })
}

fn query_param(request: &openauth_core::api::ApiRequest, name: &str) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
    })
}

async fn require_session(
    context: &openauth_core::context::AuthContext,
    request: &openauth_core::api::ApiRequest,
    store: &OrganizationStore<'_>,
) -> Result<http::CurrentSession, openauth_core::error::OpenAuthError> {
    http::current_session(context, request, store)
        .await?
        .ok_or_else(|| openauth_core::error::OpenAuthError::Api("Unauthorized".to_owned()))
}

async fn require_member(
    store: &OrganizationStore<'_>,
    organization_id: &str,
    user_id: &str,
) -> Result<crate::organization::Member, openauth_core::error::OpenAuthError> {
    store
        .member_by_org_user(organization_id, user_id)
        .await?
        .ok_or_else(|| openauth_core::error::OpenAuthError::Api("Member not found".to_owned()))
}
