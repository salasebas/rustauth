use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::access::{create_access_control, statements};
use openauth_plugins::organization::{DynamicAccessControlOptions, OrganizationOptions};
use serde_json::json;

#[tokio::test]
async fn dynamic_access_control_crud_roles_and_rejects_assigned_delete(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let options = OrganizationOptions::builder()
        .dynamic_access_control(DynamicAccessControlOptions {
            enabled: true,
            maximum_roles_per_organization: Some(3),
        })
        .build();
    let auth = super::test_router(adapter, options)?;

    let ada = super::sign_up(&auth, "Ada", "ada-dac@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Acme DAC","slug":"acme-dac"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);

    let role = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "role": "billing",
            "permission": { "organization": ["update"], "ac": ["read"] }
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(role.status, StatusCode::OK);
    assert_eq!(role.body["role"], "billing");
    let role_id = role.body["id"].as_str().ok_or("missing role id")?;

    let listed = super::request_json(
        &auth,
        Method::GET,
        "/api/auth/organization/list-roles",
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body.as_array().map(Vec::len), Some(1));

    let updated = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/update-role",
        json!({
            "roleId": role_id,
            "permission": { "organization": ["update"], "invitation": ["create"], "ac": ["read"] }
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);

    let ben = super::sign_up(&auth, "Ben", "ben-dac@example.com").await?;
    let member = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": ben.user_id, "role": "billing"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(member.status, StatusCode::OK);

    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({"organizationId": org.body["id"]}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);
    let permission = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/has-permission",
        json!({"permissions": {"invitation": ["create"]}}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(permission.status, StatusCode::OK);
    assert_eq!(permission.body["success"], true);

    let assigned_delete = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/delete-role",
        json!({"roleId": role_id}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(assigned_delete.status, StatusCode::BAD_REQUEST);
    assert_eq!(assigned_delete.body["code"], "ROLE_IS_ASSIGNED_TO_MEMBERS");

    Ok(())
}

#[tokio::test]
async fn has_permission_allows_custom_ac_resource_for_dynamic_role(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let access_control = create_access_control(statements([
        ("project", vec!["read", "write"]),
        ("ac", vec!["create", "read", "update", "delete"]),
    ]))?;
    let options = OrganizationOptions::builder()
        .access_control(access_control)
        .dynamic_access_control(DynamicAccessControlOptions {
            enabled: true,
            maximum_roles_per_organization: Some(3),
        })
        .build();
    let auth = super::test_router(adapter, options)?;

    let ada = super::sign_up(&auth, "Ada", "ada-custom-ac@example.com").await?;
    super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Custom AC","slug":"custom-ac"}),
        Some(&ada.cookie),
    )
    .await?;
    let role = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "role": "project_writer",
            "permission": { "project": ["write"], "ac": ["read"] }
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(role.status, StatusCode::OK);

    let ben = super::sign_up(&auth, "Ben", "ben-custom-ac@example.com").await?;
    let added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": ben.user_id, "role": "project_writer"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);
    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({"organizationId": added.body["organizationId"]}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);

    let permission = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/has-permission",
        json!({"permissions": {"project": ["write"]}}),
        Some(&ben.cookie),
    )
    .await?;

    assert_eq!(permission.status, StatusCode::OK);
    assert_eq!(permission.body["success"], true);
    Ok(())
}

#[tokio::test]
async fn has_permission_preserves_builtin_actions_when_db_role_is_partial(
) -> Result<(), Box<dyn std::error::Error>> {
    use openauth_core::db::{Create, DbAdapter, DbValue};
    use time::OffsetDateTime;

    let adapter = Arc::new(MemoryAdapter::new());
    let options = OrganizationOptions::builder()
        .dynamic_access_control(DynamicAccessControlOptions {
            enabled: true,
            maximum_roles_per_organization: Some(3),
        })
        .build();
    let auth = super::test_router(adapter.clone(), options)?;
    let owner = super::sign_up(&auth, "Owner", "owner-partial-db@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Partial DB","slug":"partial-db"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].as_str().ok_or("missing organization id")?;

    let now = OffsetDateTime::now_utc();
    adapter
        .create(
            Create::new("organization_role")
                .data("id", DbValue::String("role_owner_partial".to_owned()))
                .data(
                    "organization_id",
                    DbValue::String(organization_id.to_owned()),
                )
                .data("role", DbValue::String("owner".to_owned()))
                .data(
                    "permission",
                    DbValue::Json(json!({ "organization": ["update"] })),
                )
                .data("created_at", DbValue::Timestamp(now))
                .data("updated_at", DbValue::Timestamp(now)),
        )
        .await?;

    let update = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/has-permission",
        json!({"organizationId": organization_id, "permissions": {"organization": ["update"]}}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(update.status, StatusCode::OK);
    assert_eq!(update.body["success"], true);

    let delete = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/has-permission",
        json!({"organizationId": organization_id, "permissions": {"organization": ["delete"]}}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(delete.status, StatusCode::OK);
    assert_eq!(delete.body["success"], true);
    Ok(())
}

#[tokio::test]
async fn has_permission_merges_comma_separated_static_and_dynamic_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let access_control = create_access_control(statements([
        ("project", vec!["read", "write"]),
        ("ac", vec!["create", "read", "update", "delete"]),
    ]))?;
    let options = OrganizationOptions::builder()
        .access_control(access_control)
        .dynamic_access_control(DynamicAccessControlOptions {
            enabled: true,
            maximum_roles_per_organization: Some(3),
        })
        .build();
    let auth = super::test_router(adapter, options)?;
    let owner = super::sign_up(&auth, "Owner", "owner-role-merge@example.com").await?;
    let member = super::sign_up(&auth, "Member", "member-role-merge@example.com").await?;
    let org = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Role Merge","slug":"role-merge"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].clone();
    let role = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "organizationId": organization_id,
            "role": "project_writer",
            "permission": { "project": ["write"], "ac": ["read"] }
        }),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(role.status, StatusCode::OK);

    let added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": organization_id, "userId": member.user_id, "role": "member, project_writer"}),
        Some(&owner.cookie),
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);
    assert_eq!(added.body["role"], "member,project_writer");
    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({"organizationId": organization_id}),
        Some(&member.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);

    let dynamic_permission = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/has-permission",
        json!({"permissions": {"project": ["write"]}}),
        Some(&member.cookie),
    )
    .await?;
    assert_eq!(dynamic_permission.status, StatusCode::OK);
    assert_eq!(dynamic_permission.body["success"], true);

    let static_permission = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/has-permission",
        json!({"permissions": {"ac": ["read"]}}),
        Some(&member.cookie),
    )
    .await?;
    assert_eq!(static_permission.status, StatusCode::OK);
    assert_eq!(static_permission.body["success"], true);
    Ok(())
}

#[tokio::test]
async fn create_role_rejects_permissions_actor_lacks_with_missing_permissions(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let access_control = create_access_control(statements([
        ("project", vec!["read", "write"]),
        ("ac", vec!["create", "read", "update", "delete"]),
    ]))?;
    let options = OrganizationOptions::builder()
        .access_control(access_control)
        .dynamic_access_control(DynamicAccessControlOptions {
            enabled: true,
            maximum_roles_per_organization: Some(5),
        })
        .build();
    let auth = super::test_router(adapter, options)?;

    let ada = super::sign_up(&auth, "Ada", "ada-escalation@example.com").await?;
    super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Escalation","slug":"escalation"}),
        Some(&ada.cookie),
    )
    .await?;
    let limited = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "role": "limited_admin",
            "permission": { "project": ["read"], "ac": ["create", "read"] }
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(limited.status, StatusCode::OK);

    let ben = super::sign_up(&auth, "Ben", "ben-escalation@example.com").await?;
    let added = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"userId": ben.user_id, "role": "limited_admin"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);
    let active = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/set-active",
        json!({"organizationId": added.body["organizationId"]}),
        Some(&ben.cookie),
    )
    .await?;
    assert_eq!(active.status, StatusCode::OK);

    let escalated = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "role": "escalated",
            "permission": { "project": ["write"], "ac": ["read"] }
        }),
        Some(&ben.cookie),
    )
    .await?;

    assert_eq!(escalated.status, StatusCode::FORBIDDEN);
    assert_eq!(
        escalated.body["code"],
        "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE"
    );
    assert_eq!(
        escalated.body["missingPermissions"],
        json!({ "project": ["write"] })
    );
    Ok(())
}

#[tokio::test]
async fn dynamic_access_control_rejects_invalid_resources_limits_and_cross_org_role_ids(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let options = OrganizationOptions::builder()
        .dynamic_access_control(DynamicAccessControlOptions {
            enabled: true,
            maximum_roles_per_organization: Some(1),
        })
        .build();
    let auth = super::test_router(adapter, options)?;

    let ada = super::sign_up(&auth, "Ada", "ada-dac-hardening@example.com").await?;
    let first = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"First DAC","slug":"first-dac"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);
    let first_id = first.body["id"].as_str().ok_or("missing first org id")?;

    let invalid = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "organizationId": first_id,
            "role": "invalid",
            "permission": { "billing": ["read"] }
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid.body["code"], "INVALID_RESOURCE");

    let role = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "organizationId": first_id,
            "role": "ops",
            "permission": { "organization": ["update"], "ac": ["read"] }
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(role.status, StatusCode::OK);
    let role_id = role.body["id"].as_str().ok_or("missing role id")?;

    let too_many = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create-role",
        json!({
            "organizationId": first_id,
            "role": "finance",
            "permission": { "organization": ["update"] }
        }),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(too_many.status, StatusCode::BAD_REQUEST);
    assert_eq!(too_many.body["code"], "TOO_MANY_ROLES");

    let second = super::request_json(
        &auth,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Second DAC","slug":"second-dac"}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(second.status, StatusCode::OK);
    let second_id = second.body["id"].as_str().ok_or("missing second org id")?;

    let cross_org = super::request_json(
        &auth,
        Method::GET,
        &format!("/api/auth/organization/get-role?organizationId={second_id}&roleId={role_id}"),
        json!({}),
        Some(&ada.cookie),
    )
    .await?;
    assert_eq!(cross_org.status, StatusCode::BAD_REQUEST);
    assert_eq!(cross_org.body["code"], "ROLE_NOT_FOUND");

    Ok(())
}
