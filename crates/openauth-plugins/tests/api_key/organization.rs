use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::api_key::{
    api_key_with, ApiKeyConfiguration, ApiKeyOptions, ApiKeyReference,
    INSUFFICIENT_API_KEY_PERMISSIONS, INVALID_REFERENCE_ID_FROM_API_KEY, KEY_NOT_FOUND,
    ORGANIZATION_PLUGIN_REQUIRED, USER_NOT_MEMBER_OF_ORGANIZATION,
};
use openauth_plugins::organization::{organization, organization_with, OrganizationOptions};
use serde_json::{json, Value};

use super::helpers::{request_json, sign_up, test_router_with_plugins};

#[tokio::test]
async fn organization_owned_keys_require_membership_and_do_not_mock_sessions(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let api_key_plugin = api_key_with(
        ApiKeyOptions::builder()
            .configuration(ApiKeyConfiguration {
                config_id: Some("org".to_owned()),
                reference: ApiKeyReference::Organization,
                enable_session_for_api_keys: true,
                ..ApiKeyConfiguration::default()
            })
            .build()?,
    )?;
    let router = test_router_with_plugins(adapter, vec![organization(), api_key_plugin])?;
    let owner = sign_up(&router, "Ira", "ira-api@example.com").await?;
    let outsider = sign_up(&router, "Jia", "jia-api@example.com").await?;

    let org = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"API Team","slug":"api-team"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].as_str().ok_or("missing organization id")?;

    let denied = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"org","organizationId": organization_id, "name":"outsider"}),
        Some(&outsider.cookie),
        None,
    )
    .await?;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"org","organizationId": organization_id, "name":"org-key"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["referenceId"], organization_id);
    let key = created.body["key"].as_str().ok_or("missing api key")?;

    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"configId":"org","key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(verified.body["valid"], true);
    assert_eq!(verified.body["key"]["referenceId"], organization_id);

    let session = request_json(
        &router,
        Method::GET,
        "/api/auth/get-session",
        Value::Null,
        None,
        Some(("x-api-key", key)),
    )
    .await?;
    assert_eq!(session.status, StatusCode::UNAUTHORIZED);
    assert_eq!(session.body["code"], INVALID_REFERENCE_ID_FROM_API_KEY);
    Ok(())
}

#[tokio::test]
async fn organization_custom_api_key_permission_controls_org_key_access(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let api_key_plugin = api_key_with(
        ApiKeyOptions::builder()
            .configuration(ApiKeyConfiguration {
                config_id: Some("org".to_owned()),
                reference: ApiKeyReference::Organization,
                ..ApiKeyConfiguration::default()
            })
            .build()?,
    )?;
    let organization_plugin = organization_with(
        OrganizationOptions::builder()
            .custom_role(
                "api-reader",
                json!({
                    "apiKey": ["read"]
                }),
            )
            .build(),
    );
    let router = test_router_with_plugins(adapter, vec![organization_plugin, api_key_plugin])?;
    let owner = sign_up(&router, "Ora", "ora-api@example.com").await?;
    let reader = sign_up(&router, "Rio", "rio-api@example.com").await?;

    let org = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Scoped API Team","slug":"scoped-api-team"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].as_str().ok_or("missing organization id")?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"org","organizationId": organization_id, "name":"org-key"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let member = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": organization_id, "userId": reader.user_id, "role":"api-reader"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(member.status, StatusCode::OK);

    let listed = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/list?configId=org&organizationId={organization_id}"),
        Value::Null,
        Some(&reader.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 1);

    let denied_delete = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/delete",
        json!({"configId":"org","keyId": key_id}),
        Some(&reader.cookie),
        None,
    )
    .await?;
    assert_eq!(denied_delete.status, StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn organization_owner_can_crud_org_owned_api_keys() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    let api_key_plugin = api_key_with(
        ApiKeyOptions::builder()
            .configurations(vec![
                ApiKeyConfiguration {
                    config_id: Some("user".to_owned()),
                    reference: ApiKeyReference::User,
                    ..ApiKeyConfiguration::default()
                },
                ApiKeyConfiguration {
                    config_id: Some("org".to_owned()),
                    reference: ApiKeyReference::Organization,
                    ..ApiKeyConfiguration::default()
                },
            ])
            .build()?,
    )?;
    let router = test_router_with_plugins(adapter, vec![organization(), api_key_plugin])?;
    let owner = sign_up(&router, "Owner", "owner-org-key-crud@example.com").await?;

    let org = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Owner Key Org","slug":"owner-key-org"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].as_str().ok_or("missing org id")?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"org","organizationId": organization_id, "name":"owner-key"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["configId"], "org");
    assert_eq!(created.body["referenceId"], organization_id);
    let key_id = created.body["id"].as_str().ok_or("missing key id")?;

    let listed = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/list?configId=org&organizationId={organization_id}"),
        Value::Null,
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 1);
    assert_eq!(listed.body["apiKeys"][0]["id"], key_id);

    let fetched = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/get?configId=org&id={key_id}"),
        Value::Null,
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.body["id"], key_id);

    let updated = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"configId":"org","keyId": key_id, "name":"updated-owner-key"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["name"], "updated-owner-key");

    let deleted = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/delete",
        json!({"configId":"org","keyId": key_id}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(deleted.status, StatusCode::OK);
    assert_eq!(deleted.body["success"], true);
    Ok(())
}

#[tokio::test]
async fn organization_api_key_denies_non_member_on_all_owner_routes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let api_key_plugin = api_key_with(
        ApiKeyOptions::builder()
            .configuration(ApiKeyConfiguration {
                config_id: Some("org".to_owned()),
                reference: ApiKeyReference::Organization,
                ..ApiKeyConfiguration::default()
            })
            .build()?,
    )?;
    let router = test_router_with_plugins(adapter, vec![organization(), api_key_plugin])?;
    let owner = sign_up(&router, "Owner", "owner-org-key-deny@example.com").await?;
    let outsider = sign_up(&router, "Out", "outsider-org-key-deny@example.com").await?;

    let org = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Deny Key Org","slug":"deny-key-org"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].as_str().ok_or("missing org id")?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"org","organizationId": organization_id, "name":"owner-key"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key_id = created.body["id"].as_str().ok_or("missing key id")?;

    let denied_list = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/list?configId=org&organizationId={organization_id}"),
        Value::Null,
        Some(&outsider.cookie),
        None,
    )
    .await?;
    assert_eq!(denied_list.status, StatusCode::FORBIDDEN);
    assert_eq!(denied_list.body["code"], USER_NOT_MEMBER_OF_ORGANIZATION);

    let denied_create = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"org","organizationId": organization_id, "name":"outsider"}),
        Some(&outsider.cookie),
        None,
    )
    .await?;
    assert_eq!(denied_create.status, StatusCode::FORBIDDEN);
    assert_eq!(denied_create.body["code"], USER_NOT_MEMBER_OF_ORGANIZATION);

    let denied_get = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/get?configId=org&id={key_id}"),
        Value::Null,
        Some(&outsider.cookie),
        None,
    )
    .await?;
    assert_eq!(denied_get.status, StatusCode::FORBIDDEN);
    assert_eq!(denied_get.body["code"], USER_NOT_MEMBER_OF_ORGANIZATION);

    let denied_update = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"configId":"org","keyId": key_id, "name":"hacked"}),
        Some(&outsider.cookie),
        None,
    )
    .await?;
    assert_eq!(denied_update.status, StatusCode::FORBIDDEN);
    assert_eq!(denied_update.body["code"], USER_NOT_MEMBER_OF_ORGANIZATION);

    let denied_delete = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/delete",
        json!({"configId":"org","keyId": key_id}),
        Some(&outsider.cookie),
        None,
    )
    .await?;
    assert_eq!(denied_delete.status, StatusCode::FORBIDDEN);
    assert_eq!(denied_delete.body["code"], USER_NOT_MEMBER_OF_ORGANIZATION);
    Ok(())
}

#[tokio::test]
async fn organization_api_key_reports_missing_org_plugin_and_wrong_config(
) -> Result<(), Box<dyn std::error::Error>> {
    let org_config = ApiKeyConfiguration {
        config_id: Some("org".to_owned()),
        reference: ApiKeyReference::Organization,
        ..ApiKeyConfiguration::default()
    };
    let user_config = ApiKeyConfiguration {
        config_id: Some("user".to_owned()),
        reference: ApiKeyReference::User,
        ..ApiKeyConfiguration::default()
    };

    let missing_plugin_router = test_router_with_plugins(
        Arc::new(MemoryAdapter::new()),
        vec![api_key_with(
            ApiKeyOptions::builder()
                .configurations(vec![org_config.clone()])
                .build()?,
        )?],
    )?;
    let user = sign_up(
        &missing_plugin_router,
        "Missing",
        "missing-org-plugin@example.com",
    )
    .await?;
    let missing_plugin = request_json(
        &missing_plugin_router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"org","organizationId":"org_missing","name":"missing"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(missing_plugin.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(missing_plugin.body["code"], ORGANIZATION_PLUGIN_REQUIRED);

    let router = test_router_with_plugins(
        Arc::new(MemoryAdapter::new()),
        vec![
            organization(),
            api_key_with(
                ApiKeyOptions::builder()
                    .configurations(vec![user_config, org_config])
                    .build()?,
            )?,
        ],
    )?;
    let owner = sign_up(&router, "Owner", "wrong-config-owner@example.com").await?;
    let org = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Wrong Config Org","slug":"wrong-config-org"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].as_str().ok_or("missing org id")?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"org","organizationId": organization_id, "name":"org-key"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key_id = created.body["id"].as_str().ok_or("missing key id")?;

    let wrong_config = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/get?configId=user&id={key_id}"),
        Value::Null,
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(wrong_config.status, StatusCode::NOT_FOUND);
    assert_eq!(wrong_config.body["code"], KEY_NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn organization_api_key_rejects_member_role_without_api_key_permissions(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let api_key_plugin = api_key_with(
        ApiKeyOptions::builder()
            .configuration(ApiKeyConfiguration {
                config_id: Some("org".to_owned()),
                reference: ApiKeyReference::Organization,
                ..ApiKeyConfiguration::default()
            })
            .build()?,
    )?;
    let router = test_router_with_plugins(adapter, vec![organization(), api_key_plugin])?;
    let owner = sign_up(&router, "Owner", "owner-org-key-member@example.com").await?;
    let member = sign_up(&router, "Member", "member-org-key-member@example.com").await?;

    let org = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/create",
        json!({"name":"Member Key Org","slug":"member-key-org"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(org.status, StatusCode::OK);
    let organization_id = org.body["id"].as_str().ok_or("missing org id")?;

    let added = request_json(
        &router,
        Method::POST,
        "/api/auth/organization/add-member",
        json!({"organizationId": organization_id, "userId": member.user_id, "role":"member"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    assert_eq!(added.status, StatusCode::OK);

    let denied = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/list?configId=org&organizationId={organization_id}"),
        Value::Null,
        Some(&member.cookie),
        None,
    )
    .await?;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.body["code"], INSUFFICIENT_API_KEY_PERMISSIONS);
    Ok(())
}
