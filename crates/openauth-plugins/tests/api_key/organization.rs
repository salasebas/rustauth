use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::api_key::{
    api_key_with_configurations, ApiKeyConfiguration, ApiKeyReference,
};
use openauth_plugins::organization::{
    organization, organization_with_options, OrganizationOptions,
};
use serde_json::{json, Value};

use super::helpers::{request_json, sign_up, test_router_with_plugins};

#[tokio::test]
async fn organization_owned_keys_require_membership_and_do_not_mock_sessions(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let api_key_plugin = api_key_with_configurations(vec![ApiKeyConfiguration {
        config_id: Some("org".to_owned()),
        reference: ApiKeyReference::Organization,
        enable_session_for_api_keys: true,
        ..ApiKeyConfiguration::default()
    }])?;
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
    assert_eq!(session.status, StatusCode::OK);
    assert!(session.body.is_null());
    Ok(())
}

#[tokio::test]
async fn organization_custom_api_key_permission_controls_org_key_access(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let api_key_plugin = api_key_with_configurations(vec![ApiKeyConfiguration {
        config_id: Some("org".to_owned()),
        reference: ApiKeyReference::Organization,
        ..ApiKeyConfiguration::default()
    }])?;
    let organization_plugin = organization_with_options(
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
