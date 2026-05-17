use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::api_key::{
    api_key_with_configurations, ApiKeyConfiguration, ApiKeyReference, UPSTREAM_PLUGIN_ID,
};
use serde_json::{json, Value};

use super::helpers::{request_json, sign_up, test_router};

#[test]
fn multiple_configurations_require_unique_config_ids() -> Result<(), Box<dyn std::error::Error>> {
    let missing = api_key_with_configurations(vec![ApiKeyConfiguration::default()]);
    assert!(missing.is_err());

    let duplicate = api_key_with_configurations(vec![
        ApiKeyConfiguration {
            config_id: Some("default".to_owned()),
            ..ApiKeyConfiguration::default()
        },
        ApiKeyConfiguration {
            config_id: Some("default".to_owned()),
            ..ApiKeyConfiguration::default()
        },
    ]);
    assert!(duplicate.is_err());

    let plugin = api_key_with_configurations(vec![
        ApiKeyConfiguration {
            config_id: Some("user-keys".to_owned()),
            reference: ApiKeyReference::User,
            ..ApiKeyConfiguration::default()
        },
        ApiKeyConfiguration {
            config_id: Some("org-keys".to_owned()),
            reference: ApiKeyReference::Organization,
            ..ApiKeyConfiguration::default()
        },
    ])?;
    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);

    Ok(())
}

#[tokio::test]
async fn list_without_config_id_merges_user_keys_from_all_configurations(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let plugin = api_key_with_configurations(vec![
        ApiKeyConfiguration {
            config_id: Some("primary".to_owned()),
            ..ApiKeyConfiguration::default()
        },
        ApiKeyConfiguration {
            config_id: Some("secondary".to_owned()),
            ..ApiKeyConfiguration::default()
        },
    ])?;
    let router = test_router(adapter, plugin)?;
    let user = sign_up(&router, "Jay", "jay-api@example.com").await?;

    for (config_id, name) in [("primary", "one"), ("secondary", "two")] {
        let created = request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"configId": config_id, "name": name}),
            Some(&user.cookie),
            None,
        )
        .await?;
        assert_eq!(created.status, StatusCode::OK);
    }

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list?sortBy=name&sortDirection=asc",
        Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 2);
    assert_eq!(listed.body["apiKeys"][0]["name"], "one");
    assert_eq!(listed.body["apiKeys"][1]["name"], "two");
    Ok(())
}
