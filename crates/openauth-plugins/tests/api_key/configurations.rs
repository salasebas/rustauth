use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::api_key::{
    api_key, api_key_with, ApiKeyConfiguration, ApiKeyOptions, ApiKeyRateLimitOptions,
    ApiKeyReference, UPSTREAM_PLUGIN_ID,
};
use serde_json::{json, Value};

use super::helpers::{request_json, sign_up, test_router};

#[test]
fn multiple_configurations_require_unique_config_ids() -> Result<(), Box<dyn std::error::Error>> {
    let missing = ApiKeyOptions::builder().configurations(vec![
        ApiKeyConfiguration::default(),
        ApiKeyConfiguration {
            config_id: Some("second".to_owned()),
            ..ApiKeyConfiguration::default()
        },
    ]);
    assert!(missing.build().is_err());

    let duplicate = ApiKeyOptions::builder().configurations(vec![
        ApiKeyConfiguration {
            config_id: Some("default".to_owned()),
            ..ApiKeyConfiguration::default()
        },
        ApiKeyConfiguration {
            config_id: Some("default".to_owned()),
            ..ApiKeyConfiguration::default()
        },
    ]);
    assert!(duplicate.build().is_err());

    let plugin = api_key_with(
        ApiKeyOptions::builder()
            .configurations(vec![
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
            ])
            .build()?,
    )?;
    assert_eq!(plugin.id, UPSTREAM_PLUGIN_ID);

    Ok(())
}

#[tokio::test]
async fn list_without_config_id_merges_user_keys_from_all_configurations(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let plugin = api_key_with(
        ApiKeyOptions::builder()
            .configurations(vec![
                ApiKeyConfiguration {
                    config_id: Some("primary".to_owned()),
                    ..ApiKeyConfiguration::default()
                },
                ApiKeyConfiguration {
                    config_id: Some("secondary".to_owned()),
                    ..ApiKeyConfiguration::default()
                },
            ])
            .build()?,
    )?;
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

#[tokio::test]
async fn specific_config_id_controls_create_verify_get_update_and_delete(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let plugin = api_key_with(
        ApiKeyOptions::builder()
            .configurations(vec![
                ApiKeyConfiguration {
                    config_id: Some("default".to_owned()),
                    default_prefix: Some("def_".to_owned()),
                    rate_limit: ApiKeyRateLimitOptions {
                        max_requests: 10,
                        ..ApiKeyRateLimitOptions::default()
                    },
                    ..ApiKeyConfiguration::default()
                },
                ApiKeyConfiguration {
                    config_id: Some("public-api".to_owned()),
                    default_prefix: Some("pub_".to_owned()),
                    rate_limit: ApiKeyRateLimitOptions {
                        max_requests: 15,
                        ..ApiKeyRateLimitOptions::default()
                    },
                    ..ApiKeyConfiguration::default()
                },
            ])
            .build()?,
    )?;
    let router = test_router(adapter, plugin)?;
    let user = sign_up(&router, "Cfg", "cfg-api@example.com").await?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"configId":"public-api","name":"public-key"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["configId"], "public-api");
    assert_eq!(created.body["prefix"], "pub_");
    assert_eq!(created.body["rateLimitMax"], 15);
    let key = created.body["key"].as_str().ok_or("missing key")?;
    let key_id = created.body["id"].as_str().ok_or("missing id")?;

    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"configId":"public-api","key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.body["valid"], true);
    assert_eq!(verified.body["key"]["configId"], "public-api");
    assert_eq!(verified.body["key"]["rateLimitMax"], 15);

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list?configId=public-api",
        Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 1);
    assert_eq!(listed.body["apiKeys"][0]["id"], key_id);

    let fetched = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/get?configId=public-api&id={key_id}"),
        Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.body["configId"], "public-api");

    let updated = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"configId":"public-api","keyId": key_id, "name":"updated-public"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["configId"], "public-api");
    assert_eq!(updated.body["name"], "updated-public");

    let deleted = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/delete",
        json!({"configId":"public-api","keyId": key_id}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(deleted.status, StatusCode::OK);
    assert_eq!(deleted.body["success"], true);
    Ok(())
}

#[tokio::test]
async fn list_combines_sorting_with_pagination() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Pag", "pag-api@example.com").await?;

    for index in 0..5 {
        let created = request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": format!("pag-key-{index}")}),
            Some(&user.cookie),
            None,
        )
        .await?;
        assert_eq!(created.status, StatusCode::OK);
    }

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list?limit=3&offset=1&sortBy=name&sortDirection=desc",
        Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["limit"], 3);
    assert_eq!(listed.body["offset"], 1);
    assert_eq!(listed.body["total"], 5);
    let keys = listed.body["apiKeys"].as_array().ok_or("missing apiKeys")?;
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0]["name"], "pag-key-3");
    assert_eq!(keys[1]["name"], "pag-key-2");
    assert_eq!(keys[2]["name"], "pag-key-1");
    Ok(())
}
