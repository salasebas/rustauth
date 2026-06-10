use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::{DbAdapter, DbValue, FindOne, MemoryAdapter, Update, Where};
use openauth_plugins::api_key::{api_key, METADATA_DISABLED, NO_VALUES_TO_UPDATE};
use openauth_plugins::api_key::{api_key_with, ApiKeyConfiguration, ApiKeyOptions, API_KEY_MODEL};
use serde_json::json;

use super::helpers::{request_json, sign_up, test_router};

#[tokio::test]
async fn metadata_requires_explicit_enablement() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Fay", "fay-api@example.com").await?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"plain"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let create_with_metadata = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"with-metadata","metadata":{"env":"prod"}}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(create_with_metadata.status, StatusCode::BAD_REQUEST);
    assert_eq!(create_with_metadata.body["code"], METADATA_DISABLED);

    let update_with_metadata = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "metadata":{"env":"prod"}}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(update_with_metadata.status, StatusCode::BAD_REQUEST);
    assert_eq!(update_with_metadata.body["code"], NO_VALUES_TO_UPDATE);
    Ok(())
}

#[tokio::test]
async fn database_backed_reads_migrate_double_stringified_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter.clone(),
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_metadata: true,
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Meta", "meta-api@example.com").await?;
    let mut keys = Vec::new();
    for name in ["get", "list", "verify", "update"] {
        let created = request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": name, "metadata": {"initial": name}}),
            Some(&user.cookie),
            None,
        )
        .await?;
        keys.push((
            created.body["id"].as_str().ok_or("missing id")?.to_owned(),
            created.body["key"]
                .as_str()
                .ok_or("missing key")?
                .to_owned(),
        ));
    }

    for (index, (id, _key)) in keys.iter().enumerate() {
        set_legacy_metadata(&adapter, id, json!({ "legacy": index })).await?;
    }

    let get = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/get?id={}", keys[0].0),
        serde_json::Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(get.body["metadata"], json!({ "legacy": 0 }));
    assert_metadata_migrated(&adapter, &keys[0].0, json!({ "legacy": 0 })).await?;

    let list = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        serde_json::Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert!(
        list.body["apiKeys"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|api_key| api_key["id"] == keys[1].0
                && api_key["metadata"] == json!({ "legacy": 1 }))
    );
    assert_metadata_migrated(&adapter, &keys[1].0, json!({ "legacy": 1 })).await?;

    let verify = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": keys[2].1}),
        None,
        None,
    )
    .await?;
    assert_eq!(verify.body["key"]["metadata"], json!({ "legacy": 2 }));
    assert_metadata_migrated(&adapter, &keys[2].0, json!({ "legacy": 2 })).await?;

    let update = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": keys[3].0, "name": "updated"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(update.body["metadata"], json!({ "legacy": 3 }));
    assert_metadata_migrated(&adapter, &keys[3].0, json!({ "legacy": 3 })).await?;
    Ok(())
}

async fn set_legacy_metadata(
    adapter: &MemoryAdapter,
    id: &str,
    metadata: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let legacy = serde_json::to_string(&serde_json::to_string(&metadata)?)?;
    adapter
        .update(
            Update::new(API_KEY_MODEL)
                .where_clause(Where::new("id", DbValue::String(id.to_owned())))
                .data("metadata", DbValue::String(legacy)),
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn properly_formatted_metadata_does_not_require_migration(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter.clone(),
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    enable_metadata: true,
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
    )?;
    let user = sign_up(&router, "Plain", "plain-meta@example.com").await?;
    let metadata = json!({ "alreadyCorrect": true, "value": 123 });

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name": "plain-meta", "metadata": metadata}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key_id = created.body["id"].as_str().ok_or("missing id")?;

    let fetched = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/get?id={key_id}"),
        serde_json::Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(fetched.body["metadata"], metadata);
    assert_metadata_migrated(&adapter, key_id, metadata).await?;
    Ok(())
}

async fn assert_metadata_migrated(
    adapter: &MemoryAdapter,
    id: &str,
    expected: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let record = adapter
        .find_one(
            FindOne::new(API_KEY_MODEL)
                .where_clause(Where::new("id", DbValue::String(id.to_owned()))),
        )
        .await?
        .ok_or("missing api key")?;
    assert_eq!(record.get("metadata"), Some(&DbValue::Json(expected)));
    Ok(())
}
