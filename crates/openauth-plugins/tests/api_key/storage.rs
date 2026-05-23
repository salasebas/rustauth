use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::{DbAdapter, DbValue, Delete, MemoryAdapter, Where};
use openauth_plugins::api_key::{
    api_key_with_options, ApiKeyConfiguration, ApiKeyOptions, ApiKeyStorageMode, API_KEY_MODEL,
};
use serde_json::json;

use super::helpers::{
    request_json, sign_up, test_router, test_router_with_adapter, DelayedUpdateAdapter,
    TestSecondaryStorage,
};

#[tokio::test]
async fn secondary_storage_mode_does_not_write_database_rows(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = test_router(
        adapter.clone(),
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                storage: ApiKeyStorageMode::SecondaryStorage,
                custom_storage: Some(storage.clone()),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Cid", "cid-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"cache-only","expiresIn": 60 * 60 * 24}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(adapter.records(API_KEY_MODEL).await.len(), 0);
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;
    assert!(storage
        .ttl_for(&format!("api-key:by-id:{key_id}"))
        .flatten()
        .is_some_and(|ttl| ttl > 0));

    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": created.body["key"]}),
        None,
        None,
    )
    .await?;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.body["valid"], true);
    Ok(())
}

#[tokio::test]
async fn fallback_storage_keeps_database_as_source_and_invalidates_ref_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = test_router(
        adapter.clone(),
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                storage: ApiKeyStorageMode::SecondaryStorage,
                fallback_to_database: true,
                custom_storage: Some(storage.clone()),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Dom", "dom-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"fallback"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(adapter.records(API_KEY_MODEL).await.len(), 1);
    assert!(storage
        .deleted_keys()
        .iter()
        .any(|key| key == &format!("api-key:by-ref:{}", user.user_id)));

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        serde_json::Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 1);
    assert_eq!(listed.body["apiKeys"][0]["name"], "fallback");
    Ok(())
}

#[tokio::test]
async fn fallback_storage_list_reads_existing_ref_cache_before_database(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = test_router(
        adapter.clone(),
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                storage: ApiKeyStorageMode::SecondaryStorage,
                fallback_to_database: true,
                custom_storage: Some(storage),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Kai", "kai-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"cached"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let populated = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        serde_json::Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(populated.status, StatusCode::OK);
    assert_eq!(populated.body["total"], 1);

    adapter
        .delete(
            Delete::new(API_KEY_MODEL)
                .where_clause(Where::new("id", DbValue::String(key_id.to_owned()))),
        )
        .await?;

    let cached = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        serde_json::Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(cached.status, StatusCode::OK);
    assert_eq!(cached.body["total"], 1);
    assert_eq!(cached.body["apiKeys"][0]["id"], key_id);
    Ok(())
}

#[tokio::test]
async fn secondary_storage_list_fetches_key_records_concurrently(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::with_get_delay(20));
    let router = test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                storage: ApiKeyStorageMode::SecondaryStorage,
                custom_storage: Some(storage.clone()),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Lux", "lux-api@example.com").await?;

    for index in 0..12 {
        let created = request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": format!("key-{index:02}")}),
            Some(&user.cookie),
            None,
        )
        .await?;
        assert_eq!(created.status, StatusCode::OK);
    }

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        serde_json::Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 12);
    assert!(
        storage.max_active_gets() > 1,
        "expected list to fetch multiple API key records concurrently"
    );
    Ok(())
}

#[tokio::test]
async fn fallback_secondary_storage_keeps_usage_updates_consistent_under_concurrency(
) -> Result<(), Box<dyn std::error::Error>> {
    let memory = Arc::new(MemoryAdapter::new());
    let adapter: Arc<dyn DbAdapter> = Arc::new(DelayedUpdateAdapter::new(
        memory,
        std::time::Duration::from_millis(50),
    ));
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = test_router_with_adapter(
        adapter,
        vec![api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                storage: ApiKeyStorageMode::SecondaryStorage,
                fallback_to_database: true,
                custom_storage: Some(storage),
                ..ApiKeyConfiguration::default()
            },
        })],
    )?;
    let user = sign_up(&router, "Sec Race", "sec-race-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"fallback-single-use","userId": user.user_id, "remaining": 1}),
        None,
        None,
    )
    .await?;
    let key = created.body["key"]
        .as_str()
        .ok_or("missing api key")?
        .to_owned();

    let (first, second) = tokio::join!(
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/verify",
            json!({"key": key}),
            None,
            None,
        ),
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/verify",
            json!({"key": key}),
            None,
            None,
        ),
    );
    let responses = [first?, second?];
    let valid = responses
        .iter()
        .filter(|response| response.body["valid"] == true)
        .count();
    let usage_exceeded = responses
        .iter()
        .filter(|response| response.body["error"]["code"] == "USAGE_EXCEEDED")
        .count();

    assert_eq!(valid, 1, "fallback database should serialize usage updates");
    assert_eq!(
        usage_exceeded, 1,
        "second request should observe exhausted usage"
    );
    Ok(())
}
