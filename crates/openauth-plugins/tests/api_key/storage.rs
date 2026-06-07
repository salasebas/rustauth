use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::{DbAdapter, DbValue, Delete, MemoryAdapter, Update, Where};
use openauth_core::options::SecondaryStorage;
use openauth_fred::{FredSecondaryStorage, FredSecondaryStorageOptions};
use openauth_plugins::api_key::{
    api_key_with_options, default_key_hasher, ApiKeyConfiguration, ApiKeyOptions,
    ApiKeyStorageMode, API_KEY_MODEL, INVALID_API_KEY,
};
use openauth_redis::{RedisSecondaryStorage, RedisSecondaryStorageOptions};
use serde_json::json;
use time::{Duration, OffsetDateTime};

use super::helpers::{
    request_json, server_request_json, sign_up, test_router, test_router_with_adapter,
    DelayedUpdateAdapter, TestSecondaryStorage,
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
async fn malformed_secondary_storage_payload_is_treated_as_missing(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
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
    let user = sign_up(&router, "Bad Cache", "bad-cache-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"malformed"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;
    let hashed = default_key_hasher(key);
    storage.insert_raw(format!("api-key:{hashed}"), "not-json");

    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;

    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.body["valid"], false);
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
    let created = server_request_json(
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

fn revalidating_router(
    adapter: Arc<MemoryAdapter>,
    storage: Arc<TestSecondaryStorage>,
) -> Result<openauth_core::api::AuthRouter, Box<dyn std::error::Error>> {
    test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                storage: ApiKeyStorageMode::SecondaryStorage,
                fallback_to_database: true,
                revalidate_secondary_against_database: true,
                custom_storage: Some(storage),
                ..ApiKeyConfiguration::default()
            },
        }),
    )
}

#[tokio::test]
async fn revalidation_list_reflects_out_of_band_database_delete(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = revalidating_router(adapter.clone(), storage)?;
    let user = sign_up(&router, "Rev", "rev-api@example.com").await?;
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
    assert_eq!(populated.body["total"], 1);

    adapter
        .delete(
            Delete::new(API_KEY_MODEL)
                .where_clause(Where::new("id", DbValue::String(key_id.to_owned()))),
        )
        .await?;

    // With revalidation enabled the database is the source of truth, so the
    // out-of-band delete is reflected immediately instead of being masked by
    // the stale cache.
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
    assert_eq!(listed.body["total"], 0);
    Ok(())
}

#[tokio::test]
async fn revalidation_revoked_database_key_fails_verify_and_purges_cache(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = revalidating_router(adapter.clone(), storage.clone())?;
    let user = sign_up(&router, "Rev Verify", "rev-verify-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"revocable"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let first = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(first.body["valid"], true);

    adapter
        .delete(
            Delete::new(API_KEY_MODEL)
                .where_clause(Where::new("id", DbValue::String(key_id.to_owned()))),
        )
        .await?;

    let second = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(second.body["valid"], false);
    assert_eq!(second.body["error"]["code"], INVALID_API_KEY);
    assert!(
        storage
            .deleted_keys()
            .iter()
            .any(|deleted| deleted == &format!("api-key:by-id:{key_id}")),
        "the stale cache entry should be purged when the database row is gone"
    );
    Ok(())
}

#[tokio::test]
async fn revalidation_refreshes_cache_when_database_record_is_newer(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = revalidating_router(adapter.clone(), storage)?;
    let user = sign_up(&router, "Rev Fresh", "rev-fresh-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"original"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    // Simulate an out-of-band database edit with a newer updated_at.
    adapter
        .update(
            Update::new(API_KEY_MODEL)
                .where_clause(Where::new("id", DbValue::String(key_id.to_owned())))
                .data("name", DbValue::String("renamed".to_owned()))
                .data(
                    "updated_at",
                    DbValue::Timestamp(OffsetDateTime::now_utc() + Duration::days(1)),
                ),
        )
        .await?;

    let verified = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/verify",
        json!({"key": key}),
        None,
        None,
    )
    .await?;
    assert_eq!(verified.body["valid"], true);
    assert_eq!(
        verified.body["key"]["name"], "renamed",
        "the newer database record should supersede the cached copy"
    );
    Ok(())
}

#[tokio::test]
async fn delete_expired_purges_secondary_entries() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
    let router = test_router(
        adapter.clone(),
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                storage: ApiKeyStorageMode::SecondaryStorage,
                fallback_to_database: true,
                defer_updates: true,
                custom_storage: Some(storage.clone()),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Exp", "exp-api@example.com").await?;
    let expiring = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"expiring"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let expiring_key = expiring.body["key"].as_str().ok_or("missing api key")?;
    let expiring_id = expiring.body["id"].as_str().ok_or("missing api key id")?;
    let expiring_hash = default_key_hasher(expiring_key);

    // Drive the key's expiry into the past directly in the database, leaving the
    // secondary cache entry behind (the scenario delete_expired must clean up).
    adapter
        .update(
            Update::new(API_KEY_MODEL)
                .where_clause(Where::new("id", DbValue::String(expiring_id.to_owned())))
                .data(
                    "expires_at",
                    DbValue::Timestamp(OffsetDateTime::now_utc() - Duration::days(1)),
                ),
        )
        .await?;

    // The dedicated endpoint bypasses the cleanup throttle and runs delete_expired.
    let cleaned = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/delete-all-expired-api-keys",
        serde_json::Value::Null,
        None,
        None,
    )
    .await?;
    assert_eq!(cleaned.status, StatusCode::OK);
    assert_eq!(cleaned.body["success"], true);

    let remaining_ids = adapter
        .records(API_KEY_MODEL)
        .await
        .into_iter()
        .filter_map(|record| match record.get("id") {
            Some(DbValue::String(id)) => Some(id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        !remaining_ids.iter().any(|id| id == expiring_id),
        "delete_expired should remove the expired row from the database; remaining={remaining_ids:?}"
    );

    let deleted = storage.deleted_keys();
    assert!(
        deleted
            .iter()
            .any(|key| key == &format!("api-key:by-id:{expiring_id}")),
        "delete_expired should evict the expired key's by-id cache entry"
    );
    assert!(
        deleted
            .iter()
            .any(|key| key == &format!("api-key:{expiring_hash}")),
        "delete_expired should evict the expired key's hash cache entry"
    );
    Ok(())
}

#[tokio::test]
async fn secondary_storage_concurrent_creates_keep_both_ids_in_ref_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    // The gate releases the two concurrent `api-key:by-ref:*` reads together,
    // which reproduces the lost update when the index read/modify/write is not
    // serialized: both creates would read the same starting vector and the
    // second write would drop the first id from `/api-key/list`.
    let storage = Arc::new(TestSecondaryStorage::with_ref_index_gate(2));
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
    let user = sign_up(&router, "Conc", "conc-api@example.com").await?;

    let (first, second) = tokio::join!(
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": "first"}),
            Some(&user.cookie),
            None,
        ),
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": "second"}),
            Some(&user.cookie),
            None,
        ),
    );
    let first = first?;
    let second = second?;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(second.status, StatusCode::OK);
    let first_id = first.body["id"]
        .as_str()
        .ok_or("missing first id")?
        .to_owned();
    let second_id = second.body["id"]
        .as_str()
        .ok_or("missing second id")?
        .to_owned();

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
    assert_eq!(
        listed.body["total"], 2,
        "both concurrently-created keys must remain in the listing index"
    );
    let listed_ids = listed.body["apiKeys"]
        .as_array()
        .ok_or("missing apiKeys array")?
        .iter()
        .filter_map(|api_key| api_key["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(
        listed_ids.contains(&first_id),
        "first concurrently-created key id missing from list: {listed_ids:?}"
    );
    assert!(
        listed_ids.contains(&second_id),
        "second concurrently-created key id missing from list: {listed_ids:?}"
    );
    Ok(())
}

#[tokio::test]
async fn secondary_storage_list_prunes_zombie_ids_from_ref_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let storage = Arc::new(TestSecondaryStorage::default());
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
    let user = sign_up(&router, "Zombie", "zombie-api@example.com").await?;

    let first = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name": "live"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let second = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name": "zombie"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(second.status, StatusCode::OK);
    let live_id = first.body["id"].as_str().ok_or("missing live id")?;
    let zombie_id = second.body["id"].as_str().ok_or("missing zombie id")?;

    storage.remove_raw(&format!("api-key:by-id:{zombie_id}"));

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
    assert_eq!(listed.body["apiKeys"][0]["id"], live_id);

    let ref_index = storage
        .value_for(&format!("api-key:by-ref:{}", user.user_id))
        .ok_or("missing repaired ref index")?;
    let indexed_ids = serde_json::from_str::<Vec<String>>(&ref_index)?;
    assert_eq!(indexed_ids, vec![live_id.to_owned()]);
    Ok(())
}

#[tokio::test]
async fn live_atomic_secondary_storage_concurrent_creates_keep_both_ids_in_ref_index(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut storages: Vec<(&str, Arc<dyn SecondaryStorage>)> = Vec::new();

    for target in live_secondary_storage_targets("OPENAUTH_REDIS_URL", "OPENAUTH_VALKEY_URL") {
        match RedisSecondaryStorage::connect_with_options(
            &target.url,
            RedisSecondaryStorageOptions {
                key_prefix: format!("openauth:test:api-key:{}:{}:", target.name, now_ms()),
                scan_count: 10,
            },
        )
        .await
        {
            Ok(storage) => storages.push((target.name, Arc::new(storage))),
            Err(error) if target.explicit => {
                return Err(format!(
                    "explicit {} Redis target `{}` is unavailable: {error}",
                    target.name, target.url
                )
                .into());
            }
            Err(error) => {
                eprintln!(
                    "skipping default {} Redis target `{}` because it is unavailable: {error}",
                    target.name, target.url
                );
            }
        }
    }

    for target in
        live_secondary_storage_targets("OPENAUTH_FRED_REDIS_URL", "OPENAUTH_FRED_VALKEY_URL")
    {
        match FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: format!("openauth:test:api-key:fred:{}:{}:", target.name, now_ms()),
                scan_count: 10,
            },
        )
        .await
        {
            Ok(storage) => storages.push((target.name, Arc::new(storage))),
            Err(error) if target.explicit => {
                return Err(format!(
                    "explicit {} Fred target `{}` is unavailable: {error}",
                    target.name, target.url
                )
                .into());
            }
            Err(error) => {
                eprintln!(
                    "skipping default {} Fred target `{}` because it is unavailable: {error}",
                    target.name, target.url
                );
            }
        }
    }

    for (name, storage) in storages {
        assert_concurrent_create_listing_keeps_both_ids(name, storage).await?;
    }
    Ok(())
}

async fn assert_concurrent_create_listing_keeps_both_ids(
    storage_name: &str,
    storage: Arc<dyn SecondaryStorage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                storage: ApiKeyStorageMode::SecondaryStorage,
                custom_storage: Some(storage),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let suffix = now_ms();
    let user = sign_up(
        &router,
        &format!("Live Conc {storage_name}"),
        &format!("live-conc-{storage_name}-{suffix}@example.com"),
    )
    .await?;

    let (first, second) = tokio::join!(
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": "first"}),
            Some(&user.cookie),
            None,
        ),
        request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": "second"}),
            Some(&user.cookie),
            None,
        ),
    );
    let first = first?;
    let second = second?;
    assert_eq!(first.status, StatusCode::OK, "{storage_name} first create");
    assert_eq!(
        second.status,
        StatusCode::OK,
        "{storage_name} second create"
    );
    let first_id = first.body["id"].as_str().ok_or("missing first id")?;
    let second_id = second.body["id"].as_str().ok_or("missing second id")?;

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        serde_json::Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK, "{storage_name} list");
    assert_eq!(
        listed.body["total"], 2,
        "{storage_name} must keep both concurrently-created keys in the reference index",
    );
    let listed_ids = listed.body["apiKeys"]
        .as_array()
        .ok_or("missing apiKeys array")?
        .iter()
        .filter_map(|api_key| api_key["id"].as_str())
        .collect::<Vec<_>>();
    assert!(
        listed_ids.contains(&first_id),
        "{storage_name} first concurrently-created key id missing from list: {listed_ids:?}"
    );
    assert!(
        listed_ids.contains(&second_id),
        "{storage_name} second concurrently-created key id missing from list: {listed_ids:?}"
    );
    Ok(())
}

#[derive(Debug)]
struct LiveSecondaryStorageTarget {
    name: &'static str,
    url: String,
    explicit: bool,
}

fn live_secondary_storage_targets(
    redis_env: &str,
    valkey_env: &str,
) -> Vec<LiveSecondaryStorageTarget> {
    let mut targets = Vec::new();
    if let Ok(url) = std::env::var(redis_env) {
        targets.push(LiveSecondaryStorageTarget {
            name: "redis",
            url,
            explicit: true,
        });
    }
    if let Ok(url) = std::env::var(valkey_env) {
        targets.push(LiveSecondaryStorageTarget {
            name: "valkey",
            url,
            explicit: true,
        });
    }
    if targets.is_empty() {
        targets.push(LiveSecondaryStorageTarget {
            name: "redis",
            url: "redis://127.0.0.1:6379".to_owned(),
            explicit: false,
        });
        targets.push(LiveSecondaryStorageTarget {
            name: "valkey",
            url: "valkey://127.0.0.1:6380".to_owned(),
            explicit: false,
        });
    }
    targets
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}
