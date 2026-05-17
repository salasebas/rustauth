use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::api_key::{
    api_key, api_key_with_options, ApiKeyConfiguration, ApiKeyExpirationOptions, ApiKeyOptions,
    StartingCharactersConfig, API_KEY_MODEL, EXPIRES_IN_IS_TOO_LARGE, EXPIRES_IN_IS_TOO_SMALL,
    INVALID_PREFIX_LENGTH, NAME_REQUIRED, NO_VALUES_TO_UPDATE, SERVER_ONLY_PROPERTY,
};
use serde_json::{json, Value};

use super::helpers::{request_json, sign_up, test_router};

#[tokio::test]
async fn create_verify_get_list_update_and_delete_user_api_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter.clone(),
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                enable_metadata: true,
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Ada", "ada-api@example.com").await?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"deploy","metadata":{"env":"prod"},"remaining": null}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key = created.body["key"]
        .as_str()
        .ok_or("missing plaintext key")?;
    assert_eq!(created.body["name"], "deploy");
    assert_eq!(created.body["metadata"]["env"], "prod");
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let rows = adapter.records(API_KEY_MODEL).await;
    assert_eq!(rows.len(), 1);
    assert_ne!(
        rows[0].get("key").and_then(|value| match value {
            openauth_core::db::DbValue::String(value) => Some(value.as_str()),
            _ => None,
        }),
        Some(key),
    );

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
    assert_eq!(verified.body["valid"], true);
    assert!(verified.body["key"]["key"].is_null());

    let fetched = request_json(
        &router,
        Method::GET,
        &format!("/api/auth/api-key/get?id={key_id}"),
        Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.body["id"], key_id);
    assert!(fetched.body["key"].is_null());

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 1);
    assert_eq!(listed.body["apiKeys"][0]["id"], key_id);

    let updated = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "name": "deploy-updated", "enabled": false}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["name"], "deploy-updated");
    assert_eq!(updated.body["enabled"], false);

    let delete = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/delete",
        json!({"keyId": key_id}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(delete.status, StatusCode::OK);
    assert_eq!(delete.body["success"], true);
    Ok(())
}

#[tokio::test]
async fn list_api_keys_preserves_total_when_paginated() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Pag", "pag-api@example.com").await?;

    for name in ["alpha", "beta", "gamma"] {
        let created = request_json(
            &router,
            Method::POST,
            "/api/auth/api-key/create",
            json!({"name": name}),
            Some(&user.cookie),
            None,
        )
        .await?;
        assert_eq!(created.status, StatusCode::OK);
    }

    let listed = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list?limit=1&offset=1&sortBy=name&sortDirection=asc",
        Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.body["total"], 3);
    assert_eq!(listed.body["apiKeys"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed.body["apiKeys"][0]["name"], "beta");
    Ok(())
}

#[tokio::test]
async fn create_rejects_sessionless_and_client_only_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                require_name: true,
                minimum_prefix_length: 2,
                maximum_prefix_length: 4,
                key_expiration: ApiKeyExpirationOptions {
                    min_expires_in_days: 2,
                    ..ApiKeyExpirationOptions::default()
                },
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Eve", "eve-api@example.com").await?;

    let unauthenticated = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"deploy"}),
        None,
        None,
    )
    .await?;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let server_only = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"deploy","remaining": 1}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(server_only.status, StatusCode::BAD_REQUEST);
    assert_eq!(server_only.body["code"], SERVER_ONLY_PROPERTY);

    let missing_name = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(missing_name.status, StatusCode::BAD_REQUEST);
    assert_eq!(missing_name.body["code"], NAME_REQUIRED);

    let invalid_prefix = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"deploy","prefix":"toolong"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(invalid_prefix.status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_prefix.body["code"], INVALID_PREFIX_LENGTH);

    let invalid_expiration = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"deploy","expiresIn": 60 * 60 * 24}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(invalid_expiration.status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_expiration.body["code"], EXPIRES_IN_IS_TOO_SMALL);
    Ok(())
}

#[tokio::test]
async fn generated_keys_use_upstream_letter_only_default_charset(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                default_key_length: 96,
                default_prefix: Some("sk_".to_owned()),
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Gus", "gus-api@example.com").await?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"letters"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key = created.body["key"].as_str().ok_or("missing api key")?;
    let generated = key.strip_prefix("sk_").ok_or("missing prefix")?;
    assert_eq!(generated.len(), 96);
    assert!(generated
        .chars()
        .all(|character| character.is_ascii_alphabetic()));
    assert_eq!(created.body["start"], &key[..6]);
    Ok(())
}

#[tokio::test]
async fn hashing_can_be_disabled_and_starting_characters_are_configurable(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter.clone(),
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                disable_key_hashing: true,
                starting_characters: StartingCharactersConfig {
                    should_store: true,
                    characters_length: 3,
                },
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Gia", "gia-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"plain"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key = created.body["key"].as_str().ok_or("missing api key")?;
    assert_eq!(created.body["start"], &key[..3]);
    let rows = adapter.records(API_KEY_MODEL).await;
    assert_eq!(
        rows[0].get("key").and_then(|value| match value {
            openauth_core::db::DbValue::String(value) => Some(value.as_str()),
            _ => None,
        }),
        Some(key),
    );

    let no_start_router = test_router(
        Arc::new(MemoryAdapter::new()),
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                starting_characters: StartingCharactersConfig {
                    should_store: false,
                    characters_length: 6,
                },
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let no_start_user = sign_up(&no_start_router, "Gia2", "gia2-api@example.com").await?;
    let no_start = request_json(
        &no_start_router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"hidden-start"}),
        Some(&no_start_user.cookie),
        None,
    )
    .await?;
    assert_eq!(no_start.status, StatusCode::OK);
    assert!(no_start.body["start"].is_null());
    Ok(())
}

#[tokio::test]
async fn update_rejects_empty_patch_and_disabled_keys_do_not_verify(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Gil", "gil-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"toggle"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key = created.body["key"].as_str().ok_or("missing api key")?;
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let empty_update = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(empty_update.status, StatusCode::BAD_REQUEST);
    assert_eq!(empty_update.body["code"], NO_VALUES_TO_UPDATE);

    let server_only_update = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "remaining": 7}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(server_only_update.status, StatusCode::BAD_REQUEST);
    assert_eq!(server_only_update.body["code"], SERVER_ONLY_PROPERTY);

    let disabled = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "enabled": false}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(disabled.status, StatusCode::OK);

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
    assert_eq!(
        verified.body["error"]["code"],
        openauth_plugins::api_key::KEY_DISABLED
    );
    Ok(())
}

#[tokio::test]
async fn update_validates_expiration_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with_options(ApiKeyOptions {
            configuration: ApiKeyConfiguration {
                key_expiration: ApiKeyExpirationOptions {
                    min_expires_in_days: 2,
                    max_expires_in_days: 3,
                    ..ApiKeyExpirationOptions::default()
                },
                ..ApiKeyConfiguration::default()
            },
        }),
    )?;
    let user = sign_up(&router, "Hal", "hal-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"bounded"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let too_small = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "expiresIn": 60 * 60 * 24}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(too_small.status, StatusCode::BAD_REQUEST);
    assert_eq!(too_small.body["code"], EXPIRES_IN_IS_TOO_SMALL);

    let too_large = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "expiresIn": 60 * 60 * 24 * 4}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(too_large.status, StatusCode::BAD_REQUEST);
    assert_eq!(too_large.body["code"], EXPIRES_IN_IS_TOO_LARGE);
    Ok(())
}

#[tokio::test]
async fn server_update_allows_explicit_null_expiration_and_permissions(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Nil", "nil-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({
            "name":"nullable",
            "userId": user.user_id,
            "expiresIn": 60 * 60 * 24 * 7,
            "permissions": {"post": ["read"]}
        }),
        None,
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert!(!created.body["expiresAt"].is_null());
    assert_eq!(created.body["permissions"]["post"][0], "read");
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let updated = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({
            "keyId": key_id,
            "userId": user.user_id,
            "expiresIn": null,
            "permissions": null
        }),
        None,
        None,
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert!(updated.body["expiresAt"].is_null());
    assert!(updated.body["permissions"].is_null());
    Ok(())
}
