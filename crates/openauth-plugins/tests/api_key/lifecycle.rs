use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::api_key::{
    api_key, api_key_with, ApiKeyConfiguration, ApiKeyExpirationOptions, ApiKeyOptions,
    ApiKeyReference, StartingCharactersConfig, API_KEY_MODEL, EXPIRES_IN_IS_TOO_LARGE,
    EXPIRES_IN_IS_TOO_SMALL, INVALID_PREFIX_LENGTH, KEY_NOT_FOUND, NAME_REQUIRED,
    NO_VALUES_TO_UPDATE, REFILL_INTERVAL_AND_AMOUNT_REQUIRED, SERVER_ONLY_PROPERTY,
    UNAUTHORIZED_SESSION,
};
use serde_json::{json, Value};

use super::helpers::{request_json, server_request_json, sign_up, test_router};

#[tokio::test]
async fn create_verify_get_list_update_and_delete_user_api_key(
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
async fn list_get_and_delete_auth_and_missing_key_errors() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Auth", "auth-api@example.com").await?;

    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"owned"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    let key_id = created.body["id"].as_str().ok_or("missing key id")?;

    let unauth_list = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/list",
        Value::Null,
        None,
        None,
    )
    .await?;
    assert_eq!(unauth_list.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_list.body["code"], UNAUTHORIZED_SESSION);

    let unauth_delete = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/delete",
        json!({"keyId": key_id}),
        None,
        None,
    )
    .await?;
    assert_eq!(unauth_delete.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauth_delete.body["code"], UNAUTHORIZED_SESSION);

    let missing_get = request_json(
        &router,
        Method::GET,
        "/api/auth/api-key/get?id=missing",
        Value::Null,
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(missing_get.status, StatusCode::NOT_FOUND);
    assert_eq!(missing_get.body["code"], KEY_NOT_FOUND);

    let missing_delete = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/delete",
        json!({"keyId": "missing"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(missing_delete.status, StatusCode::NOT_FOUND);
    assert_eq!(missing_delete.body["code"], KEY_NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn create_rejects_sessionless_and_client_only_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    require_name: true,
                    minimum_prefix_length: 2,
                    maximum_prefix_length: 4,
                    key_expiration: ApiKeyExpirationOptions {
                        min_expires_in_days: 2,
                        ..ApiKeyExpirationOptions::default()
                    },
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
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
async fn create_with_refill_keeps_omitted_remaining_null() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Rem", "rem-api@example.com").await?;

    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"refill-only","refillAmount": 10, "refillInterval": 1000, "userId": user.user_id}),
        None,
        None,
    )
    .await?;

    assert_eq!(created.status, StatusCode::OK);
    assert!(created.body["remaining"].is_null());
    Ok(())
}

#[tokio::test]
async fn generated_keys_use_upstream_letter_only_default_charset(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    default_key_length: 96,
                    default_prefix: Some("sk_".to_owned()),
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
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
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    disable_key_hashing: true,
                    starting_characters: StartingCharactersConfig {
                        should_store: true,
                        characters_length: 3,
                    },
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
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
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    starting_characters: StartingCharactersConfig {
                        should_store: false,
                        characters_length: 6,
                    },
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
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

    let server_remaining = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "userId": user.user_id, "remaining": 50}),
        None,
        None,
    )
    .await?;
    assert_eq!(server_remaining.status, StatusCode::OK);
    assert_eq!(server_remaining.body["remaining"], 50);
    assert!(server_remaining.body["lastRequest"].is_null());

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
async fn update_refill_interval_without_amount_returns_upstream_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Ria", "ria-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"refill"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let updated = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "refillInterval": 1000, "userId": user.user_id}),
        None,
        None,
    )
    .await?;

    assert_eq!(updated.status, StatusCode::BAD_REQUEST);
    assert_eq!(updated.body["code"], REFILL_INTERVAL_AND_AMOUNT_REQUIRED);
    Ok(())
}

#[tokio::test]
async fn update_validates_expiration_bounds() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(
        adapter,
        api_key_with(
            ApiKeyOptions::builder()
                .configuration(ApiKeyConfiguration {
                    key_expiration: ApiKeyExpirationOptions {
                        min_expires_in_days: 2,
                        max_expires_in_days: 3,
                        ..ApiKeyExpirationOptions::default()
                    },
                    ..ApiKeyConfiguration::default()
                })
                .build()?,
        )?,
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
    let created = server_request_json(
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

    let updated = server_request_json(
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

#[tokio::test]
async fn updating_key_metadata_does_not_touch_usage_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Usage", "usage-api@example.com").await?;
    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"usage","userId": user.user_id, "remaining": 5}),
        None,
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["remaining"], 5);
    assert!(created.body["lastRequest"].is_null());
    let key_id = created.body["id"].as_str().ok_or("missing key id")?;

    let updated = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "name":"usage-renamed"}),
        Some(&user.cookie),
        None,
    )
    .await?;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["name"], "usage-renamed");
    assert_eq!(updated.body["remaining"], 5);
    assert!(updated.body["lastRequest"].is_null());
    Ok(())
}

#[tokio::test]
async fn external_create_rejects_body_user_id_without_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let victim = sign_up(&router, "Vic", "vic-api@example.com").await?;

    // An internet client may not name an arbitrary user via the request body.
    let forged = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"forged","userId": victim.user_id}),
        None,
        None,
    )
    .await?;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
    assert_eq!(forged.body["code"], UNAUTHORIZED_SESSION);
    Ok(())
}

#[tokio::test]
async fn external_create_with_user_id_and_server_only_props_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let victim = sign_up(&router, "Sol", "sol-api@example.com").await?;

    // The previously vulnerable shape (no cookie + body userId + server-only
    // props) must now be rejected instead of silently provisioning a key.
    let forged = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"forged","userId": victim.user_id, "remaining": 5}),
        None,
        None,
    )
    .await?;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
    assert_eq!(forged.body["code"], UNAUTHORIZED_SESSION);

    // A session request that includes server-only props is still rejected with
    // the precise server-only error.
    let server_only = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"forged","remaining": 5}),
        Some(&victim.cookie),
        None,
    )
    .await?;
    assert_eq!(server_only.status, StatusCode::BAD_REQUEST);
    assert_eq!(server_only.body["code"], SERVER_ONLY_PROPERTY);
    Ok(())
}

#[tokio::test]
async fn external_update_rejects_body_user_id_without_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let owner = sign_up(&router, "Ona", "ona-api@example.com").await?;
    let created = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"victim-key"}),
        Some(&owner.cookie),
        None,
    )
    .await?;
    let key_id = created.body["id"].as_str().ok_or("missing api key id")?;

    let forged = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/update",
        json!({"keyId": key_id, "name":"hijacked", "userId": owner.user_id}),
        None,
        None,
    )
    .await?;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
    assert_eq!(forged.body["code"], UNAUTHORIZED_SESSION);
    Ok(())
}

#[tokio::test]
async fn server_side_create_trusts_body_user_id_and_server_props(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = test_router(adapter, api_key())?;
    let user = sign_up(&router, "Srv", "srv-api@example.com").await?;

    // The trusted server-side entry point still provisions for an explicit user.
    let created = server_request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({"name":"provisioned","userId": user.user_id, "remaining": 3}),
        None,
        None,
    )
    .await?;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["remaining"], 3);
    Ok(())
}

#[tokio::test]
async fn external_org_create_rejects_body_user_id_before_permission_check(
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
    let router = test_router(adapter, api_key_plugin)?;
    let victim = sign_up(&router, "Org", "org-api@example.com").await?;

    // An internet client must not be able to name a member id to act as them;
    // the request is rejected before any organization permission lookup runs.
    let forged = request_json(
        &router,
        Method::POST,
        "/api/auth/api-key/create",
        json!({
            "configId":"org",
            "organizationId":"org_123",
            "userId": victim.user_id,
            "name":"forged-org-key"
        }),
        None,
        None,
    )
    .await?;
    assert_eq!(forged.status, StatusCode::UNAUTHORIZED);
    assert_eq!(forged.body["code"], UNAUTHORIZED_SESSION);
    Ok(())
}
