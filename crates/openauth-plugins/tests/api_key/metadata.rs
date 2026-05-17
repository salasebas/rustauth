use std::sync::Arc;

use http::{Method, StatusCode};
use openauth_core::db::MemoryAdapter;
use openauth_plugins::api_key::{api_key, METADATA_DISABLED, NO_VALUES_TO_UPDATE};
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
