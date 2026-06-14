use std::sync::Arc;

use http::{Method, StatusCode};
use rustauth_core::db::{DbAdapter, FindMany};
use rustauth_passkey::PasskeyOptions;
use serde_json::Value;

use crate::support::{
    cookie_header_from_response, empty_request, json_request_with_origin, seed_passkey,
    seeded_router_with_secondary_storage, InMemorySecondaryStorage,
};

#[tokio::test]
async fn generate_authenticate_options_persists_challenge_in_secondary_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(InMemorySecondaryStorage::default());
    let (adapter, router, _backend) =
        seeded_router_with_secondary_storage(PasskeyOptions::default(), storage.clone()).await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        storage.keys_with_prefix("verification:").len(),
        1,
        "challenge must be stored in secondary storage"
    );
    let db_challenges = adapter.find_many(FindMany::new("verification")).await?;
    assert!(
        db_challenges.is_empty(),
        "challenge must not fall back to the DB verification table"
    );
    Ok(())
}

#[tokio::test]
async fn passkey_login_session_resolves_from_secondary_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(InMemorySecondaryStorage::default());
    let (adapter, router, _backend) =
        seeded_router_with_secondary_storage(PasskeyOptions::default(), storage.clone()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;

    let options_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/generate-authenticate-options",
            None,
        )?)
        .await?;
    let passkey_cookie = cookie_header_from_response(&options_response);

    let verify_response = router
        .handle_async(json_request_with_origin(
            Method::POST,
            "/api/auth/passkey/verify-authentication",
            r#"{"response":{"id":"credential-id"}}"#,
            Some(&passkey_cookie),
        )?)
        .await?;
    assert_eq!(verify_response.status(), StatusCode::OK);

    assert!(
        !storage.keys_with_prefix("session:").is_empty(),
        "session must be persisted in secondary storage"
    );
    let db_sessions = adapter.find_many(FindMany::new("session")).await?;
    assert!(
        db_sessions.is_empty(),
        "session must not be written to the DB when store_session_in_database is false"
    );

    let session_cookie = cookie_header_from_response(&verify_response);
    let session_response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/get-session",
            Some(&session_cookie),
        )?)
        .await?;

    assert_eq!(session_response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(session_response.body())?;
    assert_eq!(
        body["user"]["id"], "user_1",
        "get-session must resolve the passkey session from secondary storage"
    );
    Ok(())
}
