use http::{Method, StatusCode};
use openauth_core::db::{DbAdapter, DbValue, FindOne, Where};
use openauth_passkey::PasskeyOptions;
use serde_json::Value;

use crate::support::{
    empty_request, json_request, seed_passkey, seed_user_two, seeded_router, session_cookie_for,
};

#[tokio::test]
async fn update_and_delete_require_passkey_ownership() -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_user_two(adapter.as_ref()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "original",
        "credential-id",
    )
    .await?;
    let user_two_cookie = session_cookie_for(&adapter, "user_2", "token_2").await?;

    let update = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/update-passkey",
            r#"{"id":"passkey_1","name":"hacked"}"#,
            Some(&user_two_cookie),
        )?)
        .await?;
    assert_eq!(update.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(update.body())?;
    assert_eq!(body["code"], "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY");

    let delete = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/delete-passkey",
            r#"{"id":"passkey_1"}"#,
            Some(&user_two_cookie),
        )?)
        .await?;
    assert_eq!(delete.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(delete.body())?;
    assert_eq!(body["code"], "UNAUTHORIZED");

    let unchanged = adapter
        .find_one(
            FindOne::new("passkey")
                .where_clause(Where::new("id", DbValue::String("passkey_1".to_owned()))),
        )
        .await?
        .ok_or("missing passkey")?;
    assert_eq!(
        unchanged.get("name"),
        Some(&DbValue::String("original".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn list_passkeys_serializes_upstream_credential_id_field(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    seed_passkey(
        adapter.as_ref(),
        "passkey_1",
        "user_1",
        "Laptop",
        "credential-id",
    )
    .await?;
    let session_cookie = session_cookie_for(&adapter, "user_1", "token_1").await?;

    let response = router
        .handle_async(empty_request(
            Method::GET,
            "/api/auth/passkey/list-user-passkeys",
            Some(&session_cookie),
        )?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(response.body())?;
    assert_eq!(body[0]["credentialID"], "credential-id");
    assert!(body[0].get("credentialId").is_none());
    Ok(())
}

#[tokio::test]
async fn update_and_delete_missing_passkey_return_not_found(
) -> Result<(), Box<dyn std::error::Error>> {
    let (adapter, router, _backend) = seeded_router(PasskeyOptions::default()).await?;
    let session_cookie = session_cookie_for(&adapter, "user_1", "token_1").await?;

    let update = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/update-passkey",
            r#"{"id":"missing","name":"new"}"#,
            Some(&session_cookie),
        )?)
        .await?;
    assert_eq!(update.status(), StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_slice(update.body())?;
    assert_eq!(body["code"], "PASSKEY_NOT_FOUND");

    let delete = router
        .handle_async(json_request(
            Method::POST,
            "/api/auth/passkey/delete-passkey",
            r#"{"id":"missing"}"#,
            Some(&session_cookie),
        )?)
        .await?;
    assert_eq!(delete.status(), StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_slice(delete.body())?;
    assert_eq!(body["code"], "PASSKEY_NOT_FOUND");
    Ok(())
}
