use std::sync::Arc;

use http::StatusCode;
use openauth_core::db::MemoryAdapter;
use openauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use time::{Duration, OffsetDateTime};

use super::{nonce, options, options_rejecting_signature, response_json, router, verify, WALLET};

#[tokio::test]
async fn verify_endpoint_rejects_missing_nonce() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options())?;

    let response = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(&response)?["code"],
        "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
    );
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_rejects_expired_nonce() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    DbVerificationStore::new(adapter.as_ref())
        .create_verification(CreateVerificationInput::new(
            format!("siwe:{WALLET}:1"),
            "expired_nonce",
            OffsetDateTime::now_utc() - Duration::minutes(1),
        ))
        .await?;
    let router = router(adapter, options())?;

    let response = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(&response)?["code"],
        "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
    );
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_rejects_invalid_signature() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options_rejecting_signature())?;
    nonce(&router, WALLET, Some(1)).await?;

    let response = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "invalid_signature",
        None,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_rejects_invalid_message_with_valid_signature(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options())?;
    nonce(&router, WALLET, Some(1)).await?;

    let response = verify(
        &router,
        WALLET,
        Some(1),
        "invalid_message",
        "valid_signature",
        None,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_rejects_invalid_email_when_present(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options())?;
    nonce(&router, WALLET, Some(1)).await?;

    let response = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        Some("not-an-email"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_deletes_nonce_after_success() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options())?;
    nonce(&router, WALLET, Some(1)).await?;

    let first = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;
    let second = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_requires_email_when_anonymous_is_false(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options().anonymous(false))?;
    nonce(&router, WALLET, Some(1)).await?;

    let response = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_rejects_empty_email_when_anonymous_is_false(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options().anonymous(false))?;
    nonce(&router, WALLET, Some(1)).await?;

    let response = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        Some(""),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}
