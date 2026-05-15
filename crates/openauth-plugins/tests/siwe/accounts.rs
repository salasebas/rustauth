use std::sync::Arc;

use http::StatusCode;
use openauth_core::db::{DbAdapter, DbValue, FindMany, MemoryAdapter, Where};
use openauth_plugins::siwe::{EnsLookupArgs, EnsLookupResult};

use super::{nonce, options, response_json, router, verify, WALLET};

#[tokio::test]
async fn verify_endpoint_creates_anonymous_user_wallet_account_and_session(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone(), options())?;
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

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(&response)?;
    let user_id = body["user"]["id"].as_str().ok_or("missing user id")?;
    assert_eq!(body["success"], true);
    assert_eq!(body["user"]["walletAddress"], WALLET);
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("session").await, 1);
    assert_eq!(adapter.len("walletAddress").await, 1);
    let accounts = adapter.records("account").await;
    assert!(accounts.iter().any(|record| {
        record.get("user_id") == Some(&DbValue::String(user_id.to_owned()))
            && record.get("provider_id") == Some(&DbValue::String("siwe".to_owned()))
            && record.get("account_id") == Some(&DbValue::String(format!("{WALLET}:1")))
    }));
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_uses_email_and_ens_metadata_when_configured(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let opts = options()
        .anonymous(false)
        .ens_lookup(|_args: EnsLookupArgs| async {
            Ok(Some(EnsLookupResult {
                name: "vitalik.eth".to_owned(),
                avatar: "https://example.com/avatar.png".to_owned(),
            }))
        });
    let router = router(adapter.clone(), opts)?;
    nonce(&router, WALLET, Some(1)).await?;

    let response = verify(
        &router,
        WALLET,
        Some(1),
        "valid_message",
        "valid_signature",
        Some("user@example.com"),
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let users = adapter.records("user").await;
    assert_eq!(
        users.first().and_then(|record| record.get("email")),
        Some(&DbValue::String("user@example.com".to_owned()))
    );
    assert_eq!(
        users.first().and_then(|record| record.get("name")),
        Some(&DbValue::String("vitalik.eth".to_owned()))
    );
    assert_eq!(
        users.first().and_then(|record| record.get("image")),
        Some(&DbValue::String(
            "https://example.com/avatar.png".to_owned()
        ))
    );
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_reuses_same_wallet_and_adds_second_chain(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone(), options())?;

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
    nonce(&router, WALLET, Some(137)).await?;
    let second = verify(
        &router,
        WALLET,
        Some(137),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    let wallet_records = adapter
        .find_many(
            FindMany::new("walletAddress")
                .where_clause(Where::new("address", DbValue::String(WALLET.to_owned()))),
        )
        .await?;
    assert_eq!(wallet_records.len(), 2);
    assert!(wallet_records.iter().any(|record| {
        record.get("chainId") == Some(&DbValue::Number(1))
            && record.get("isPrimary") == Some(&DbValue::Boolean(true))
    }));
    assert!(wallet_records.iter().any(|record| {
        record.get("chainId") == Some(&DbValue::Number(137))
            && record.get("isPrimary") == Some(&DbValue::Boolean(false))
    }));
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_reuses_same_wallet_when_case_changes(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone(), options())?;

    nonce(&router, &WALLET.to_lowercase(), Some(1)).await?;
    let first = verify(
        &router,
        &WALLET.to_lowercase(),
        Some(1),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;
    nonce(&router, &WALLET.to_uppercase(), Some(1)).await?;
    let second = verify(
        &router,
        &WALLET.to_uppercase(),
        Some(1),
        "valid_message",
        "valid_signature",
        None,
    )
    .await?;

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("walletAddress").await, 1);
    Ok(())
}

#[tokio::test]
async fn verify_endpoint_reuses_same_wallet_on_same_chain() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone(), options())?;

    nonce(&router, WALLET, Some(1)).await?;
    let first = response_json(
        &verify(
            &router,
            WALLET,
            Some(1),
            "valid_message",
            "valid_signature",
            None,
        )
        .await?,
    )?;
    nonce(&router, WALLET, Some(1)).await?;
    let second = response_json(
        &verify(
            &router,
            WALLET,
            Some(1),
            "valid_message",
            "valid_signature",
            None,
        )
        .await?,
    )?;

    assert_eq!(first["user"]["id"], second["user"]["id"]);
    assert_eq!(adapter.len("user").await, 1);
    assert_eq!(adapter.len("walletAddress").await, 1);
    Ok(())
}
