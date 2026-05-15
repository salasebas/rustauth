use std::sync::{Arc, Mutex};

use http::StatusCode;
use openauth_core::db::{DbValue, MemoryAdapter};

use super::{nonce, options, record_by_string, response_json, router, WALLET};

#[tokio::test]
async fn nonce_endpoint_returns_nonce_and_stores_chain_scoped_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone(), options())?;

    let response = nonce(&router, WALLET, Some(137)).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(&response)?["nonce"], "A1b2C3d4E5f6G7h8J");
    let stored = record_by_string(
        &adapter,
        "verification",
        "identifier",
        "siwe:0x000000000000000000000000000000000000dEaD:137",
    )
    .await?
    .ok_or("verification missing")?;
    assert_eq!(
        stored.get("value"),
        Some(&DbValue::String("A1b2C3d4E5f6G7h8J".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn nonce_endpoint_defaults_chain_id_to_one() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter.clone(), options())?;

    let response = nonce(&router, WALLET, None).await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(record_by_string(
        &adapter,
        "verification",
        "identifier",
        "siwe:0x000000000000000000000000000000000000dEaD:1",
    )
    .await?
    .is_some());
    Ok(())
}

#[tokio::test]
async fn nonce_endpoint_rejects_invalid_wallet_address() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let router = router(adapter, options())?;

    let response = nonce(&router, "invalid", None).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn verify_message_receives_checksum_chain_signature_and_cacao(
) -> Result<(), Box<dyn std::error::Error>> {
    let adapter = Arc::new(MemoryAdapter::new());
    let seen = Arc::new(Mutex::new(None));
    let seen_for_callback = Arc::clone(&seen);
    let opts = openauth_plugins::siwe::SiweOptions::new(
        "example.com",
        || async { Ok("nonce-for-cacao".to_owned()) },
        move |args: openauth_plugins::siwe::SiweVerifyMessageArgs| {
            let seen_for_callback = Arc::clone(&seen_for_callback);
            async move {
                seen_for_callback
                    .lock()
                    .map_err(|_| {
                        openauth_core::error::OpenAuthError::Api("lock poisoned".to_owned())
                    })?
                    .replace(args);
                Ok(true)
            }
        },
    );
    let router = router(adapter, opts)?;

    nonce(&router, &WALLET.to_lowercase(), Some(137)).await?;
    super::verify(
        &router,
        &WALLET.to_lowercase(),
        Some(137),
        "message",
        "signature",
        None,
    )
    .await?;

    let args = seen
        .lock()
        .map_err(|_| "lock poisoned")?
        .clone()
        .ok_or("verify args missing")?;
    assert_eq!(args.address, WALLET);
    assert_eq!(args.chain_id, 137);
    assert_eq!(args.signature, "signature");
    assert_eq!(args.cacao.p.domain, "example.com");
    assert_eq!(args.cacao.p.nonce, "nonce-for-cacao");
    Ok(())
}
