use base64::Engine as _;
use openauth_stripe::stripe_api::{verify_webhook_signature, webhook_signing_key};

#[path = "../common/mod.rs"]
mod common;

use common::webhook::{dashboard_webhook_secret, sign_webhook_payload};

#[test]
fn accepts_whsec_prefix_with_base64_secret() -> Result<(), Box<dyn std::error::Error>> {
    let raw_key = b"super-secret-signing-key!";
    let secret = dashboard_webhook_secret(raw_key);
    let payload = br#"{"id":"evt_dashboard","type":"customer.subscription.updated"}"#;
    let timestamp = 1_700_000_000_i64;
    let header = sign_webhook_payload(&secret, payload, timestamp)?;

    verify_webhook_signature(payload, &header, &secret, 300, timestamp + 30)?;
    assert_eq!(webhook_signing_key(&secret)?, raw_key.as_slice());
    Ok(())
}

#[test]
fn accepts_whsec_prefix_with_cli_style_base64_secret() -> Result<(), Box<dyn std::error::Error>> {
    // Stripe CLI prints secrets whose suffix is valid base64 (48-byte key when decoded).
    let suffix = "e5001980d26252f9b2b3460050d4bf794f6e7bce6bd00ddc181d6175974b8c98";
    let secret = format!("whsec_{suffix}");
    let raw_key = base64::engine::general_purpose::STANDARD.decode(suffix)?;
    let payload = br#"{"id":"evt_cli","type":"customer.subscription.created"}"#;
    let timestamp = 1_700_000_000_i64;
    let header = sign_webhook_payload(&secret, payload, timestamp)?;

    verify_webhook_signature(payload, &header, &secret, 300, timestamp + 30)?;
    assert_eq!(webhook_signing_key(&secret)?, raw_key.as_slice());
    Ok(())
}

#[test]
fn accepts_raw_secret_without_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let payload = br#"{"id":"evt_123","type":"customer.subscription.updated"}"#;
    let secret = "whsec_test";
    let timestamp = 1_700_000_000_i64;
    let header = sign_webhook_payload(secret, payload, timestamp)?;

    verify_webhook_signature(payload, &header, secret, 300, timestamp + 30)?;
    Ok(())
}

#[test]
fn rejects_stale_timestamp() -> Result<(), Box<dyn std::error::Error>> {
    let payload = br#"{"id":"evt_123"}"#;
    let secret = "whsec_test";
    let timestamp = 1_700_000_000_i64;
    let header = "t=1700000000,v1=bad";

    let error = verify_webhook_signature(payload, header, secret, 300, timestamp + 301)
        .err()
        .ok_or("stale signature should fail")?;

    assert_eq!(error.code(), "FAILED_TO_CONSTRUCT_STRIPE_EVENT");
    Ok(())
}

#[test]
fn rejects_invalid_v1_signature() -> Result<(), Box<dyn std::error::Error>> {
    let payload = br#"{"id":"evt_123"}"#;
    let secret = dashboard_webhook_secret(b"test-key");
    let timestamp = 1_700_000_000_i64;
    let header = format!("t={timestamp},v1=deadbeef");

    let error = verify_webhook_signature(payload, &header, &secret, 300, timestamp)
        .err()
        .ok_or("invalid signature should fail")?;

    assert_eq!(error.code(), "FAILED_TO_CONSTRUCT_STRIPE_EVENT");
    Ok(())
}
