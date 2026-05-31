use base64::Engine as _;
use hmac::{Hmac, Mac};
use openauth_stripe::stripe_api::verify_webhook_signature;
use sha2::Sha256;

#[path = "../common/mod.rs"]
mod common;

use common::webhook::{dashboard_webhook_secret, sign_webhook_payload};

#[test]
fn accepts_realistic_dashboard_secret() -> Result<(), Box<dyn std::error::Error>> {
    // Realistic Dashboard secret; the suffix is base64-decodable but must be
    // ignored: Stripe signs with the verbatim `whsec_...` string as the key.
    let secret = dashboard_webhook_secret(b"super-secret-signing-key!");
    let payload = br#"{"id":"evt_dashboard","type":"customer.subscription.updated"}"#;
    let timestamp = 1_700_000_000_i64;
    let header = sign_webhook_payload(&secret, payload, timestamp)?;

    verify_webhook_signature(payload, &header, &secret, 300, timestamp + 30)?;
    Ok(())
}

#[test]
fn rejects_legacy_base64_decoded_key() -> Result<(), Box<dyn std::error::Error>> {
    // Regression for OPE-39: a hex/alphanumeric `whsec_` suffix that is valid
    // base64. The previous implementation decoded the suffix and used those
    // bytes as the HMAC key. Signing with the literal secret must verify, while
    // signing with the legacy base64-decoded key must now fail.
    let suffix = "e5001980d26252f9b2b3460050d4bf794f6e7bce6bd00ddc181d6175974b8c98";
    let secret = format!("whsec_{suffix}");
    let payload = br#"{"id":"evt_cli","type":"customer.subscription.created"}"#;
    let timestamp = 1_700_000_000_i64;

    let header = sign_webhook_payload(&secret, payload, timestamp)?;
    verify_webhook_signature(payload, &header, &secret, 300, timestamp + 30)?;

    let legacy_key = base64::engine::general_purpose::STANDARD
        .decode(suffix)
        .map_err(|error| error.to_string())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&legacy_key)?;
    mac.update(format!("{timestamp}.{}", String::from_utf8_lossy(payload)).as_bytes());
    let legacy_header = format!(
        "t={timestamp},v1={}",
        hex::encode(mac.finalize().into_bytes())
    );

    let error = verify_webhook_signature(payload, &legacy_header, &secret, 300, timestamp + 30)
        .err()
        .ok_or("legacy base64-decoded signature must no longer verify")?;
    assert_eq!(error.code(), "FAILED_TO_CONSTRUCT_STRIPE_EVENT");
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
