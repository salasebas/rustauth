use hmac::{Hmac, Mac};
use openauth_stripe::stripe_api::verify_webhook_signature;
use sha2::Sha256;

#[test]
fn webhook_signature_verification_accepts_valid_payload() -> Result<(), Box<dyn std::error::Error>>
{
    let payload = br#"{"id":"evt_123","type":"customer.subscription.updated"}"#;
    let secret = "whsec_test";
    let timestamp = 1_700_000_000_i64;
    let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(payload));
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())?;
    mac.update(signed_payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let header = format!("t={timestamp},v1={signature}");

    verify_webhook_signature(payload, &header, secret, 300, timestamp + 30)?;
    Ok(())
}

#[test]
fn webhook_signature_verification_rejects_stale_timestamp() -> Result<(), Box<dyn std::error::Error>>
{
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
