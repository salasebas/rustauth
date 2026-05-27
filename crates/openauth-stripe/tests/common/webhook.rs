use base64::Engine as _;
use hmac::{Hmac, Mac};
use http::{Method, Request};
use openauth_stripe::stripe_api::webhook_signing_key;
use sha2::Sha256;
use time::OffsetDateTime;

pub fn sign_webhook_payload(
    secret: &str,
    payload: &[u8],
    timestamp: i64,
) -> Result<String, Box<dyn std::error::Error>> {
    let signing_key = webhook_signing_key(secret)?;
    let signed_payload = format!("{timestamp}.{}", String::from_utf8_lossy(payload));
    let mut mac = Hmac::<Sha256>::new_from_slice(&signing_key)?;
    mac.update(signed_payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    Ok(format!("t={timestamp},v1={signature}"))
}

pub fn dashboard_webhook_secret(raw_key: &[u8]) -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode(raw_key)
    )
}

pub fn signed_webhook_request(
    secret: &str,
    payload: &[u8],
) -> Result<Request<Vec<u8>>, Box<dyn std::error::Error>> {
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signature = sign_webhook_payload(secret, payload, timestamp)?;
    Ok(Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/api/auth/stripe/webhook")
        .header("stripe-signature", signature)
        .body(payload.to_vec())?)
}
