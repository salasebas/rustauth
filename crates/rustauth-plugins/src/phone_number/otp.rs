use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use time::{Duration, OffsetDateTime};

use rustauth_core::crypto::buffer::constant_time_equal;
use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::error::RustAuthError;
use rustauth_core::verification::{CreateVerificationInput, DbVerificationStore};
use sha2::Sha256;

const OTP_MAC_DOMAIN: &[u8] = b"rustauth-phone-number-otp-v1";
const OTP_VALUE_VERSION: &str = "v1";
const OTP_SALT_LEN: usize = 32;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct StoredOtp<'a> {
    pub salt: &'a str,
    pub mac: &'a str,
    pub attempts: u32,
}

pub(crate) fn generate_otp(length: usize) -> String {
    generate_random_string(length)
        .bytes()
        .map(|byte| char::from(b'0' + (byte % 10)))
        .collect()
}

pub(crate) fn encode(
    secret: &str,
    identifier: &str,
    code: &str,
    attempts: u32,
) -> Result<String, RustAuthError> {
    let salt = generate_random_string(OTP_SALT_LEN);
    let mac = mac_otp(secret, identifier, &salt, code)?;
    Ok(format!("{OTP_VALUE_VERSION}:{salt}:{mac}:{attempts}"))
}

pub(crate) fn encode_stored(stored: StoredOtp<'_>, attempts: u32) -> String {
    format!(
        "{OTP_VALUE_VERSION}:{}:{}:{attempts}",
        stored.salt, stored.mac
    )
}

pub(crate) fn decode(value: &str) -> Option<StoredOtp<'_>> {
    let mut parts = value.split(':');
    let (Some(version), Some(salt), Some(mac), Some(attempts), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    if version != OTP_VALUE_VERSION || salt.is_empty() || mac.is_empty() {
        return None;
    };
    Some(StoredOtp {
        salt,
        mac,
        attempts: attempts.parse().unwrap_or(0),
    })
}

pub(crate) fn verify(
    secret: &str,
    identifier: &str,
    stored: StoredOtp<'_>,
    code: &str,
) -> Result<bool, RustAuthError> {
    let expected = mac_otp(secret, identifier, stored.salt, code)?;
    Ok(constant_time_equal(
        expected.as_bytes(),
        stored.mac.as_bytes(),
    ))
}

pub(crate) async fn create(
    adapter: &dyn rustauth_core::db::DbAdapter,
    secret: &str,
    identifier: impl Into<String>,
    code: &str,
    expires_in: Duration,
) -> Result<(), RustAuthError> {
    let identifier = identifier.into();
    let value = encode(secret, &identifier, code, 0)?;
    DbVerificationStore::new(adapter)
        .create_verification(CreateVerificationInput::new(
            identifier,
            value,
            OffsetDateTime::now_utc() + expires_in,
        ))
        .await?;
    Ok(())
}

fn mac_otp(
    secret: &str,
    identifier: &str,
    salt: &str,
    code: &str,
) -> Result<String, RustAuthError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| RustAuthError::Crypto("failed to initialize phone OTP MAC".to_owned()))?;
    mac.update(OTP_MAC_DOMAIN);
    mac.update(&[0]);
    mac.update(identifier.as_bytes());
    mac.update(&[0]);
    mac.update(salt.as_bytes());
    mac.update(&[0]);
    mac.update(code.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, verify};

    #[test]
    fn encoded_otp_does_not_reveal_plain_code() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = encode("test-secret", "+1234567890", "123456", 0)?;

        assert_ne!(encoded, "123456:0");
        assert!(!encoded.contains("123456"));
        let stored = decode(&encoded).ok_or("missing encoded otp parts")?;
        assert_eq!(stored.attempts, 0);
        assert!(verify("test-secret", "+1234567890", stored, "123456")?);
        assert!(!verify("test-secret", "+1234567890", stored, "000000")?);
        Ok(())
    }

    #[test]
    fn plaintext_legacy_values_are_not_accepted() {
        assert!(decode("123456:0").is_none());
    }
}
