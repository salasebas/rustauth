use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use url::form_urlencoded;

use openauth_core::error::OpenAuthError;

type HmacSha1 = Hmac<Sha1>;

pub fn totp_code(secret: &str, digits: u32, period: u64, unix_timestamp: i64) -> String {
    let counter = (unix_timestamp.max(0) as u64) / period.max(1);
    hotp(secret.as_bytes(), counter, digits)
}

pub fn verify_totp_code(secret: &str, code: &str, digits: u32, period: u64) -> bool {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    [-1_i64, 0, 1].into_iter().any(|offset| {
        let timestamp = now + (offset * period.max(1) as i64);
        let expected = totp_code(secret, digits, period, timestamp);
        expected.as_bytes().ct_eq(code.as_bytes()).into()
    })
}

pub fn totp_uri(secret: &str, issuer: &str, account: &str, digits: u32, period: u64) -> String {
    let encoded_secret = BASE32_NOPAD.encode(secret.as_bytes());
    let encoded_issuer = component_encode(issuer);
    let encoded_account = component_encode(account);
    let encoded_label = format!("{encoded_issuer}:{encoded_account}");
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", &encoded_secret)
        .append_pair("issuer", issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", &digits.to_string())
        .append_pair("period", &period.to_string())
        .finish();
    format!("otpauth://totp/{encoded_label}?{query}")
}

fn component_encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    let Ok(mut mac) = HmacSha1::new_from_slice(secret) else {
        return "0".repeat(digits as usize);
    };
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let binary = (u32::from(result[offset] & 0x7f) << 24)
        | (u32::from(result[offset + 1]) << 16)
        | (u32::from(result[offset + 2]) << 8)
        | u32::from(result[offset + 3]);
    let modulo = 10_u32.saturating_pow(digits);
    format!("{:0width$}", binary % modulo, width = digits as usize)
}

pub fn validate_digits(digits: u32) -> Result<(), OpenAuthError> {
    if matches!(digits, 6 | 8) {
        Ok(())
    } else {
        Err(OpenAuthError::InvalidConfig(
            "two factor TOTP digits must be 6 or 8".to_owned(),
        ))
    }
}
