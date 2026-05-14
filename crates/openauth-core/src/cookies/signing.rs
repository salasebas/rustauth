use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::OpenAuthError;

pub(super) fn hmac_base64(value: &str, secret: &str) -> Result<String, OpenAuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| OpenAuthError::Cookie(error.to_string()))?;
    mac.update(value.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

pub fn sign_cookie_value(value: &str, secret: &str) -> Result<String, OpenAuthError> {
    Ok(format!("{value}.{}", hmac_base64(value, secret)?))
}

pub fn verify_cookie_value(value: &str, secret: &str) -> Result<Option<String>, OpenAuthError> {
    let Some((unsigned, signature)) = value.rsplit_once('.') else {
        return Ok(None);
    };
    let expected = hmac_base64(unsigned, secret)?;
    if crate::crypto::buffer::constant_time_equal(expected.as_bytes(), signature.as_bytes()) {
        Ok(Some(unsigned.to_owned()))
    } else {
        Ok(None)
    }
}
