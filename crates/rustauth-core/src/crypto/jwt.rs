//! Minimal HS256 JWT helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::Sha256;
use time::OffsetDateTime;

use crate::crypto::buffer::constant_time_equal;
use crate::error::RustAuthError;

type HmacSha256 = Hmac<Sha256>;

/// Sign a JSON-serializable payload as an HS256 JWT.
pub fn sign_jwt<T>(payload: &T, secret: &str, expires_in: i64) -> Result<String, RustAuthError>
where
    T: Serialize,
{
    let header = json!({ "alg": "HS256", "typ": "JWT" });
    let mut payload =
        serde_json::to_value(payload).map_err(|error| RustAuthError::Crypto(error.to_string()))?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if let Value::Object(map) = &mut payload {
        map.insert("iat".to_owned(), json!(now));
        map.insert("exp".to_owned(), json!(now + expires_in));
    }

    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|error| RustAuthError::Crypto(error.to_string()))?,
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload).map_err(|error| RustAuthError::Crypto(error.to_string()))?,
    );
    let signing_input = format!("{header}.{payload}");
    let signature = sign_bytes(signing_input.as_bytes(), secret)?;

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// Verify an HS256 JWT and deserialize its payload.
pub fn verify_jwt<T>(token: &str, secret: &str) -> Result<Option<T>, RustAuthError>
where
    T: DeserializeOwned,
{
    let Some((signing_input, signature)) = token.rsplit_once('.') else {
        return Ok(None);
    };
    let expected = sign_bytes(signing_input.as_bytes(), secret)?;
    let signature = match URL_SAFE_NO_PAD.decode(signature) {
        Ok(signature) => signature,
        Err(_) => return Ok(None),
    };
    if !constant_time_equal(expected, signature) {
        return Ok(None);
    }

    let mut parts = signing_input.split('.');
    let Some(_header) = parts.next() else {
        return Ok(None);
    };
    let Some(payload) = parts.next() else {
        return Ok(None);
    };
    if parts.next().is_some() {
        return Ok(None);
    }

    let payload = match URL_SAFE_NO_PAD.decode(payload) {
        Ok(payload) => payload,
        Err(_) => return Ok(None),
    };
    let value: Value = serde_json::from_slice(&payload)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?;
    if let Some(exp) = value.get("exp").and_then(Value::as_i64) {
        if exp < OffsetDateTime::now_utc().unix_timestamp() {
            return Ok(None);
        }
    }

    serde_json::from_value(value)
        .map(Some)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))
}

fn sign_bytes(data: &[u8], secret: &str) -> Result<Vec<u8>, RustAuthError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
