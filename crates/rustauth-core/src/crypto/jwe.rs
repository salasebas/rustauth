//! JWE helpers for encrypted JWT-style payloads.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use josekit::jwe::{self, Dir, JweHeader};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

pub use crate::crypto::jwe_secret::{JweSecret, JweSecretSource};
use crate::error::RustAuthError;

const JWE_SALT: &str = "better-auth-session";
const JWE_ENC: &str = "A256CBC-HS512";
const HKDF_INFO: &[u8] = b"BetterAuth.js Generated Encryption Key";
const CLOCK_TOLERANCE_SECONDS: i64 = 15;

pub fn symmetric_encode_jwt<T, K>(
    payload: &T,
    secret: &K,
    expires_in: u64,
) -> Result<String, RustAuthError>
where
    T: Serialize,
    K: JweSecretSource + ?Sized,
{
    symmetric_encode_jwt_with_salt(payload, secret, JWE_SALT, expires_in)
}

pub fn symmetric_decode_jwt<T, K>(token: &str, secret: &K) -> Result<Option<T>, RustAuthError>
where
    T: DeserializeOwned,
    K: JweSecretSource + ?Sized,
{
    symmetric_decode_jwt_with_salt(token, secret, JWE_SALT)
}

pub fn symmetric_encode_jwt_with_salt<T, K>(
    payload: &T,
    secret: &K,
    salt: &str,
    expires_in: u64,
) -> Result<String, RustAuthError>
where
    T: Serialize,
    K: JweSecretSource + ?Sized,
{
    let current_secret = secret.current_jwe_secret()?;
    let encryption_secret = derive_encryption_secret(&current_secret, salt)?;
    let kid = jwk_thumbprint(&encryption_secret);
    let claims = claims_with_registered_fields(payload, expires_in)?;

    let mut header = JweHeader::new();
    header.set_content_encryption(JWE_ENC);
    header.set_key_id(kid);

    let encrypter = Dir
        .encrypter_from_bytes(encryption_secret)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?;
    jwe::serialize_compact(&claims, &header, &encrypter)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))
}

pub fn symmetric_decode_jwt_with_salt<T, K>(
    token: &str,
    secret: &K,
    salt: &str,
) -> Result<Option<T>, RustAuthError>
where
    T: DeserializeOwned,
    K: JweSecretSource + ?Sized,
{
    if token.is_empty() {
        return Ok(None);
    }
    let Some(kid) = protected_header_kid(token) else {
        return Ok(None);
    };
    let secrets = secret.all_jwe_secrets()?;

    if let Some(kid) = kid {
        let Some(secret) = secrets
            .iter()
            .find(|secret| secret_kid(&secret.value, salt).is_ok_and(|value| value == kid))
        else {
            return Ok(None);
        };
        return decrypt_with_secret(token, &secret.value, salt);
    }

    for secret in secrets {
        if let Some(payload) = decrypt_with_secret(token, &secret.value, salt)? {
            return Ok(Some(payload));
        }
    }
    Ok(None)
}

fn derive_encryption_secret(secret: &str, salt: &str) -> Result<[u8; 64], RustAuthError> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret.as_bytes());
    let mut key = [0_u8; 64];
    hkdf.expand(HKDF_INFO, &mut key)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?;
    Ok(key)
}

fn claims_with_registered_fields<T>(payload: &T, expires_in: u64) -> Result<Vec<u8>, RustAuthError>
where
    T: Serialize,
{
    let mut claims = match serde_json::to_value(payload)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?
    {
        Value::Object(claims) => claims,
        _ => {
            return Err(RustAuthError::Crypto(
                "JWE payload must serialize to a JSON object".to_owned(),
            ));
        }
    };

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    claims.insert("iat".to_owned(), Value::Number(Number::from(now)));
    claims.insert(
        "exp".to_owned(),
        Value::Number(Number::from(now + expires_in as i64)),
    );
    claims.insert("jti".to_owned(), Value::String(random_jti()));

    serde_json::to_vec(&Value::Object(claims))
        .map_err(|error| RustAuthError::Crypto(error.to_string()))
}

fn decrypt_with_secret<T>(token: &str, secret: &str, salt: &str) -> Result<Option<T>, RustAuthError>
where
    T: DeserializeOwned,
{
    let encryption_secret = derive_encryption_secret(secret, salt)?;
    let decrypter = Dir
        .decrypter_from_bytes(encryption_secret)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))?;
    let Ok((payload, header)) = jwe::deserialize_compact(token, &decrypter) else {
        return Ok(None);
    };
    if header.content_encryption() != Some(JWE_ENC) {
        return Ok(None);
    }

    let value: Value = serde_json::from_slice(&payload)
        .map_err(|error| RustAuthError::Crypto(format!("could not parse JWE payload: {error}")))?;
    if is_expired(&value) {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(|error| RustAuthError::Crypto(error.to_string()))
}

fn is_expired(value: &Value) -> bool {
    let Some(exp) = value.get("exp").and_then(Value::as_i64) else {
        return false;
    };
    exp + CLOCK_TOLERANCE_SECONDS < time::OffsetDateTime::now_utc().unix_timestamp()
}

fn protected_header_kid(token: &str) -> Option<Option<String>> {
    let protected = token.split('.').next()?;
    let decoded = URL_SAFE_NO_PAD.decode(protected).ok()?;
    let header: Map<String, Value> = serde_json::from_slice(&decoded).ok()?;
    Some(header.get("kid").and_then(Value::as_str).map(str::to_owned))
}

fn secret_kid(secret: &str, salt: &str) -> Result<String, RustAuthError> {
    let encryption_secret = derive_encryption_secret(secret, salt)?;
    Ok(jwk_thumbprint(&encryption_secret))
}

fn jwk_thumbprint(key: &[u8; 64]) -> String {
    let key = URL_SAFE_NO_PAD.encode(key);
    let canonical = format!(r#"{{"k":"{key}","kty":"oct"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn random_jti() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ])
    )
}
