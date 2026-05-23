use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::crypto::jwt::{sign_jwt, verify_jwt};
use crate::crypto::JweSecretSource;
use crate::error::OpenAuthError;
use crate::options::CookieCacheStrategy;

use super::chunked::ChunkedCookieStore;
use super::types::{AuthCookies, Cookie, CookieOptions};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieCachePayload<S, U> {
    pub session: S,
    pub user: U,
    pub updated_at: i64,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompactCookieEnvelope<S, U> {
    session: CookieCachePayload<S, U>,
    expires_at: i64,
    signature: String,
}

fn encode_compact_cache<S, U>(
    payload: &CookieCachePayload<S, U>,
    secret: &str,
    max_age: u64,
) -> Result<String, OpenAuthError>
where
    S: Serialize,
    U: Serialize,
{
    let expires_at = time::OffsetDateTime::now_utc().unix_timestamp() + max_age as i64;
    let signed = cache_signature_value(payload, expires_at)?;
    let signature = hmac_base64url(
        &serde_json::to_string(&signed).map_err(|error| {
            OpenAuthError::Cookie(format!(
                "could not serialize cookie cache signature: {error}"
            ))
        })?,
        secret,
    )?;
    let envelope = json!({
        "session": payload,
        "expires_at": expires_at,
        "signature": signature,
    });
    let json = serde_json::to_vec(&envelope).map_err(|error| {
        OpenAuthError::Cookie(format!(
            "could not serialize cookie cache envelope: {error}"
        ))
    })?;

    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn decode_compact_cache<S, U>(
    value: &str,
    secret: &str,
) -> Result<Option<CookieCachePayload<S, U>>, OpenAuthError>
where
    S: DeserializeOwned + Serialize,
    U: DeserializeOwned + Serialize,
{
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(value) else {
        return Ok(None);
    };
    let envelope: CompactCookieEnvelope<S, U> = match serde_json::from_slice(&decoded) {
        Ok(envelope) => envelope,
        Err(_) => return Ok(None),
    };
    if envelope.expires_at < time::OffsetDateTime::now_utc().unix_timestamp() {
        return Ok(None);
    }

    let signed = cache_signature_value(&envelope.session, envelope.expires_at)?;
    let expected = hmac_base64url(
        &serde_json::to_string(&signed).map_err(|error| {
            OpenAuthError::Cookie(format!(
                "could not serialize cookie cache signature: {error}"
            ))
        })?,
        secret,
    )?;
    if !crate::crypto::buffer::constant_time_equal(expected, envelope.signature) {
        return Ok(None);
    }

    Ok(Some(envelope.session))
}

fn cache_signature_value<S, U>(
    payload: &CookieCachePayload<S, U>,
    expires_at: i64,
) -> Result<Value, OpenAuthError>
where
    S: Serialize,
    U: Serialize,
{
    serde_json::to_value(json!({
        "session": payload.session,
        "user": payload.user,
        "updated_at": payload.updated_at,
        "version": payload.version,
        "expires_at": expires_at,
    }))
    .map_err(|error| OpenAuthError::Cookie(error.to_string()))
}

fn hmac_base64url(value: &str, secret: &str) -> Result<String, OpenAuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| OpenAuthError::Cookie(error.to_string()))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub fn set_cookie_cache<S, U>(
    auth_cookies: &AuthCookies,
    secret: &(impl JweSecretSource + ?Sized),
    payload: &CookieCachePayload<S, U>,
    strategy: CookieCacheStrategy,
    max_age: u64,
) -> Result<Vec<Cookie>, OpenAuthError>
where
    S: Serialize,
    U: Serialize,
{
    let data = match strategy {
        CookieCacheStrategy::Compact => {
            encode_compact_cache(payload, &secret.current_jwe_secret()?, max_age)?
        }
        CookieCacheStrategy::Jwt => {
            sign_jwt(payload, &secret.current_jwe_secret()?, max_age as i64)?
        }
        CookieCacheStrategy::Jwe => encode_jwe_cache(payload, secret, max_age)?,
    };
    let mut attributes = auth_cookies.session_data.attributes.clone();
    attributes.max_age = Some(max_age);
    let store = ChunkedCookieStore::new(auth_cookies.session_data.name.clone(), attributes, "");

    Ok(store.chunk(&data))
}

pub fn get_cookie_cache<S, U>(
    cookie_header: &str,
    cookie_name: &str,
    secret: &(impl JweSecretSource + ?Sized),
    strategy: CookieCacheStrategy,
    expected_version: Option<&str>,
) -> Result<Option<CookieCachePayload<S, U>>, OpenAuthError>
where
    S: DeserializeOwned + Serialize,
    U: DeserializeOwned + Serialize,
{
    let store = ChunkedCookieStore::new(cookie_name, CookieOptions::default(), cookie_header);
    let Some(data) = store.value() else {
        return Ok(None);
    };
    let Some(payload) = (match strategy {
        CookieCacheStrategy::Compact => decode_compact_cache(&data, &secret.current_jwe_secret()?)?,
        CookieCacheStrategy::Jwt => verify_jwt(&data, &secret.current_jwe_secret()?)?,
        CookieCacheStrategy::Jwe => decode_jwe_cache(&data, secret)?,
    }) else {
        return Ok(None);
    };

    if expected_version.is_some_and(|version| payload.version != version) {
        return Ok(None);
    }

    Ok(Some(payload))
}

#[cfg(feature = "jose")]
fn encode_jwe_cache<S, U>(
    payload: &CookieCachePayload<S, U>,
    secret: &(impl JweSecretSource + ?Sized),
    max_age: u64,
) -> Result<String, OpenAuthError>
where
    S: Serialize,
    U: Serialize,
{
    crate::crypto::symmetric_encode_jwt(payload, secret, max_age)
}

#[cfg(not(feature = "jose"))]
fn encode_jwe_cache<S, U>(
    _payload: &CookieCachePayload<S, U>,
    _secret: &(impl JweSecretSource + ?Sized),
    _max_age: u64,
) -> Result<String, OpenAuthError>
where
    S: Serialize,
    U: Serialize,
{
    Err(OpenAuthError::FeatureDisabled { feature: "jose" })
}

#[cfg(feature = "jose")]
fn decode_jwe_cache<S, U>(
    data: &str,
    secret: &(impl JweSecretSource + ?Sized),
) -> Result<Option<CookieCachePayload<S, U>>, OpenAuthError>
where
    S: DeserializeOwned,
    U: DeserializeOwned,
{
    crate::crypto::symmetric_decode_jwt(data, secret)
}

#[cfg(not(feature = "jose"))]
fn decode_jwe_cache<S, U>(
    _data: &str,
    _secret: &(impl JweSecretSource + ?Sized),
) -> Result<Option<CookieCachePayload<S, U>>, OpenAuthError>
where
    S: DeserializeOwned,
    U: DeserializeOwned,
{
    Err(OpenAuthError::FeatureDisabled { feature: "jose" })
}

#[cfg(all(test, not(feature = "jose")))]
mod tests {
    use super::*;
    use crate::cookies::get_cookies;
    use crate::options::OpenAuthOptions;

    #[derive(Debug, Serialize)]
    struct TestSession {
        id: String,
    }

    #[derive(Debug, Serialize)]
    struct TestUser {
        id: String,
    }

    #[test]
    fn jwe_cache_strategy_fails_closed_without_jose() -> Result<(), OpenAuthError> {
        let cookies = get_cookies(&OpenAuthOptions::default())?;
        let payload = CookieCachePayload {
            session: TestSession {
                id: "session_1".to_owned(),
            },
            user: TestUser {
                id: "user_1".to_owned(),
            },
            updated_at: 0,
            version: "1".to_owned(),
        };

        let result = set_cookie_cache(
            &cookies,
            "secret-a-at-least-32-chars-long!!",
            &payload,
            CookieCacheStrategy::Jwe,
            300,
        );

        assert!(matches!(
            result,
            Err(OpenAuthError::FeatureDisabled { feature: "jose" })
        ));
        Ok(())
    }
}
