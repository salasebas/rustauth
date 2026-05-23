use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use josekit::jwk::JwkSet;
use josekit::jwt;

use super::claims::TokenValidationOptions;
use super::error::OAuthError;
use super::http::{default_http_client, OAuthHttpClient};
use super::token_validation::{verify_jws_with_jwks, TokenValidationResult};

pub async fn get_jwks(jwks_url: &str) -> Result<JwkSet, OAuthError> {
    get_jwks_with_client(jwks_url, &default_http_client()?).await
}

pub async fn get_jwks_with_client(
    jwks_url: &str,
    client: &OAuthHttpClient,
) -> Result<JwkSet, OAuthError> {
    let bytes = client.get_bytes(jwks_url).await?;
    JwkSet::from_bytes(bytes).map_err(Into::into)
}

pub async fn verify_jws_access_token(
    token: &str,
    jwks_url: &str,
    verify_options: TokenValidationOptions,
) -> Result<TokenValidationResult, OAuthError> {
    verify_jws_access_token_with_client(token, jwks_url, verify_options, &default_http_client()?)
        .await
}

pub(crate) async fn verify_jws_access_token_with_client(
    token: &str,
    jwks_url: &str,
    verify_options: TokenValidationOptions,
    client: &OAuthHttpClient,
) -> Result<TokenValidationResult, OAuthError> {
    let jwks = get_cached_jwks_for_token(token, jwks_url, client).await?;
    let mut result = verify_jws_with_jwks(token, &jwks, &verify_options)?;
    map_azp_to_client_id(&mut result.payload);
    Ok(result)
}

pub fn clear_jwks_cache() -> Result<(), OAuthError> {
    jwks_cache()
        .lock()
        .map_err(|_| OAuthError::InvalidConfiguration("jwks cache lock poisoned".to_owned()))?
        .clear();
    Ok(())
}

fn map_azp_to_client_id(payload: &mut serde_json::Value) {
    let Some(authorized_party) = payload.get("azp").cloned() else {
        return;
    };
    if let Some(object) = payload.as_object_mut() {
        object.insert("client_id".to_owned(), authorized_party);
    }
}

async fn get_cached_jwks_for_token(
    token: &str,
    jwks_url: &str,
    client: &OAuthHttpClient,
) -> Result<JwkSet, OAuthError> {
    let kid = jwt::decode_header(token).ok().and_then(|header| {
        header
            .as_any()
            .downcast_ref::<josekit::jws::JwsHeader>()
            .and_then(|header| header.key_id().map(str::to_owned))
    });
    if let Some(cached) = cached_jwks(jwks_url)? {
        if kid
            .as_deref()
            .is_some_and(|kid| cached.get(kid).into_iter().next().is_some())
        {
            return Ok(cached);
        }
    }
    let jwks = get_jwks_with_client(jwks_url, client).await?;
    cache_jwks(jwks_url, &jwks)?;
    Ok(jwks)
}

fn cached_jwks(jwks_url: &str) -> Result<Option<JwkSet>, OAuthError> {
    jwks_cache()
        .lock()
        .map_err(|_| OAuthError::InvalidConfiguration("jwks cache lock poisoned".to_owned()))
        .map(|cache| cache.get(jwks_url).cloned())
}

fn cache_jwks(jwks_url: &str, jwks: &JwkSet) -> Result<(), OAuthError> {
    jwks_cache()
        .lock()
        .map_err(|_| OAuthError::InvalidConfiguration("jwks cache lock poisoned".to_owned()))?
        .insert(jwks_url.to_owned(), jwks.clone());
    Ok(())
}

fn jwks_cache() -> &'static Mutex<HashMap<String, JwkSet>> {
    static CACHE: OnceLock<Mutex<HashMap<String, JwkSet>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
