use josekit::jwk::JwkSet;
use josekit::jwt;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::claims::TokenValidationOptions;
use super::error::OAuthError;
use super::http::{default_http_client, OAuthHttpClient};
use super::token_validation::{verify_jws_with_jwks, TokenValidationResult};

const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_JWKS_CACHE_MAX_ENTRIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthJwksCacheConfig {
    pub ttl: Duration,
    pub max_entries: usize,
}

impl Default for OAuthJwksCacheConfig {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_JWKS_CACHE_TTL,
            max_entries: DEFAULT_JWKS_CACHE_MAX_ENTRIES,
        }
    }
}

impl OAuthJwksCacheConfig {
    pub fn new(ttl: Duration, max_entries: usize) -> Result<Self, OAuthError> {
        let config = Self { ttl, max_entries };
        config.validate()?;
        Ok(config)
    }

    fn validate(self) -> Result<(), OAuthError> {
        if self.ttl.is_zero() {
            return Err(OAuthError::JwksCache(
                "JWKS cache ttl must be greater than zero".to_owned(),
            ));
        }
        if self.max_entries == 0 {
            return Err(OAuthError::JwksCache(
                "JWKS cache max_entries must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Options for [`verify_jws_access_token`].
#[derive(Debug, Clone, Default)]
pub struct JwksVerifyOptions {
    pub verify_options: TokenValidationOptions,
    pub cache: OAuthJwksCacheConfig,
    pub http: Option<OAuthHttpClient>,
}

impl JwksVerifyOptions {
    pub fn new(verify_options: TokenValidationOptions) -> Self {
        Self {
            verify_options,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
struct CachedJwks {
    jwks: JwkSet,
    fetched_at: Instant,
}

pub async fn get_jwks(jwks_url: &str) -> Result<JwkSet, OAuthError> {
    get_jwks_with_http(jwks_url, None).await
}

pub async fn get_jwks_with_http(
    jwks_url: &str,
    http: Option<&OAuthHttpClient>,
) -> Result<JwkSet, OAuthError> {
    let client = match http {
        Some(client) => client,
        None => &default_http_client()?,
    };
    let bytes = client.get_bytes(jwks_url).await?;
    JwkSet::from_bytes(bytes).map_err(Into::into)
}

pub async fn verify_jws_access_token(
    token: &str,
    jwks_url: &str,
    options: JwksVerifyOptions,
) -> Result<TokenValidationResult, OAuthError> {
    let client = match options.http.as_ref() {
        Some(client) => client,
        None => &default_http_client()?,
    };
    let jwks = get_cached_jwks_for_token(token, jwks_url, client, options.cache).await?;
    let mut result = verify_jws_with_jwks(token, &jwks, &options.verify_options)?;
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

pub(crate) async fn get_cached_jwks_for_token(
    token: &str,
    jwks_url: &str,
    client: &OAuthHttpClient,
    cache_config: OAuthJwksCacheConfig,
) -> Result<JwkSet, OAuthError> {
    cache_config.validate()?;
    let kid = jwt::decode_header(token).ok().and_then(|header| {
        header
            .as_any()
            .downcast_ref::<josekit::jws::JwsHeader>()
            .and_then(|header| header.key_id().map(str::to_owned))
    });
    if let Some(cached) = cached_jwks(jwks_url, cache_config)? {
        if kid
            .as_deref()
            .is_some_and(|kid| cached.get(kid).into_iter().next().is_some())
        {
            return Ok(cached);
        }
    }
    let jwks = get_jwks_with_http(jwks_url, Some(client)).await?;
    cache_jwks(jwks_url, &jwks, cache_config)?;
    Ok(jwks)
}

fn cached_jwks(
    jwks_url: &str,
    cache_config: OAuthJwksCacheConfig,
) -> Result<Option<JwkSet>, OAuthError> {
    jwks_cache()
        .lock()
        .map_err(|_| OAuthError::InvalidConfiguration("jwks cache lock poisoned".to_owned()))
        .map(|cache| {
            cache.get(jwks_url).and_then(|cached| {
                (cached.fetched_at.elapsed() <= cache_config.ttl).then(|| cached.jwks.clone())
            })
        })
}

fn cache_jwks(
    jwks_url: &str,
    jwks: &JwkSet,
    cache_config: OAuthJwksCacheConfig,
) -> Result<(), OAuthError> {
    let mut cache = jwks_cache()
        .lock()
        .map_err(|_| OAuthError::InvalidConfiguration("jwks cache lock poisoned".to_owned()))?;
    cache.insert(
        jwks_url.to_owned(),
        CachedJwks {
            jwks: jwks.clone(),
            fetched_at: Instant::now(),
        },
    );
    while cache.len() > cache_config.max_entries {
        if let Some(oldest_key) = cache
            .iter()
            .min_by_key(|(_, cached)| cached.fetched_at)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest_key);
        } else {
            break;
        }
    }
    Ok(())
}

fn jwks_cache() -> &'static Mutex<HashMap<String, CachedJwks>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedJwks>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}
