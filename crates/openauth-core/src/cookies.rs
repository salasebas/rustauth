//! Cookie naming, parsing, and chunking helpers.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::crypto::jwe::{symmetric_decode_jwt, symmetric_encode_jwt, JweSecretSource};
use crate::crypto::jwt::{sign_jwt, verify_jwt};
use crate::env::is_production;
use crate::error::OpenAuthError;
use crate::options::{CookieAttributesOverride, OpenAuthOptions};

pub use crate::options::CookieCacheStrategy;
pub use crate::options::CookieConfig;

pub const SECURE_COOKIE_PREFIX: &str = "__Secure-";
pub const HOST_COOKIE_PREFIX: &str = "__Host-";
const ALLOWED_COOKIE_SIZE: usize = 4096;
const ESTIMATED_EMPTY_COOKIE_SIZE: usize = 200;
const CHUNK_SIZE: usize = ALLOWED_COOKIE_SIZE - ESTIMATED_EMPTY_COOKIE_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub attributes: CookieOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCookie {
    pub name: String,
    pub attributes: CookieOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCookies {
    pub session_token: AuthCookie,
    pub session_data: AuthCookie,
    pub account_data: AuthCookie,
    pub dont_remember_token: AuthCookie,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CookieOptions {
    pub max_age: Option<u64>,
    pub expires: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub partitioned: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedCookie {
    pub value: String,
    pub max_age: Option<u64>,
    pub expires: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
    pub same_site: Option<String>,
    pub partitioned: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionCookieOptions {
    pub dont_remember: bool,
    pub overrides: CookieOptions,
}

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

pub fn strip_secure_cookie_prefix(cookie_name: &str) -> &str {
    cookie_name
        .strip_prefix(SECURE_COOKIE_PREFIX)
        .or_else(|| cookie_name.strip_prefix(HOST_COOKIE_PREFIX))
        .unwrap_or(cookie_name)
}

pub fn get_cookies(options: &OpenAuthOptions) -> Result<AuthCookies, OpenAuthError> {
    let secure = resolve_secure(options);
    let secure_prefix = if secure { SECURE_COOKIE_PREFIX } else { "" };
    let prefix = options
        .advanced
        .cookie_prefix
        .as_deref()
        .unwrap_or("better-auth");
    let domain = resolve_domain(options)?;
    let session_max_age = options.session.expires_in.unwrap_or(60 * 60 * 24 * 7);
    let cache_max_age = options.session.cookie_cache.max_age.unwrap_or(60 * 5);

    let create = |name: &str, max_age: Option<u64>| AuthCookie {
        name: format!("{secure_prefix}{prefix}.{name}"),
        attributes: merge_cookie_attributes(
            CookieOptions {
                max_age,
                expires: None,
                domain: domain.clone(),
                path: Some("/".to_owned()),
                secure: Some(secure),
                http_only: Some(true),
                same_site: Some("lax".to_owned()),
                partitioned: None,
            },
            &options.advanced.default_cookie_attributes,
        ),
    };

    Ok(AuthCookies {
        session_token: create("session_token", Some(session_max_age)),
        session_data: create("session_data", Some(cache_max_age)),
        account_data: create("account_data", Some(cache_max_age)),
        dont_remember_token: create("dont_remember", None),
    })
}

fn resolve_secure(options: &OpenAuthOptions) -> bool {
    if let Some(secure) = options.advanced.use_secure_cookies {
        return secure;
    }
    if let Some(base_url) = &options.base_url {
        return base_url.starts_with("https://");
    }
    options.production || is_production()
}

fn resolve_domain(options: &OpenAuthOptions) -> Result<Option<String>, OpenAuthError> {
    let Some(config) = &options.advanced.cross_subdomain_cookies else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }
    if let Some(domain) = &config.domain {
        return Ok(Some(domain.clone()));
    }
    let Some(base_url) = &options.base_url else {
        return Err(OpenAuthError::Cookie(
            "base_url is required when cross-subdomain cookies are enabled".to_owned(),
        ));
    };
    host_from_url(base_url)
        .map(Some)
        .ok_or_else(|| OpenAuthError::Cookie("could not resolve cookie domain".to_owned()))
}

fn host_from_url(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let host = rest.split('/').next().unwrap_or(rest);
    let host = host.split(':').next().unwrap_or(host);
    (!host.is_empty()).then(|| host.to_owned())
}

fn merge_cookie_attributes(
    mut base: CookieOptions,
    override_attrs: &CookieAttributesOverride,
) -> CookieOptions {
    if override_attrs.domain.is_some() {
        base.domain.clone_from(&override_attrs.domain);
    }
    if override_attrs.path.is_some() {
        base.path.clone_from(&override_attrs.path);
    }
    if override_attrs.secure.is_some() {
        base.secure = override_attrs.secure;
    }
    if override_attrs.http_only.is_some() {
        base.http_only = override_attrs.http_only;
    }
    if override_attrs.same_site.is_some() {
        base.same_site.clone_from(&override_attrs.same_site);
    }
    if override_attrs.max_age.is_some() {
        base.max_age = override_attrs.max_age;
    }
    if override_attrs.partitioned.is_some() {
        base.partitioned = override_attrs.partitioned;
    }
    base
}

fn merge_options(mut base: CookieOptions, overrides: CookieOptions) -> CookieOptions {
    if overrides.max_age.is_some() {
        base.max_age = overrides.max_age;
    }
    if overrides.expires.is_some() {
        base.expires = overrides.expires;
    }
    if overrides.domain.is_some() {
        base.domain = overrides.domain;
    }
    if overrides.path.is_some() {
        base.path = overrides.path;
    }
    if overrides.secure.is_some() {
        base.secure = overrides.secure;
    }
    if overrides.http_only.is_some() {
        base.http_only = overrides.http_only;
    }
    if overrides.same_site.is_some() {
        base.same_site = overrides.same_site;
    }
    if overrides.partitioned.is_some() {
        base.partitioned = overrides.partitioned;
    }
    base
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

fn hmac_base64(value: &str, secret: &str) -> Result<String, OpenAuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| OpenAuthError::Cookie(error.to_string()))?;
    mac.update(value.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

fn hmac_base64url(value: &str, secret: &str) -> Result<String, OpenAuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| OpenAuthError::Cookie(error.to_string()))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub fn parse_cookies(cookie_header: &str) -> BTreeMap<String, String> {
    let mut cookies = BTreeMap::new();
    for pair in cookie_header.split("; ") {
        if let Some((name, value)) = pair.split_once('=') {
            cookies.insert(name.to_owned(), value.to_owned());
        }
    }
    cookies
}

/// Read the session token cookie from a request `Cookie` header.
pub fn get_session_cookie(
    cookie_header: &str,
    cookie_prefix: Option<&str>,
    cookie_name: Option<&str>,
) -> Option<String> {
    let prefix = cookie_prefix.unwrap_or("better-auth");
    let name = cookie_name.unwrap_or("session_token");
    let full_name = format!("{prefix}.{name}");
    let legacy_name = format!("{prefix}-{name}");
    let secure_name = format!("{SECURE_COOKIE_PREFIX}{full_name}");
    let secure_legacy_name = format!("{SECURE_COOKIE_PREFIX}{legacy_name}");
    let cookies = parse_cookies(cookie_header);

    cookies
        .get(&full_name)
        .or_else(|| cookies.get(&secure_name))
        .or_else(|| cookies.get(&legacy_name))
        .or_else(|| cookies.get(&secure_legacy_name))
        .cloned()
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

pub fn set_session_cookie(
    auth_cookies: &AuthCookies,
    secret: &str,
    token: &str,
    options: SessionCookieOptions,
) -> Result<Vec<Cookie>, OpenAuthError> {
    let mut attributes = merge_options(
        auth_cookies.session_token.attributes.clone(),
        options.overrides,
    );
    if options.dont_remember {
        attributes.max_age = None;
    }

    let mut cookies = vec![Cookie {
        name: auth_cookies.session_token.name.clone(),
        value: sign_cookie_value(token, secret)?,
        attributes,
    }];

    if options.dont_remember {
        cookies.push(Cookie {
            name: auth_cookies.dont_remember_token.name.clone(),
            value: sign_cookie_value("true", secret)?,
            attributes: auth_cookies.dont_remember_token.attributes.clone(),
        });
    }

    Ok(cookies)
}

pub fn expire_cookie(cookie: &AuthCookie) -> Cookie {
    let mut attributes = cookie.attributes.clone();
    attributes.max_age = Some(0);
    Cookie {
        name: cookie.name.clone(),
        value: String::new(),
        attributes,
    }
}

pub fn delete_session_cookie(
    auth_cookies: &AuthCookies,
    cookie_header: &str,
    skip_dont_remember: bool,
) -> Vec<Cookie> {
    let mut expired = vec![
        expire_cookie(&auth_cookies.session_token),
        expire_cookie(&auth_cookies.session_data),
        expire_cookie(&auth_cookies.account_data),
    ];
    expired.extend(clean_chunked_cookie(
        &auth_cookies.session_data,
        cookie_header,
    ));
    expired.extend(clean_chunked_cookie(
        &auth_cookies.account_data,
        cookie_header,
    ));
    if !skip_dont_remember {
        expired.push(expire_cookie(&auth_cookies.dont_remember_token));
    }
    expired
}

fn clean_chunked_cookie(cookie: &AuthCookie, cookie_header: &str) -> Vec<Cookie> {
    ChunkedCookieStore::new(
        cookie.name.clone(),
        cookie.attributes.clone(),
        cookie_header,
    )
    .clean()
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
        CookieCacheStrategy::Jwe => symmetric_encode_jwt(payload, secret, max_age)?,
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
        CookieCacheStrategy::Jwe => symmetric_decode_jwt(&data, secret)?,
    }) else {
        return Ok(None);
    };

    if expected_version.is_some_and(|version| payload.version != version) {
        return Ok(None);
    }

    Ok(Some(payload))
}

pub fn parse_set_cookie_header(set_cookie: &str) -> BTreeMap<String, ParsedCookie> {
    let mut cookies = BTreeMap::new();
    for cookie in split_set_cookie_header(set_cookie) {
        let parts = cookie.split(';').map(str::trim).collect::<Vec<_>>();
        let Some(name_value) = parts.first() else {
            continue;
        };
        let Some((name, value)) = name_value.split_once('=') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }

        let mut parsed = ParsedCookie {
            value: percent_decode(value),
            ..ParsedCookie::default()
        };
        for attribute in parts.iter().skip(1) {
            let (attribute_name, attribute_value) = attribute
                .split_once('=')
                .map_or((*attribute, ""), |(name, value)| (name, value));
            match attribute_name.trim().to_ascii_lowercase().as_str() {
                "max-age" => parsed.max_age = attribute_value.trim().parse::<u64>().ok(),
                "expires" => parsed.expires = Some(attribute_value.trim().to_owned()),
                "domain" => parsed.domain = Some(attribute_value.trim().to_owned()),
                "path" => parsed.path = Some(attribute_value.trim().to_owned()),
                "secure" => parsed.secure = Some(true),
                "httponly" => parsed.http_only = Some(true),
                "samesite" => parsed.same_site = Some(attribute_value.trim().to_ascii_lowercase()),
                "partitioned" => parsed.partitioned = Some(true),
                _ => {}
            }
        }
        cookies.insert(name.to_owned(), parsed);
    }
    cookies
}

fn split_set_cookie_header(set_cookie: &str) -> Vec<String> {
    if set_cookie.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut start = 0;
    let mut index = 0;
    let bytes = set_cookie.as_bytes();
    while index < bytes.len() {
        if bytes[index] == b',' {
            let mut cursor = index + 1;
            while cursor < bytes.len() && bytes[cursor] == b' ' {
                cursor += 1;
            }
            while cursor < bytes.len()
                && bytes[cursor] != b'='
                && bytes[cursor] != b';'
                && bytes[cursor] != b','
            {
                cursor += 1;
            }
            if cursor < bytes.len() && bytes[cursor] == b'=' {
                let part = set_cookie[start..index].trim();
                if !part.is_empty() {
                    result.push(part.to_owned());
                }
                start = index + 1;
                while start < bytes.len() && bytes[start] == b' ' {
                    start += 1;
                }
                index = start;
                continue;
            }
        }
        index += 1;
    }
    let last = set_cookie[start..].trim();
    if !last.is_empty() {
        result.push(last.to_owned());
    }
    result
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (from_hex(bytes[index + 1]), from_hex(bytes[index + 2])) {
                output.push((hi << 4) | lo);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(output).unwrap_or_else(|_| value.to_owned())
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn to_cookie_options(attributes: &ParsedCookie) -> CookieOptions {
    CookieOptions {
        max_age: attributes.max_age,
        expires: attributes.expires.clone(),
        domain: attributes.domain.clone(),
        path: attributes.path.clone(),
        secure: attributes.secure,
        http_only: attributes.http_only,
        same_site: attributes.same_site.clone(),
        partitioned: attributes.partitioned,
    }
}

#[derive(Debug, Clone)]
pub struct ChunkedCookieStore {
    cookie_name: String,
    cookie_options: CookieOptions,
    chunks: BTreeMap<String, String>,
    direct_value: Option<String>,
}

impl ChunkedCookieStore {
    pub fn new(
        cookie_name: impl Into<String>,
        cookie_options: CookieOptions,
        header: &str,
    ) -> Self {
        let cookie_name = cookie_name.into();
        let parsed = parse_cookies(header);
        let direct_value = parsed.get(&cookie_name).cloned();
        let prefix = format!("{cookie_name}.");
        let chunks = parsed
            .into_iter()
            .filter(|(name, _)| name.starts_with(&prefix))
            .collect();
        Self {
            cookie_name,
            cookie_options,
            chunks,
            direct_value,
        }
    }

    pub fn value(&self) -> Option<String> {
        if let Some(value) = &self.direct_value {
            return Some(value.clone());
        }
        if self.chunks.is_empty() {
            return None;
        }
        let mut chunks = self
            .chunks
            .iter()
            .filter_map(|(name, value)| chunk_index(name).map(|index| (index, value)))
            .collect::<Vec<_>>();
        chunks.sort_by_key(|(index, _)| *index);
        Some(
            chunks
                .into_iter()
                .map(|(_, value)| value.as_str())
                .collect(),
        )
    }

    pub fn chunk(&self, value: &str) -> Vec<Cookie> {
        if value.len() <= CHUNK_SIZE {
            return vec![Cookie {
                name: self.cookie_name.clone(),
                value: value.to_owned(),
                attributes: self.cookie_options.clone(),
            }];
        }
        value
            .as_bytes()
            .chunks(CHUNK_SIZE)
            .enumerate()
            .map(|(index, chunk)| Cookie {
                name: format!("{}.{}", self.cookie_name, index),
                value: String::from_utf8_lossy(chunk).into_owned(),
                attributes: self.cookie_options.clone(),
            })
            .collect()
    }

    pub fn clean(&self) -> Vec<Cookie> {
        self.chunks
            .keys()
            .map(|name| {
                let mut attributes = self.cookie_options.clone();
                attributes.max_age = Some(0);
                Cookie {
                    name: name.clone(),
                    value: String::new(),
                    attributes,
                }
            })
            .collect()
    }
}

fn chunk_index(cookie_name: &str) -> Option<usize> {
    cookie_name.rsplit_once('.')?.1.parse().ok()
}
