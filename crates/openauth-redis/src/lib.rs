//! Redis-backed integrations for OpenAuth.
//!
//! The rate limit store uses `redis-rs` with the async
//! `redis::aio::ConnectionManager`, RESP-compatible Redis or Valkey servers,
//! Lua scripting for atomic consume decisions, and core commands that are
//! shared by Redis and Valkey.

use std::borrow::Cow;

use openauth_core::error::OpenAuthError;
use openauth_core::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitStore, SecondaryStorage,
    SecondaryStorageFuture,
};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};

const RATE_LIMIT_SCRIPT: &str = r#"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max = tonumber(ARGV[3])

local data = redis.call("HMGET", key, "count", "last_request")
local count = tonumber(data[1])
local last_request = tonumber(data[2])

if count == nil or last_request == nil or (now - last_request) >= window then
  redis.call("HSET", key, "count", 1, "last_request", now)
  redis.call("PEXPIRE", key, window)
  return {1, 1, now}
end

if count >= max then
  redis.call("PEXPIRE", key, window)
  return {0, count, last_request}
end

count = count + 1
redis.call("HSET", key, "count", count, "last_request", now)
redis.call("PEXPIRE", key, window)
return {1, count, now}
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisRateLimitOptions {
    pub key_prefix: String,
}

impl Default for RedisRateLimitOptions {
    fn default() -> Self {
        Self {
            key_prefix: "openauth:".to_owned(),
        }
    }
}

#[derive(Clone)]
pub struct RedisRateLimitStore {
    manager: ConnectionManager,
    options: RedisRateLimitOptions,
}

impl RedisRateLimitStore {
    pub async fn connect(redis_url: &str) -> Result<Self, OpenAuthError> {
        let redis_url = normalize_redis_url(redis_url);
        let client = redis::Client::open(redis_url.as_ref())
            .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
        let manager = ConnectionManager::new(client)
            .await
            .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
        Ok(Self::new(manager, RedisRateLimitOptions::default()))
    }

    pub fn new(manager: ConnectionManager, options: RedisRateLimitOptions) -> Self {
        Self { manager, options }
    }

    fn key(&self, key: &str) -> String {
        format!("{}rate-limit:{key}", self.options.key_prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisSecondaryStorageOptions {
    pub key_prefix: String,
}

impl Default for RedisSecondaryStorageOptions {
    fn default() -> Self {
        Self {
            key_prefix: "openauth:".to_owned(),
        }
    }
}

#[derive(Clone)]
pub struct RedisSecondaryStorage {
    manager: ConnectionManager,
    options: RedisSecondaryStorageOptions,
}

impl RedisSecondaryStorage {
    pub async fn connect(redis_url: &str) -> Result<Self, OpenAuthError> {
        let redis_url = normalize_redis_url(redis_url);
        let client = redis::Client::open(redis_url.as_ref())
            .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
        let manager = ConnectionManager::new(client)
            .await
            .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
        Ok(Self::new(manager, RedisSecondaryStorageOptions::default()))
    }

    pub fn new(manager: ConnectionManager, options: RedisSecondaryStorageOptions) -> Self {
        Self { manager, options }
    }

    fn key(&self, key: &str) -> String {
        format!("{}secondary:{key}", self.options.key_prefix)
    }
}

fn normalize_redis_url(redis_url: &str) -> Cow<'_, str> {
    if let Some(rest) = redis_url.strip_prefix("valkey://") {
        return Cow::Owned(format!("redis://{rest}"));
    }
    if let Some(rest) = redis_url.strip_prefix("valkeys://") {
        return Cow::Owned(format!("rediss://{rest}"));
    }
    Cow::Borrowed(redis_url)
}

impl SecondaryStorage for RedisSecondaryStorage {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>> {
        Box::pin(async move {
            let mut manager = self.manager.clone();
            manager
                .get(self.key(key))
                .await
                .map_err(|error| OpenAuthError::Adapter(error.to_string()))
        })
    }

    fn set<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            let redis_key = self.key(key);
            let mut manager = self.manager.clone();
            match ttl_seconds {
                Some(0) => {
                    let _: usize = manager
                        .del(redis_key)
                        .await
                        .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
                }
                Some(ttl_seconds) => {
                    let _: () = manager
                        .set_ex(redis_key, value, ttl_seconds)
                        .await
                        .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
                }
                None => {
                    let _: () = manager
                        .set(redis_key, value)
                        .await
                        .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
                }
            }
            Ok(())
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, ()> {
        Box::pin(async move {
            let mut manager = self.manager.clone();
            let _: usize = manager
                .del(self.key(key))
                .await
                .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
            Ok(())
        })
    }
}

impl RateLimitStore for RedisRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            let window_ms = validate_rule(&input)?;
            let redis_key = self.key(&input.key);
            let mut manager = self.manager.clone();
            let result: (i64, i64, i64) = Script::new(RATE_LIMIT_SCRIPT)
                .key(redis_key)
                .arg(input.now_ms)
                .arg(window_ms)
                .arg(input.rule.max as i64)
                .invoke_async(&mut manager)
                .await
                .map_err(|error| OpenAuthError::Adapter(error.to_string()))?;
            let permitted = match result.0 {
                0 => false,
                1 => true,
                _ => {
                    return Err(OpenAuthError::Adapter(
                        "invalid redis rate limit script result: `permitted` was not 0 or 1"
                            .to_owned(),
                    ));
                }
            };
            if result.1 < 0 {
                return Err(OpenAuthError::Adapter(
                    "invalid redis rate limit script result: `count` was negative".to_owned(),
                ));
            }
            let count = result.1 as u64;
            let last_request = result.2;
            let retry_ms = last_request
                .saturating_add(window_ms)
                .saturating_sub(input.now_ms)
                .max(0);
            Ok(RateLimitDecision {
                permitted,
                retry_after: if permitted {
                    0
                } else {
                    ceil_millis_to_seconds(retry_ms)
                },
                limit: input.rule.max,
                remaining: input.rule.max.saturating_sub(count),
                reset_after: ceil_millis_to_seconds(retry_ms),
            })
        })
    }
}

fn validate_rule(input: &RateLimitConsumeInput) -> Result<i64, OpenAuthError> {
    if input.rule.window == 0 {
        return Err(OpenAuthError::InvalidConfig(
            "rate limit window must be greater than zero".to_owned(),
        ));
    }
    if input.rule.max == 0 {
        return Err(OpenAuthError::InvalidConfig(
            "rate limit max must be greater than zero".to_owned(),
        ));
    }
    let window_ms = input.rule.window.checked_mul(1000).ok_or_else(|| {
        OpenAuthError::InvalidConfig("rate limit window milliseconds overflowed".to_owned())
    })?;
    let window_ms = i64::try_from(window_ms).map_err(|_| {
        OpenAuthError::InvalidConfig("rate limit window milliseconds must fit in i64".to_owned())
    })?;
    i64::try_from(input.rule.max)
        .map_err(|_| OpenAuthError::InvalidConfig("rate limit max must fit in i64".to_owned()))?;
    Ok(window_ms)
}

fn ceil_millis_to_seconds(milliseconds: i64) -> u64 {
    if milliseconds <= 0 {
        return 0;
    }
    ((milliseconds as u64).saturating_add(999)) / 1000
}

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_valkey_urls_to_redis_urls() {
        assert_eq!(
            normalize_redis_url("valkey://localhost:6379").as_ref(),
            "redis://localhost:6379"
        );
        assert_eq!(
            normalize_redis_url("valkeys://localhost:6380").as_ref(),
            "rediss://localhost:6380"
        );
    }

    #[test]
    fn leaves_non_valkey_urls_unchanged() {
        assert_eq!(
            normalize_redis_url("redis://localhost:6379").as_ref(),
            "redis://localhost:6379"
        );
        assert_eq!(
            normalize_redis_url("rediss://localhost:6380").as_ref(),
            "rediss://localhost:6380"
        );
        assert_eq!(
            normalize_redis_url("unix:///tmp/redis.sock").as_ref(),
            "unix:///tmp/redis.sock"
        );
    }

    #[test]
    fn rate_limit_script_uses_current_hash_set_command() {
        assert!(RATE_LIMIT_SCRIPT.contains("HSET"));
        assert!(!RATE_LIMIT_SCRIPT.contains("HMSET"));
    }

    #[test]
    fn secondary_storage_uses_separate_key_namespace() {
        let options = RedisSecondaryStorageOptions {
            key_prefix: "test:".to_owned(),
        };
        let key = format!("{}secondary:{}", options.key_prefix, "session:token");

        assert_eq!(key, "test:secondary:session:token");
    }

    #[cfg(any(feature = "rustls", feature = "native-tls"))]
    #[test]
    fn tls_urls_open_as_tls_connections() -> Result<(), redis::RedisError> {
        for url in ["rediss://localhost:6379", "valkeys://localhost:6380"] {
            let client = redis::Client::open(normalize_redis_url(url).as_ref())?;
            assert!(
                matches!(
                    client.get_connection_info().addr,
                    redis::ConnectionAddr::TcpTls { .. }
                ),
                "{url} should open as a TLS connection"
            );
        }
        Ok(())
    }
}
