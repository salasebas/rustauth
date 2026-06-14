use redis::aio::ConnectionManager;
use redis::Script;
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{
    validate_rate_limit_rule, RateLimitConsumeInput, RateLimitDecision, RateLimitFuture,
    RateLimitStore,
};

use crate::url::validate_rate_limit_key_prefix;

pub(crate) const RATE_LIMIT_SCRIPT: &str = r#"
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max = tonumber(ARGV[3])

local data = redis.call("HMGET", key, "count", "last_request")
local count = tonumber(data[1])
local last_request = tonumber(data[2])

if count == nil or last_request == nil or (now - last_request) > window then
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
            key_prefix: "rustauth:".to_owned(),
        }
    }
}

#[derive(Clone)]
pub struct RedisRateLimitStore {
    manager: ConnectionManager,
    options: RedisRateLimitOptions,
}

impl RedisRateLimitStore {
    pub async fn connect(redis_url: &str) -> Result<Self, RustAuthError> {
        Self::connect_with_options(redis_url, RedisRateLimitOptions::default()).await
    }

    pub async fn connect_with_options(
        redis_url: &str,
        options: RedisRateLimitOptions,
    ) -> Result<Self, RustAuthError> {
        let manager = crate::connect_manager(redis_url).await?;
        Ok(Self::new(manager, options))
    }

    pub fn new(manager: ConnectionManager, options: RedisRateLimitOptions) -> Self {
        Self { manager, options }
    }

    fn key(&self, key: &str) -> Result<String, RustAuthError> {
        validate_rate_limit_key_prefix(&self.options.key_prefix)?;
        Ok(format!("{}rate-limit:{key}", self.options.key_prefix))
    }
}

impl RateLimitStore for RedisRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            let window_ms = validate_rate_limit_rule(&input.rule)?;
            let redis_key = self.key(&input.key)?;
            let mut manager = self.manager.clone();
            let result: (i64, i64, i64) = Script::new(RATE_LIMIT_SCRIPT)
                .key(redis_key)
                .arg(input.now_ms)
                .arg(window_ms)
                .arg(input.rule.max as i64)
                .invoke_async(&mut manager)
                .await
                .map_err(|error| RustAuthError::Adapter(error.to_string()))?;
            let permitted = match result.0 {
                0 => false,
                1 => true,
                _ => {
                    return Err(RustAuthError::Adapter(
                        "invalid redis rate limit script result: `permitted` was not 0 or 1"
                            .to_owned(),
                    ));
                }
            };
            if result.1 < 0 {
                return Err(RustAuthError::Adapter(
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

fn ceil_millis_to_seconds(milliseconds: i64) -> u64 {
    if milliseconds <= 0 {
        return 0;
    }
    ((milliseconds as u64).saturating_add(999)) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_key_prefix_must_not_be_empty() {
        assert!(matches!(
            validate_rate_limit_key_prefix(""),
            Err(RustAuthError::InvalidConfig(message))
                if message == "rate limit key prefix must not be empty"
        ));
    }
}
