//! Redis-backed integrations for RustAuth.
//!
//! The rate limit store uses `redis-rs` with the async
//! `redis::aio::ConnectionManager`, RESP-compatible Redis or Valkey servers,
//! Lua scripting for atomic consume decisions, and core commands that are
//! shared by Redis and Valkey.

mod bundle;
mod rate_limit;
mod secondary;
mod url;

pub use bundle::{RedisOptions, RedisRustAuthOptions, RedisRustAuthStores, RedisStores};
pub use rate_limit::{RedisRateLimitOptions, RedisRateLimitStore};
pub use secondary::{RedisSecondaryStorage, RedisSecondaryStorageOptions};

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) async fn connect_manager(
    redis_url: &str,
) -> Result<redis::aio::ConnectionManager, rustauth_core::error::RustAuthError> {
    let redis_url = url::normalize_redis_url(redis_url);
    let client = redis::Client::open(redis_url.as_ref())
        .map_err(|error| rustauth_core::error::RustAuthError::Adapter(error.to_string()))?;
    redis::aio::ConnectionManager::new(client)
        .await
        .map_err(|error| rustauth_core::error::RustAuthError::Adapter(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_valkey_urls_to_redis_urls() {
        assert_eq!(
            url::normalize_redis_url("valkey://localhost:6379").as_ref(),
            "redis://localhost:6379"
        );
        assert_eq!(
            url::normalize_redis_url("valkeys://localhost:6380").as_ref(),
            "rediss://localhost:6380"
        );
    }

    #[test]
    fn leaves_non_valkey_urls_unchanged() {
        assert_eq!(
            url::normalize_redis_url("redis://localhost:6379").as_ref(),
            "redis://localhost:6379"
        );
        assert_eq!(
            url::normalize_redis_url("rediss://localhost:6380").as_ref(),
            "rediss://localhost:6380"
        );
        assert_eq!(
            url::normalize_redis_url("unix:///tmp/redis.sock").as_ref(),
            "unix:///tmp/redis.sock"
        );
    }

    #[test]
    fn rate_limit_script_uses_current_hash_set_command() {
        use crate::rate_limit::RATE_LIMIT_SCRIPT;

        assert!(RATE_LIMIT_SCRIPT.contains("HSET"));
        assert!(!RATE_LIMIT_SCRIPT.contains("HMSET"));
    }

    #[test]
    fn rate_limit_script_resets_only_after_window_elapses() {
        use crate::rate_limit::RATE_LIMIT_SCRIPT;

        assert!(RATE_LIMIT_SCRIPT.contains("(now - last_request) > window"));
        assert!(!RATE_LIMIT_SCRIPT.contains("(now - last_request) >= window"));
    }

    #[test]
    fn scan_pattern_escapes_redis_glob_metacharacters() {
        use crate::url::secondary_storage_scan_pattern;

        assert_eq!(
            secondary_storage_scan_pattern(r"tenant:*?[]\:"),
            r"tenant:\*\?\[\]\\:*"
        );
    }

    #[test]
    fn secondary_storage_uses_separate_key_namespace() {
        let options = RedisSecondaryStorageOptions {
            key_prefix: "test:".to_owned(),
            scan_count: 100,
        };
        let key = format!("{}secondary:{}", options.key_prefix, "session:token");

        assert_eq!(key, "test:secondary:session:token");
    }

    #[cfg(any(feature = "rustls", feature = "native-tls"))]
    #[test]
    fn tls_urls_open_as_tls_connections() -> Result<(), redis::RedisError> {
        for url in ["rediss://localhost:6379", "valkeys://localhost:6380"] {
            let client = redis::Client::open(url::normalize_redis_url(url).as_ref())?;
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
