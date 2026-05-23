use fred::clients::Client;
use fred::types::Value;
use openauth_core::error::OpenAuthError;
use openauth_core::options::{RateLimitConsumeInput, RateLimitRule, RateLimitStore};
use openauth_fred::{
    normalize_fred_url, parse_rate_limit_script_result, FredRateLimitOptions, FredRateLimitStore,
    FredSecondaryStorageOptions, RateLimitScriptResult,
};

#[test]
fn fred_rate_limit_options_default_to_openauth_prefix() {
    assert_eq!(FredRateLimitOptions::default().key_prefix, "openauth:");
}

#[test]
fn fred_secondary_storage_options_default_to_openauth_prefix() {
    let options = FredSecondaryStorageOptions::default();

    assert_eq!(options.key_prefix, "openauth:");
    assert_eq!(options.scan_count, 100);
}

#[test]
fn fred_urls_normalize_valkey_aliases() {
    assert_eq!(
        normalize_fred_url("valkey://localhost:6379").as_ref(),
        "redis://localhost:6379"
    );
    assert_eq!(
        normalize_fred_url("valkeys://localhost:6380").as_ref(),
        "rediss://localhost:6380"
    );
}

#[test]
fn fred_urls_leave_redis_and_unix_urls_unchanged() {
    assert_eq!(
        normalize_fred_url("redis://localhost:6379").as_ref(),
        "redis://localhost:6379"
    );
    assert_eq!(
        normalize_fred_url("rediss://localhost:6380").as_ref(),
        "rediss://localhost:6380"
    );
    assert_eq!(
        normalize_fred_url("unix:///tmp/redis.sock").as_ref(),
        "unix:///tmp/redis.sock"
    );
}

#[test]
fn parses_valid_lua_result() -> Result<(), Box<dyn std::error::Error>> {
    let result = parse_rate_limit_script_result(Value::Array(vec![
        Value::Integer(1),
        Value::Integer(3),
        Value::Integer(1_000),
    ]))?;

    assert_eq!(
        result,
        RateLimitScriptResult {
            permitted: true,
            count: 3,
            last_request: 1_000,
        }
    );
    Ok(())
}

#[test]
fn rejects_malformed_lua_result() {
    let result = parse_rate_limit_script_result(Value::Array(vec![Value::Integer(1)]));

    assert!(result.is_err());
}

#[test]
fn rejects_invalid_permitted_flag_from_lua_result() {
    let result = parse_rate_limit_script_result(Value::Array(vec![
        Value::Integer(2),
        Value::Integer(3),
        Value::Integer(1_000),
    ]));

    assert!(result.is_err());
}

#[test]
fn rejects_negative_count_from_lua_result() {
    let result = parse_rate_limit_script_result(Value::Array(vec![
        Value::Integer(1),
        Value::Integer(-1),
        Value::Integer(1_000),
    ]));

    assert!(result.is_err());
}

#[tokio::test]
async fn rejects_zero_rate_limit_window_before_calling_redis(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = FredRateLimitStore::new(Client::default(), FredRateLimitOptions::default());
    let error = store
        .consume(RateLimitConsumeInput {
            key: "127.0.0.1|/test".to_owned(),
            rule: RateLimitRule { window: 0, max: 1 },
            now_ms: 1_700_000_000_000,
        })
        .await
        .err()
        .ok_or("expected invalid config error")?;

    assert!(matches!(
        error,
        OpenAuthError::InvalidConfig(message)
            if message == "rate limit window must be greater than zero"
    ));
    Ok(())
}

#[tokio::test]
async fn rejects_zero_rate_limit_max_before_calling_redis() -> Result<(), Box<dyn std::error::Error>>
{
    let store = FredRateLimitStore::new(Client::default(), FredRateLimitOptions::default());
    let error = store
        .consume(RateLimitConsumeInput {
            key: "127.0.0.1|/test".to_owned(),
            rule: RateLimitRule { window: 1, max: 0 },
            now_ms: 1_700_000_000_000,
        })
        .await
        .err()
        .ok_or("expected invalid config error")?;

    assert!(matches!(
        error,
        OpenAuthError::InvalidConfig(message) if message == "rate limit max must be greater than zero"
    ));
    Ok(())
}
