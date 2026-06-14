use fred::clients::Client;
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{
    RateLimitConsumeInput, RateLimitRule, RateLimitStore, RustAuthOptions,
};
use rustauth_fred::{
    FredRateLimitOptions, FredRateLimitStore, FredSecondaryStorage, FredSecondaryStorageOptions,
    FredStores,
};
#[test]
fn fred_rustauth_stores_apply_to_options_wires_both_stores() {
    let stores = FredStores {
        rate_limit: FredRateLimitStore::new(Client::default(), FredRateLimitOptions::default()),
        secondary_storage: FredSecondaryStorage::new(
            Client::default(),
            FredSecondaryStorageOptions::default(),
        ),
    };
    let options = stores.apply_to_options(RustAuthOptions::default());

    assert!(options.secondary_storage.is_some());
    assert!(options.rate_limit.custom_store.is_some());
}

#[test]
fn fred_rate_limit_options_default_to_rustauth_prefix() {
    assert_eq!(FredRateLimitOptions::default().key_prefix, "rustauth:");
}

#[test]
fn fred_secondary_storage_options_default_to_rustauth_prefix() {
    let options = FredSecondaryStorageOptions::default();

    assert_eq!(options.key_prefix, "rustauth:");
    assert_eq!(options.scan_count, 100);
}

#[tokio::test]
async fn rejects_zero_rate_limit_window_before_calling_redis(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = FredRateLimitStore::new(Client::default(), FredRateLimitOptions::default());
    let error = store
        .consume(RateLimitConsumeInput {
            key: "127.0.0.1|/test".to_owned(),
            rule: RateLimitRule {
                window: time::Duration::seconds(0),
                max: 1,
            },
            now_ms: 1_700_000_000_000,
        })
        .await
        .err()
        .ok_or("expected invalid config error")?;

    assert!(matches!(
        error,
        RustAuthError::InvalidConfig(message)
            if message == "rate limit window must be greater than zero"
    ));
    Ok(())
}

#[tokio::test]
async fn rejects_empty_rate_limit_prefix_before_calling_redis(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = FredRateLimitStore::new(
        Client::default(),
        FredRateLimitOptions {
            key_prefix: String::new(),
        },
    );
    let error = store
        .consume(RateLimitConsumeInput {
            key: "127.0.0.1|/test".to_owned(),
            rule: RateLimitRule {
                window: time::Duration::seconds(1),
                max: 1,
            },
            now_ms: 1_700_000_000_000,
        })
        .await
        .err()
        .ok_or("expected invalid config error")?;

    assert!(matches!(
        error,
        RustAuthError::InvalidConfig(message)
            if message == "rate limit key prefix must not be empty"
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
            rule: RateLimitRule {
                window: time::Duration::seconds(1),
                max: 0,
            },
            now_ms: 1_700_000_000_000,
        })
        .await
        .err()
        .ok_or("expected invalid config error")?;

    assert!(matches!(
        error,
        RustAuthError::InvalidConfig(message) if message == "rate limit max must be greater than zero"
    ));
    Ok(())
}
