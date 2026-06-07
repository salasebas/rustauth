use openauth_core::options::SecondaryStorage;
use openauth_core::options::{RateLimitConsumeInput, RateLimitRule, RateLimitStore};
use openauth_core::storage_contract::assert_secondary_storage_contract;
use openauth_redis::{
    RedisOpenAuthStores, RedisRateLimitStore, RedisSecondaryStorage, RedisSecondaryStorageOptions,
};

const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379";
const DEFAULT_VALKEY_URL: &str = "valkey://127.0.0.1:6380";

#[derive(Debug, Clone, PartialEq, Eq)]
struct RedisTestTarget {
    name: &'static str,
    url: String,
}

fn redis_targets() -> Vec<RedisTestTarget> {
    redis_targets_from_env(
        std::env::var("OPENAUTH_REDIS_URL").ok(),
        std::env::var("OPENAUTH_VALKEY_URL").ok(),
    )
}

fn redis_targets_from_env(
    redis_url: Option<String>,
    valkey_url: Option<String>,
) -> Vec<RedisTestTarget> {
    let mut targets = Vec::new();
    if let Some(url) = redis_url {
        targets.push(RedisTestTarget { name: "redis", url });
    }
    if let Some(url) = valkey_url {
        targets.push(RedisTestTarget {
            name: "valkey",
            url,
        });
    }
    if targets.is_empty() {
        targets.push(RedisTestTarget {
            name: "redis",
            url: DEFAULT_REDIS_URL.to_owned(),
        });
        targets.push(RedisTestTarget {
            name: "valkey",
            url: DEFAULT_VALKEY_URL.to_owned(),
        });
    }
    targets
}

#[test]
fn redis_targets_default_to_docker_compose_redis_and_valkey_when_env_is_unset() {
    assert_eq!(
        redis_targets_from_env(None, None),
        vec![
            RedisTestTarget {
                name: "redis",
                url: DEFAULT_REDIS_URL.to_owned(),
            },
            RedisTestTarget {
                name: "valkey",
                url: DEFAULT_VALKEY_URL.to_owned(),
            },
        ]
    );
}

#[test]
fn redis_targets_allow_redis_env_override() {
    assert_eq!(
        redis_targets_from_env(Some("redis://example.test:6380".to_owned()), None),
        vec![RedisTestTarget {
            name: "redis",
            url: "redis://example.test:6380".to_owned(),
        }]
    );
}

#[test]
fn redis_targets_allow_valkey_env_override() {
    assert_eq!(
        redis_targets_from_env(None, Some("valkey://example.test:6379".to_owned())),
        vec![RedisTestTarget {
            name: "valkey",
            url: "valkey://example.test:6379".to_owned(),
        }]
    );
}

#[test]
fn redis_targets_run_both_envs_when_configured() {
    assert_eq!(
        redis_targets_from_env(
            Some("redis://redis.test:6379".to_owned()),
            Some("valkey://valkey.test:6379".to_owned()),
        ),
        vec![
            RedisTestTarget {
                name: "redis",
                url: "redis://redis.test:6379".to_owned(),
            },
            RedisTestTarget {
                name: "valkey",
                url: "valkey://valkey.test:6379".to_owned(),
            },
        ]
    );
}

#[tokio::test]
async fn redis_rate_limit_store_enforces_atomic_max_one() -> Result<(), Box<dyn std::error::Error>>
{
    for target in redis_targets() {
        let store = RedisRateLimitStore::connect(&target.url).await?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        let key = format!("test:{}:{}|/limited", target.name, now_ms);
        let rule = RateLimitRule { window: 60, max: 1 };

        let first = store
            .consume(RateLimitConsumeInput {
                key: key.clone(),
                rule: rule.clone(),
                now_ms,
            })
            .await?;
        let second = store
            .consume(RateLimitConsumeInput { key, rule, now_ms })
            .await?;

        assert!(
            first.permitted,
            "{} target should permit first call",
            target.name
        );
        assert!(
            !second.permitted,
            "{} target should reject second call",
            target.name
        );
        assert_eq!(second.remaining, 0);
    }
    Ok(())
}

#[tokio::test]
async fn redis_rate_limit_store_allows_exactly_one_concurrent_request(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in redis_targets() {
        let store = RedisRateLimitStore::connect(&target.url).await?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        let key = format!("test:{}:{now_ms}|/concurrent", target.name);
        let rule = RateLimitRule { window: 60, max: 1 };
        let first = RateLimitConsumeInput {
            key: key.clone(),
            rule: rule.clone(),
            now_ms,
        };
        let second = RateLimitConsumeInput { key, rule, now_ms };

        let (first, second) = tokio::join!(store.consume(first), store.consume(second));
        let permitted = [first?, second?]
            .into_iter()
            .filter(|decision| decision.permitted)
            .count();

        assert_eq!(
            permitted, 1,
            "{} target should permit exactly one concurrent call",
            target.name
        );
    }
    Ok(())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[tokio::test]
async fn redis_rate_limit_store_resets_after_window() -> Result<(), Box<dyn std::error::Error>> {
    for target in available_redis_targets().await? {
        let store = RedisRateLimitStore::connect(&target.url).await?;
        let now_ms = now_ms();
        let key = format!("test:{}:{now_ms}|/reset", target.name);
        let rule = RateLimitRule { window: 1, max: 1 };

        let first = store
            .consume(RateLimitConsumeInput {
                key: key.clone(),
                rule: rule.clone(),
                now_ms,
            })
            .await?;
        let second = store
            .consume(RateLimitConsumeInput {
                key,
                rule,
                now_ms: now_ms + 1_001,
            })
            .await?;

        assert!(first.permitted, "{} first consume", target.name);
        assert!(
            second.permitted,
            "{} should reset after window",
            target.name
        );
        assert_eq!(second.remaining, 0);
    }
    Ok(())
}

#[tokio::test]
async fn redis_rate_limit_store_does_not_reset_at_exact_window_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_redis_targets().await? {
        let store = RedisRateLimitStore::connect(&target.url).await?;
        let now_ms = now_ms();
        let key = format!("test:{}:{now_ms}|/exact-boundary", target.name);
        let rule = RateLimitRule { window: 1, max: 1 };

        let first = store
            .consume(RateLimitConsumeInput {
                key: key.clone(),
                rule: rule.clone(),
                now_ms,
            })
            .await?;
        let second = store
            .consume(RateLimitConsumeInput {
                key,
                rule,
                now_ms: now_ms + 1_000,
            })
            .await?;

        assert!(first.permitted, "{} first consume", target.name);
        assert!(
            !second.permitted,
            "{} should not reset until after the window (Better Auth uses >)",
            target.name
        );
    }
    Ok(())
}

async fn available_redis_targets() -> Result<Vec<RedisTestTarget>, Box<dyn std::error::Error>> {
    let mut available = Vec::new();
    for target in redis_targets() {
        if RedisRateLimitStore::connect(&target.url).await.is_ok() {
            available.push(target);
        }
    }
    Ok(available)
}

#[tokio::test]
async fn redis_secondary_storage_supports_get_set_delete_list_and_clear(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_redis_targets().await? {
        let prefix = format!("openauth:test:{}:storage:", target.name);
        let storage = RedisSecondaryStorage::connect_with_options(
            &target.url,
            RedisSecondaryStorageOptions {
                key_prefix: prefix.clone(),
                scan_count: 10,
            },
        )
        .await?;
        storage.clear().await?;

        let key = format!(
            "session:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
        );

        storage.set(&key, "value".to_owned(), Some(60)).await?;
        assert_eq!(storage.get(&key).await?.as_deref(), Some("value"));

        let mut keys = storage.list_keys().await?;
        keys.sort();
        assert_eq!(keys, vec![key.clone()]);

        storage
            .set("ttl-zero", "stale".to_owned(), Some(60))
            .await?;
        storage
            .set("ttl-zero", "persistent".to_owned(), Some(0))
            .await?;
        assert_eq!(storage.get("ttl-zero").await?, None);

        storage.delete(&key).await?;
        assert!(storage.get(&key).await?.is_none());

        storage.clear().await?;
        assert!(storage.list_keys().await?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn redis_secondary_storage_satisfies_contract() -> Result<(), Box<dyn std::error::Error>> {
    for target in available_redis_targets().await? {
        let url = target.url.clone();
        let name = target.name;
        assert_secondary_storage_contract(move |case| {
            let url = url.clone();
            async move {
                let storage = RedisSecondaryStorage::connect_with_options(
                    &url,
                    RedisSecondaryStorageOptions {
                        key_prefix: format!("openauth:test:{name}:{}:{case}:", now_ms()),
                        scan_count: 10,
                    },
                )
                .await?;
                storage.clear().await?;
                Ok(storage)
            }
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn redis_open_auth_stores_share_one_connection_manager(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_redis_targets().await? {
        let stores = RedisOpenAuthStores::connect(&target.url).await?;
        let key = format!(
            "bundle:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis()
        );
        stores
            .secondary_storage
            .set(&key, "from-bundle".to_owned(), None)
            .await?;
        assert_eq!(
            stores.secondary_storage.get(&key).await?.as_deref(),
            Some("from-bundle")
        );
        stores.secondary_storage.delete(&key).await?;
    }
    Ok(())
}
