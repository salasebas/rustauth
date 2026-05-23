use openauth_core::options::SecondaryStorage;
use openauth_core::options::{RateLimitConsumeInput, RateLimitRule, RateLimitStore};
use openauth_redis::{RedisRateLimitStore, RedisSecondaryStorage};

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

#[tokio::test]
async fn redis_secondary_storage_supports_get_set_delete_and_ttl_zero(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in redis_targets() {
        let storage = RedisSecondaryStorage::connect(&target.url).await?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis();
        let key = format!("test:{}:{now_ms}:secondary", target.name);

        storage.set(&key, "value".to_owned(), Some(60)).await?;
        let found = storage.get(&key).await?;
        storage.delete(&key).await?;
        let deleted = storage.get(&key).await?;

        assert_eq!(found.as_deref(), Some("value"));
        assert!(deleted.is_none());

        storage.set(&key, "expired".to_owned(), Some(0)).await?;
        let expired = storage.get(&key).await?;
        assert!(expired.is_none());
    }
    Ok(())
}
