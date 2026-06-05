use std::sync::Arc;
use std::sync::Mutex;

use http::{header, Method, Request, StatusCode};
use openauth::{
    AdvancedOptions, MemoryAdapter, OpenAuth, OpenAuthError, OpenAuthOptions, PasswordOptions,
    SessionOptions,
};
use openauth_core::options::{
    PasswordResetEmail, RateLimitConsumeInput, RateLimitRule, RateLimitStore, SecondaryStorage,
};
use openauth_fred::{
    FredOpenAuthStores, FredRateLimitOptions, FredRateLimitStore, FredSecondaryStorage,
    FredSecondaryStorageOptions,
};
use openauth_redis::RedisSecondaryStorage;

const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379";
const DEFAULT_VALKEY_URL: &str = "valkey://127.0.0.1:6380";

#[derive(Debug, Clone, PartialEq, Eq)]
struct FredTestTarget {
    name: &'static str,
    url: String,
    explicit: bool,
}

fn configured_fred_targets() -> Vec<FredTestTarget> {
    fred_targets_from_env(
        std::env::var("OPENAUTH_FRED_REDIS_URL").ok(),
        std::env::var("OPENAUTH_FRED_VALKEY_URL").ok(),
    )
}

fn fred_targets_from_env(
    redis_url: Option<String>,
    valkey_url: Option<String>,
) -> Vec<FredTestTarget> {
    let mut targets = Vec::new();
    if let Some(url) = redis_url {
        targets.push(FredTestTarget {
            name: "redis",
            url,
            explicit: true,
        });
    }
    if let Some(url) = valkey_url {
        targets.push(FredTestTarget {
            name: "valkey",
            url,
            explicit: true,
        });
    }
    if targets.is_empty() {
        targets.push(FredTestTarget {
            name: "redis",
            url: DEFAULT_REDIS_URL.to_owned(),
            explicit: false,
        });
        targets.push(FredTestTarget {
            name: "valkey",
            url: DEFAULT_VALKEY_URL.to_owned(),
            explicit: false,
        });
    }
    targets
}

async fn available_fred_targets() -> Result<Vec<FredTestTarget>, Box<dyn std::error::Error>> {
    let mut available = Vec::new();
    for target in configured_fred_targets() {
        match FredRateLimitStore::connect(&target.url).await {
            Ok(_) => available.push(target),
            Err(error) if target.explicit => {
                return Err(format!(
                    "explicit {} target `{}` is unavailable: {error}",
                    target.name, target.url
                )
                .into());
            }
            Err(error) => {
                eprintln!(
                    "skipping default {} target `{}` because it is unavailable: {error}",
                    target.name, target.url
                );
            }
        }
    }
    Ok(available)
}

#[test]
fn fred_targets_default_to_docker_compose_redis_and_valkey_when_env_is_unset() {
    assert_eq!(
        fred_targets_from_env(None, None),
        vec![
            FredTestTarget {
                name: "redis",
                url: DEFAULT_REDIS_URL.to_owned(),
                explicit: false,
            },
            FredTestTarget {
                name: "valkey",
                url: DEFAULT_VALKEY_URL.to_owned(),
                explicit: false,
            },
        ]
    );
}

#[test]
fn fred_targets_allow_env_overrides() {
    assert_eq!(
        fred_targets_from_env(
            Some("redis://redis.test:6379".to_owned()),
            Some("valkey://valkey.test:6379".to_owned()),
        ),
        vec![
            FredTestTarget {
                name: "redis",
                url: "redis://redis.test:6379".to_owned(),
                explicit: true,
            },
            FredTestTarget {
                name: "valkey",
                url: "valkey://valkey.test:6379".to_owned(),
                explicit: true,
            },
        ]
    );
}

#[tokio::test]
async fn fred_rate_limit_store_enforces_atomic_max_one() -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let store = FredRateLimitStore::connect(&target.url).await?;
        let now_ms = now_ms();
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

        assert!(first.permitted, "{} should permit first call", target.name);
        assert!(!second.permitted, "{} should deny second call", target.name);
        assert_eq!(second.remaining, 0);
    }
    Ok(())
}

#[tokio::test]
async fn fred_rate_limit_store_allows_exactly_one_concurrent_request(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let store = FredRateLimitStore::connect(&target.url).await?;
        let now_ms = now_ms();
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
            "{} should permit exactly one concurrent call",
            target.name
        );
    }
    Ok(())
}

#[tokio::test]
async fn fred_rate_limit_store_resets_after_window() -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let store = FredRateLimitStore::connect(&target.url).await?;
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

        assert!(first.permitted);
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
async fn fred_rate_limit_store_does_not_reset_at_exact_window_boundary(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let store = FredRateLimitStore::connect(&target.url).await?;
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

        assert!(first.permitted);
        assert!(
            !second.permitted,
            "{} should not reset until after the window (Better Auth uses >)",
            target.name
        );
    }
    Ok(())
}

#[tokio::test]
async fn openauth_handler_async_uses_fred_rate_limit_store(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let store = FredRateLimitStore::connect(&target.url).await?;
        let auth = OpenAuth::builder()
            .secret("secret-a-at-least-32-chars-long!!")
            .rate_limit(
                openauth::RateLimitOptions::secondary_storage(store)
                    .enabled(true)
                    .window(60)
                    .max(1),
            )
            .build()?;

        let ip = unique_ip(if target.name == "redis" { 0 } else { 1 });
        let first = auth
            .handler_async(
                Request::builder()
                    .method(Method::GET)
                    .uri("http://localhost:3000/api/auth/ok")
                    .header("x-forwarded-for", &ip)
                    .body(Vec::new())?,
            )
            .await?;
        let second = auth
            .handler_async(
                Request::builder()
                    .method(Method::GET)
                    .uri("http://localhost:3000/api/auth/ok")
                    .header("x-forwarded-for", &ip)
                    .body(Vec::new())?,
            )
            .await?;

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(())
}

#[tokio::test]
async fn openauth_email_signup_uses_fred_secondary_storage_for_sessions(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let prefix = format!("openauth:test:{}:{}:signup:", target.name, now_ms());
        let storage = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: prefix,
                scan_count: 10,
            },
        )
        .await?;
        storage.clear().await?;
        let options = OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            secondary_storage: Some(Arc::new(storage.clone())),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        };
        let auth = OpenAuth::builder()
            .options(options)
            .adapter(MemoryAdapter::new())
            .build()?;

        let signup = auth
            .handler_async(json_request(
                Method::POST,
                "/api/auth/sign-up/email",
                r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
                None,
            )?)
            .await?;
        assert_eq!(signup.status(), StatusCode::OK);

        let mut keys = storage.list_keys().await?;
        keys.sort();
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().any(|key| key.starts_with("session:")));
        assert!(keys.iter().any(|key| key.starts_with("session:user:")));

        let cookie = cookie_header(&signup);
        let session = auth
            .handler_async(json_request(
                Method::GET,
                "/api/auth/get-session",
                "",
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(session.status(), StatusCode::OK);
        assert!(String::from_utf8_lossy(session.body()).contains("ada@example.com"));

        let list = auth
            .handler_async(json_request(
                Method::GET,
                "/api/auth/list-sessions",
                "",
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(list.status(), StatusCode::OK);
        let list_body = String::from_utf8_lossy(list.body());
        assert!(list_body.contains("\"token\""));
        assert!(!list_body.trim().eq("[]"));

        let revoke = auth
            .handler_async(json_request(
                Method::POST,
                "/api/auth/revoke-sessions",
                "{}",
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(revoke.status(), StatusCode::OK);
        assert!(storage.list_keys().await?.is_empty());

        storage.clear().await?;
    }
    Ok(())
}

#[tokio::test]
async fn openauth_email_signup_with_database_sessions_still_writes_fred_secondary_storage(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let prefix = format!("openauth:test:{}:{}:signup-db:", target.name, now_ms());
        let storage = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: prefix,
                scan_count: 10,
            },
        )
        .await?;
        storage.clear().await?;
        let options = OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            secondary_storage: Some(Arc::new(storage.clone())),
            session: SessionOptions::new()
                .store_session_in_database(true)
                .preserve_session_in_database(true),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        };
        let auth = OpenAuth::builder()
            .options(options)
            .adapter(MemoryAdapter::new())
            .build()?;

        let signup = auth
            .handler_async(json_request(
                Method::POST,
                "/api/auth/sign-up/email",
                r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
                None,
            )?)
            .await?;
        assert_eq!(signup.status(), StatusCode::OK);

        let cookie = cookie_header(&signup);
        let session = auth
            .handler_async(json_request(
                Method::GET,
                "/api/auth/get-session",
                "",
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(session.status(), StatusCode::OK);
        assert!(String::from_utf8_lossy(session.body()).contains("ada@example.com"));

        let keys = storage.list_keys().await?;
        let session_key = keys
            .iter()
            .find(|key| key.starts_with("session:") && !key.starts_with("session:user:"))
            .ok_or("missing fred session key")?;
        assert!(storage.get(session_key).await?.is_some());

        let signout = auth
            .handler_async(json_request(
                Method::POST,
                "/api/auth/sign-out",
                "",
                Some(&cookie),
            )?)
            .await?;
        assert_eq!(signout.status(), StatusCode::OK);
        assert_eq!(storage.get(session_key).await?, None);
        storage.clear().await?;
    }
    Ok(())
}

#[tokio::test]
async fn openauth_password_reset_uses_fred_secondary_storage_for_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let prefix = format!("openauth:test:{}:{}:password-reset:", target.name, now_ms());
        let storage = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: prefix,
                scan_count: 10,
            },
        )
        .await?;
        storage.clear().await?;
        let sent = Arc::new(Mutex::new(Vec::<String>::new()));
        let sent_for_hook = Arc::clone(&sent);
        let options = OpenAuthOptions {
            secret: Some("secret-a-at-least-32-chars-long!!".to_owned()),
            secondary_storage: Some(Arc::new(storage.clone())),
            password: PasswordOptions::new().send_reset_password(
                move |email: PasswordResetEmail, _request: Option<&Request<Vec<u8>>>| {
                    sent_for_hook
                        .lock()
                        .map_err(|_| OpenAuthError::Api("password reset sink poisoned".to_owned()))?
                        .push(email.token);
                    Ok(())
                },
            ),
            advanced: AdvancedOptions {
                disable_csrf_check: true,
                disable_origin_check: true,
                ..AdvancedOptions::default()
            },
            ..OpenAuthOptions::default()
        };
        let auth = OpenAuth::builder()
            .options(options)
            .adapter(MemoryAdapter::new())
            .build()?;

        let signup = auth
            .handler_async(json_request(
                Method::POST,
                "/api/auth/sign-up/email",
                r#"{"name":"Ada","email":"ada@example.com","password":"secret123"}"#,
                None,
            )?)
            .await?;
        assert_eq!(signup.status(), StatusCode::OK);

        let request_reset = auth
            .handler_async(json_request(
                Method::POST,
                "/api/auth/request-password-reset",
                r#"{"email":"ada@example.com","redirectTo":"/reset"}"#,
                None,
            )?)
            .await?;
        assert_eq!(request_reset.status(), StatusCode::OK);
        let token = sent
            .lock()
            .map_err(|_| "password reset sink poisoned")?
            .first()
            .cloned()
            .ok_or("missing reset token")?;
        let verification_key = format!("verification:reset-password:{token}");
        assert!(storage.get(&verification_key).await?.is_some());

        let reset = auth
            .handler_async(json_request(
                Method::POST,
                "/api/auth/reset-password",
                &format!(r#"{{"newPassword":"new-secret123","token":"{token}"}}"#),
                None,
            )?)
            .await?;
        assert_eq!(reset.status(), StatusCode::OK);
        assert_eq!(storage.get(&verification_key).await?, None);
        storage.clear().await?;
    }
    Ok(())
}

#[tokio::test]
async fn fred_secondary_storage_supports_strings_ttl_delete_list_and_clear(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let prefix = format!("openauth:test:{}:{}:storage:", target.name, now_ms());
        let storage = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: prefix.clone(),
                scan_count: 10,
            },
        )
        .await?;
        storage.clear().await?;

        storage
            .set("session:token-1", "raw-session-json".to_owned(), None)
            .await?;
        storage
            .set(
                "verification:user@example.com",
                "raw-verification-json".to_owned(),
                Some(60),
            )
            .await?;

        assert_eq!(
            storage.get("session:token-1").await?,
            Some("raw-session-json".to_owned())
        );
        assert_eq!(
            storage.get("verification:user@example.com").await?,
            Some("raw-verification-json".to_owned())
        );

        let mut keys = storage.list_keys().await?;
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "session:token-1".to_owned(),
                "verification:user@example.com".to_owned()
            ]
        );

        storage.delete("session:token-1").await?;
        assert_eq!(storage.get("session:token-1").await?, None);

        storage
            .set("take-once", "consumed".to_owned(), None)
            .await?;
        assert_eq!(
            storage.take("take-once").await?,
            Some("consumed".to_owned())
        );
        assert_eq!(storage.take("take-once").await?, None);

        storage
            .set("ttl-zero", "stale".to_owned(), Some(60))
            .await?;
        storage.set("ttl-zero", "value".to_owned(), Some(0)).await?;
        assert_eq!(storage.get("ttl-zero").await?, None);

        storage
            .set("short-lived", "value".to_owned(), Some(1))
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert_eq!(storage.get("short-lived").await?, None);

        storage.clear().await?;
        assert_eq!(storage.list_keys().await?, Vec::<String>::new());
    }
    Ok(())
}

#[tokio::test]
async fn fred_open_auth_stores_share_one_client() -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let stores = FredOpenAuthStores::connect(&target.url).await?;
        let key = format!("bundle:{}:{}", target.name, now_ms());
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

#[tokio::test]
async fn fred_secondary_storage_take_returns_value_at_most_once_under_concurrency(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let storage = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: format!("openauth:test:{}:{}:take-once:", target.name, now_ms()),
                scan_count: 10,
            },
        )
        .await?;
        let key = "verification:token";
        storage
            .set(key, "one-time-payload".to_owned(), None)
            .await?;

        let first_storage = storage.clone();
        let second_storage = storage.clone();
        let first_key = key.to_owned();
        let second_key = key.to_owned();
        let (first, second) = tokio::join!(
            first_storage.take(&first_key),
            second_storage.take(&second_key),
        );

        let mut payloads = [first?, second?].into_iter().flatten().collect::<Vec<_>>();
        assert_eq!(
            payloads.len(),
            1,
            "{} concurrent take() must return the payload at most once",
            target.name
        );
        assert_eq!(payloads.pop(), Some("one-time-payload".to_owned()));
        assert_eq!(storage.get(key).await?, None);
        storage.clear().await?;
    }
    Ok(())
}

#[tokio::test]
async fn fred_secondary_storage_take_does_not_delete_value_written_during_take(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let storage = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: format!("openauth:test:{}:{}:take-race:", target.name, now_ms()),
                scan_count: 10,
            },
        )
        .await?;
        let key = "verification:race";

        for attempt in 0..50 {
            storage.set(key, "old".to_owned(), None).await?;
            let racing = storage.clone();
            let racing_key = key.to_owned();
            let take = tokio::spawn(async move { racing.take(&racing_key).await });
            storage.set(key, "new".to_owned(), None).await?;
            let taken = take.await??;
            if taken.as_deref() == Some("old") {
                assert_eq!(
                    storage.get(key).await?.as_deref(),
                    Some("new"),
                    "{} attempt {attempt}: take() must not delete a newer value written after read",
                    target.name
                );
            }
            storage.delete(key).await?;
        }
        storage.clear().await?;
    }
    Ok(())
}

#[tokio::test]
async fn fred_and_redis_secondary_storage_take_match_for_same_key(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let fred = FredSecondaryStorage::connect(&target.url).await?;
        let redis = RedisSecondaryStorage::connect(&target.url).await?;
        let key = format!("take-parity:{}:{}", target.name, now_ms());

        redis.set(&key, "shared-payload".to_owned(), None).await?;
        assert_eq!(fred.take(&key).await?, Some("shared-payload".to_owned()));
        assert_eq!(redis.take(&key).await?, None);

        fred.set(&key, "fred-payload".to_owned(), None).await?;
        assert_eq!(redis.take(&key).await?, Some("fred-payload".to_owned()));
        assert_eq!(fred.take(&key).await?, None);

        redis.delete(&key).await?;
    }
    Ok(())
}

#[tokio::test]
async fn fred_and_redis_secondary_storage_share_physical_key_layout(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let fred = FredSecondaryStorage::connect(&target.url).await?;
        let redis = RedisSecondaryStorage::connect(&target.url).await?;
        let key = format!("cross-adapter:{}:{}", target.name, now_ms());

        // Written through redis-rs, read back through fred at the same logical key.
        redis.set(&key, "redis-value".to_owned(), None).await?;
        assert_eq!(fred.get(&key).await?, Some("redis-value".to_owned()));

        // Written through fred, read back through redis-rs.
        fred.set(&key, "fred-value".to_owned(), None).await?;
        assert_eq!(redis.get(&key).await?, Some("fred-value".to_owned()));

        // Deletion is observed across both adapters.
        redis.delete(&key).await?;
        assert_eq!(fred.get(&key).await?, None);
    }
    Ok(())
}

#[tokio::test]
async fn fred_secondary_storage_clear_preserves_co_located_rate_limit_keys(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let prefix = format!("openauth:test:{}:{}:ope37:", target.name, now_ms());
        let storage = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: prefix.clone(),
                scan_count: 10,
            },
        )
        .await?;
        let rate_limit = FredRateLimitStore::connect_with_options(
            &target.url,
            FredRateLimitOptions {
                key_prefix: prefix.clone(),
            },
        )
        .await?;
        storage.clear().await?;

        let now_ms = now_ms();
        let rate_key = "10.0.0.1|/sign-in".to_owned();
        let rule = RateLimitRule { window: 60, max: 1 };
        let first = rate_limit
            .consume(RateLimitConsumeInput {
                key: rate_key.clone(),
                rule: rule.clone(),
                now_ms,
            })
            .await?;
        assert!(
            first.permitted,
            "{} should permit first consume",
            target.name
        );

        storage
            .set("session:token", "value".to_owned(), None)
            .await?;
        storage.clear().await?;
        assert_eq!(storage.list_keys().await?, Vec::<String>::new());

        let second = rate_limit
            .consume(RateLimitConsumeInput {
                key: rate_key,
                rule,
                now_ms,
            })
            .await?;
        assert!(
            !second.permitted,
            "{} rate-limit state must survive secondary clear() (OPE-37)",
            target.name
        );
        assert_eq!(second.remaining, 0);
    }
    Ok(())
}

#[tokio::test]
async fn fred_secondary_storage_clear_keeps_other_prefixes(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let base = format!("openauth:test:{}:{}:isolation:", target.name, now_ms());
        let first = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: format!("{base}first:"),
                scan_count: 10,
            },
        )
        .await?;
        let second = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: format!("{base}second:"),
                scan_count: 10,
            },
        )
        .await?;
        first.clear().await?;
        second.clear().await?;

        first.set("shared", "first".to_owned(), None).await?;
        second.set("shared", "second".to_owned(), None).await?;
        first.clear().await?;

        assert_eq!(first.get("shared").await?, None);
        assert_eq!(second.get("shared").await?, Some("second".to_owned()));
        second.clear().await?;
    }
    Ok(())
}

#[tokio::test]
async fn fred_secondary_storage_treats_glob_metacharacters_in_prefix_literally(
) -> Result<(), Box<dyn std::error::Error>> {
    for target in available_fred_targets().await? {
        let base = format!("openauth:test:{}:{}:glob", target.name, now_ms());
        let literal_prefix = format!("{base}:*?[]\\:");
        let neighbor_prefix = format!("{base}:neighbor:");
        let storage = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: literal_prefix,
                scan_count: 10,
            },
        )
        .await?;
        let neighbor = FredSecondaryStorage::connect_with_options(
            &target.url,
            FredSecondaryStorageOptions {
                key_prefix: neighbor_prefix,
                scan_count: 10,
            },
        )
        .await?;
        storage.clear().await?;
        neighbor.clear().await?;

        storage.set("session", "literal".to_owned(), None).await?;
        neighbor.set("session", "neighbor".to_owned(), None).await?;

        assert_eq!(storage.list_keys().await?, vec!["session".to_owned()]);

        storage.clear().await?;
        assert_eq!(storage.get("session").await?, None);
        assert_eq!(neighbor.get("session").await?, Some("neighbor".to_owned()));
        neighbor.clear().await?;
    }
    Ok(())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

fn unique_ip(offset: u8) -> String {
    let seed = now_ms() as u64;
    let second = ((seed >> 16) & 0xff) as u8;
    let third = ((seed >> 8) & 0xff) as u8;
    let fourth = ((seed & 0xfe) as u8).saturating_add(offset).max(1);
    format!("10.{second}.{third}.{fourth}")
}

fn json_request(
    method: Method,
    path: &str,
    body: &str,
    cookie: Option<&str>,
) -> Result<Request<Vec<u8>>, http::Error> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost:3000{path}"));
    if !body.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    builder.body(body.as_bytes().to_vec())
}

fn cookie_header(response: &http::Response<Vec<u8>>) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split_once(';').map(|(cookie, _)| cookie.to_owned()))
        .collect::<Vec<_>>()
        .join("; ")
}
