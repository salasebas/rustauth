use rustauth_core::error::RustAuthError;
use rustauth_core::options::{RateLimitConsumeInput, RateLimitRule, RateLimitStore};

const NOW_MS: i64 = 1_700_000_000_000;

pub async fn assert_sql_rate_limit_store_rejects_invalid_rules<S>(
    store: &S,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: RateLimitStore,
{
    let key = "127.0.0.1|/invalid-rule".to_owned();
    let cases = [
        (
            RateLimitRule {
                window: time::Duration::seconds(0),
                max: 1,
            },
            "rate limit window must be greater than zero",
        ),
        (
            RateLimitRule {
                window: time::Duration::seconds(1),
                max: 0,
            },
            "rate limit max must be greater than zero",
        ),
        (
            RateLimitRule {
                window: time::Duration::seconds(i64::MAX),
                max: 1,
            },
            "rate limit window is too large",
        ),
        (
            RateLimitRule {
                window: time::Duration::seconds(9_223_372_036_854_776),
                max: 1,
            },
            "rate limit window is too large",
        ),
    ];

    for (rule, expected) in cases {
        let error = store
            .consume(RateLimitConsumeInput {
                key: key.clone(),
                rule: rule.clone(),
                now_ms: NOW_MS,
            })
            .await
            .err()
            .ok_or("expected invalid config error")?;

        assert!(
            matches!(
                &error,
                RustAuthError::InvalidConfig(message) if message == expected
            ),
            "unexpected error for rule {:?}: {error:?}",
            rule,
        );
    }

    Ok(())
}
