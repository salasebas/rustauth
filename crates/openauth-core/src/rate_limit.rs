//! Router-level rate limiting.

use crate::context::AuthContext;
use crate::env::is_production;
use crate::error::OpenAuthError;
use crate::options::{
    RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitRecord, RateLimitRule,
    RateLimitStorage, RateLimitStorageOption, RateLimitStore,
};
use crate::utils::ip::{
    create_rate_limit_key, is_valid_ip, normalize_ip_with_options, NormalizeIpOptions,
};
use crate::utils::url::normalize_pathname;
use governor::clock::Clock;
use governor::middleware::StateInformationMiddleware;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use http::Request;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type Body = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRejection {
    pub retry_after: u64,
}

type GovernorLimiter = DefaultKeyedRateLimiter<String, StateInformationMiddleware>;

#[derive(Default)]
pub struct GovernorMemoryRateLimitStore {
    limiters: Mutex<HashMap<(u64, u64), Arc<GovernorLimiter>>>,
    cleanup_interval: Option<Duration>,
    last_cleanup: Mutex<Option<Instant>>,
}

impl GovernorMemoryRateLimitStore {
    pub fn new() -> Self {
        Self::with_cleanup_interval(Some(Duration::from_secs(60 * 60)))
    }

    pub fn with_cleanup_interval(cleanup_interval: Option<Duration>) -> Self {
        Self {
            limiters: Mutex::new(HashMap::new()),
            cleanup_interval,
            last_cleanup: Mutex::new(None),
        }
    }

    fn limiter(&self, rule: &RateLimitRule) -> Result<Arc<GovernorLimiter>, OpenAuthError> {
        self.cleanup_if_due()?;
        let quota = quota(rule)?;
        let mut limiters = self
            .limiters
            .lock()
            .map_err(|_| OpenAuthError::Api("rate limit store lock poisoned".to_owned()))?;
        let key = (rule.window, rule.max);
        if let Some(limiter) = limiters.get(&key) {
            return Ok(Arc::clone(limiter));
        }
        let limiter =
            Arc::new(RateLimiter::keyed(quota).with_middleware::<StateInformationMiddleware>());
        limiters.insert(key, Arc::clone(&limiter));
        Ok(limiter)
    }

    fn cleanup_if_due(&self) -> Result<(), OpenAuthError> {
        let Some(interval) = self.cleanup_interval else {
            return Ok(());
        };

        let mut last_cleanup = self
            .last_cleanup
            .lock()
            .map_err(|_| OpenAuthError::Api("rate limit cleanup lock poisoned".to_owned()))?;
        let now = Instant::now();
        if last_cleanup
            .as_ref()
            .is_some_and(|last| last.elapsed() < interval)
        {
            return Ok(());
        }
        *last_cleanup = Some(now);
        drop(last_cleanup);

        let limiters = self
            .limiters
            .lock()
            .map_err(|_| OpenAuthError::Api("rate limit store lock poisoned".to_owned()))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for limiter in limiters {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
        Ok(())
    }
}

impl RateLimitStore for GovernorMemoryRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            let limiter = self.limiter(&input.rule)?;
            match limiter.check_key(&input.key) {
                Ok(snapshot) => Ok(RateLimitDecision {
                    permitted: true,
                    retry_after: 0,
                    limit: input.rule.max,
                    remaining: u64::from(snapshot.remaining_burst_capacity()),
                    reset_after: input.rule.window,
                }),
                Err(not_until) => {
                    let retry_after =
                        ceil_duration_to_seconds(not_until.wait_time_from(limiter.clock().now()));
                    Ok(RateLimitDecision {
                        permitted: false,
                        retry_after,
                        limit: input.rule.max,
                        remaining: 0,
                        reset_after: retry_after,
                    })
                }
            }
        })
    }
}

pub struct LegacyRateLimitStorageAdapter {
    storage: Arc<dyn RateLimitStorage>,
}

impl LegacyRateLimitStorageAdapter {
    pub fn new(storage: Arc<dyn RateLimitStorage>) -> Self {
        Self { storage }
    }
}

impl RateLimitStore for LegacyRateLimitStorageAdapter {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            let window_ms = input.rule.window.saturating_mul(1000) as i64;
            let existing = self.storage.get(&input.key)?;
            let decision = match existing {
                Some(record)
                    if input.now_ms.saturating_sub(record.last_request) <= window_ms
                        && record.count >= input.rule.max =>
                {
                    denied_decision(&input, record.last_request)
                }
                Some(record) if input.now_ms.saturating_sub(record.last_request) <= window_ms => {
                    let next_count = record.count.saturating_add(1);
                    self.storage.set(
                        &input.key,
                        RateLimitRecord {
                            key: input.key.clone(),
                            count: next_count,
                            last_request: input.now_ms,
                        },
                        input.rule.window,
                        true,
                    )?;
                    allowed_decision(&input, next_count)
                }
                _ => {
                    self.storage.set(
                        &input.key,
                        RateLimitRecord {
                            key: input.key.clone(),
                            count: 1,
                            last_request: input.now_ms,
                        },
                        input.rule.window,
                        existing.is_some(),
                    )?;
                    allowed_decision(&input, 1)
                }
            };
            Ok(decision)
        })
    }
}

pub struct HybridRateLimitStore {
    local: Arc<GovernorMemoryRateLimitStore>,
    global: Arc<dyn RateLimitStore>,
    local_multiplier: u64,
}

impl HybridRateLimitStore {
    pub fn new(
        local: Arc<GovernorMemoryRateLimitStore>,
        global: Arc<dyn RateLimitStore>,
        local_multiplier: u64,
    ) -> Self {
        Self {
            local,
            global,
            local_multiplier: local_multiplier.max(1),
        }
    }
}

impl RateLimitStore for HybridRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            let local_input = RateLimitConsumeInput {
                key: input.key.clone(),
                rule: RateLimitRule {
                    window: input.rule.window,
                    max: input.rule.max.saturating_mul(self.local_multiplier).max(1),
                },
                now_ms: input.now_ms,
            };
            let local = self.local.consume(local_input).await?;
            if !local.permitted {
                return Ok(local);
            }
            self.global.consume(input).await
        })
    }
}

pub async fn consume_rate_limit(
    context: &AuthContext,
    request: &Request<Body>,
) -> Result<Option<RateLimitRejection>, OpenAuthError> {
    if !context.rate_limit.enabled {
        return Ok(None);
    }
    let Some(config) = resolve_config(context, request)? else {
        return Ok(None);
    };
    let store = store(context);
    let decision = store
        .consume(RateLimitConsumeInput {
            key: config.key,
            rule: config.rule,
            now_ms: now_millis(),
        })
        .await?;
    if decision.permitted {
        return Ok(None);
    }
    Ok(Some(RateLimitRejection {
        retry_after: decision.retry_after,
    }))
}

pub fn on_request_rate_limit(
    context: &AuthContext,
    request: &Request<Body>,
) -> Result<Option<RateLimitRejection>, OpenAuthError> {
    if !context.rate_limit.enabled {
        return Ok(None);
    }
    if resolve_config(context, request)?.is_none() {
        return Ok(None);
    }
    Err(OpenAuthError::Api(
        "async rate limit storage requires AuthRouter::handle_async".to_owned(),
    ))
}

pub fn on_response_rate_limit(
    _context: &AuthContext,
    _request: &Request<Body>,
) -> Result<(), OpenAuthError> {
    Ok(())
}

#[derive(Debug)]
struct ResolvedRateLimit {
    key: String,
    rule: RateLimitRule,
}

fn resolve_config(
    context: &AuthContext,
    request: &Request<Body>,
) -> Result<Option<ResolvedRateLimit>, OpenAuthError> {
    let path = normalize_pathname(&request.uri().to_string(), &context.base_path);
    let Some(ip) = request_ip(context, request) else {
        return Ok(None);
    };
    let Some(rule) = resolve_rule(context, request, &path)? else {
        return Ok(None);
    };
    Ok(Some(ResolvedRateLimit {
        key: create_rate_limit_key(&ip, &path),
        rule,
    }))
}

fn resolve_rule(
    context: &AuthContext,
    request: &Request<Body>,
    path: &str,
) -> Result<Option<RateLimitRule>, OpenAuthError> {
    let mut rule = default_rule(context);
    if let Some(special_rule) = default_special_rule(path) {
        rule = special_rule;
    }
    for plugin_rule in &context.rate_limit.plugin_rules {
        if path_matches(&plugin_rule.path, path) {
            rule = plugin_rule.rule.clone();
            break;
        }
    }
    for custom_rule in &context.rate_limit.custom_rules {
        if path_matches(&custom_rule.path, path) {
            return Ok(custom_rule.rule.clone());
        }
    }
    for dynamic_rule in &context.rate_limit.dynamic_rules {
        if path_matches(&dynamic_rule.path, path) {
            return dynamic_rule.provider.resolve(request, &rule);
        }
    }
    Ok(Some(rule))
}

fn default_rule(context: &AuthContext) -> RateLimitRule {
    RateLimitRule {
        window: context.rate_limit.window,
        max: context.rate_limit.max,
    }
}

fn default_special_rule(path: &str) -> Option<RateLimitRule> {
    if path.starts_with("/sign-in")
        || path.starts_with("/sign-up")
        || path.starts_with("/change-password")
        || path.starts_with("/change-email")
    {
        return Some(RateLimitRule { window: 10, max: 3 });
    }
    if path == "/request-password-reset"
        || path == "/send-verification-email"
        || path.starts_with("/forget-password")
        || path == "/email-otp/send-verification-otp"
        || path == "/email-otp/request-password-reset"
    {
        return Some(RateLimitRule { window: 60, max: 3 });
    }
    None
}

fn request_ip(context: &AuthContext, request: &Request<Body>) -> Option<String> {
    if context.options.advanced.ip_address.disable_ip_tracking {
        return None;
    }

    for header_name in &context.options.advanced.ip_address.headers {
        if let Some(value) = request
            .headers()
            .get(header_name)
            .and_then(|value| value.to_str().ok())
        {
            let Some(candidate) = value.split(',').next().map(str::trim) else {
                continue;
            };
            if is_valid_ip(candidate) {
                return Some(normalize_ip_with_options(
                    candidate,
                    NormalizeIpOptions {
                        ipv6_subnet: context.options.advanced.ip_address.ipv6_subnet,
                    },
                ));
            }
        }
    }

    if !context.options.production && !is_production() {
        return Some("127.0.0.1".to_owned());
    }

    None
}

fn store(context: &AuthContext) -> Arc<dyn RateLimitStore> {
    if let Some(store) = &context.rate_limit.custom_store {
        if context.rate_limit.hybrid.enabled {
            return Arc::new(HybridRateLimitStore::new(
                Arc::clone(&context.rate_limit.memory_store),
                Arc::clone(store),
                context.rate_limit.hybrid.local_multiplier,
            ));
        }
        return Arc::clone(store);
    }
    match context.rate_limit.storage {
        RateLimitStorageOption::Memory
        | RateLimitStorageOption::Database
        | RateLimitStorageOption::SecondaryStorage => context.rate_limit.memory_store.clone(),
    }
}

fn allowed_decision(input: &RateLimitConsumeInput, count: u64) -> RateLimitDecision {
    RateLimitDecision {
        permitted: true,
        retry_after: 0,
        limit: input.rule.max,
        remaining: input.rule.max.saturating_sub(count),
        reset_after: input.rule.window,
    }
}

fn denied_decision(input: &RateLimitConsumeInput, last_request: i64) -> RateLimitDecision {
    let retry_after = last_request
        .saturating_add(input.rule.window.saturating_mul(1000) as i64)
        .saturating_sub(input.now_ms)
        .max(0);
    RateLimitDecision {
        permitted: false,
        retry_after: ceil_millis_to_seconds(retry_after),
        limit: input.rule.max,
        remaining: 0,
        reset_after: ceil_millis_to_seconds(retry_after),
    }
}

fn ceil_duration_to_seconds(duration: std::time::Duration) -> u64 {
    if duration.is_zero() {
        return 0;
    }
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() > 0))
}

fn quota(rule: &RateLimitRule) -> Result<Quota, OpenAuthError> {
    if rule.window == 0 {
        return Err(OpenAuthError::InvalidConfig(
            "rate limit window must be greater than zero".to_owned(),
        ));
    }
    let max =
        NonZeroU32::new(u32::try_from(rule.max).map_err(|_| {
            OpenAuthError::InvalidConfig("rate limit max must fit in u32".to_owned())
        })?)
        .ok_or_else(|| {
            OpenAuthError::InvalidConfig("rate limit max must be greater than zero".to_owned())
        })?;
    let mut replenish_interval = Duration::from_secs(rule.window) / max.get();
    if replenish_interval.is_zero() {
        replenish_interval = Duration::from_nanos(1);
    }
    Quota::with_period(replenish_interval)
        .map(|quota| quota.allow_burst(max))
        .ok_or_else(|| {
            OpenAuthError::InvalidConfig(
                "rate limit replenish interval must be greater than zero".to_owned(),
            )
        })
}

fn ceil_millis_to_seconds(milliseconds: i64) -> u64 {
    if milliseconds <= 0 {
        return 0;
    }
    ((milliseconds as u64).saturating_add(999)) / 1000
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return path.starts_with(prefix) && path.ends_with(suffix);
    }
    pattern == path
}

fn now_millis() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000
}
