//! Router-level rate limiting.

use crate::context::AuthContext;
use crate::env::is_production;
use crate::error::OpenAuthError;
use crate::options::{
    MissingIpPolicy, RateLimitConsumeInput, RateLimitDecision, RateLimitFuture, RateLimitRecord,
    RateLimitRule, RateLimitStorage, RateLimitStorageOption, RateLimitStore,
};
use crate::utils::ip::{
    create_rate_limit_key, create_rate_limit_key_with_suffix, is_valid_ip,
    normalize_ip_with_options, NormalizeIpOptions,
};
use crate::utils::url::normalize_pathname;
use hmac::{Hmac, Mac};
use http::Request;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type Body = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRejection {
    pub retry_after: u64,
}

/// Framework-neutral client IP resolved by an HTTP adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestClientIp(pub IpAddr);

#[derive(Default)]
pub struct GovernorMemoryRateLimitStore {
    records: Mutex<HashMap<String, MemoryRateLimitRecord>>,
    cleanup_interval: Option<Duration>,
    last_cleanup: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone)]
struct MemoryRateLimitRecord {
    count: u64,
    last_request: i64,
    window_ms: i64,
}

impl GovernorMemoryRateLimitStore {
    pub fn new() -> Self {
        Self::with_cleanup_interval(Some(Duration::from_secs(60 * 60)))
    }

    pub fn with_cleanup_interval(cleanup_interval: Option<Duration>) -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            cleanup_interval,
            last_cleanup: Mutex::new(None),
        }
    }

    fn cleanup_if_due(&self, now_ms: i64) -> Result<(), OpenAuthError> {
        let Some(interval) = self.cleanup_interval else {
            return Ok(());
        };

        let mut last_cleanup =
            self.last_cleanup
                .lock()
                .map_err(|_| OpenAuthError::LockPoisoned {
                    context: "rate limit cleanup",
                })?;
        let now = Instant::now();
        if last_cleanup
            .as_ref()
            .is_some_and(|last| last.elapsed() < interval)
        {
            return Ok(());
        }
        *last_cleanup = Some(now);
        drop(last_cleanup);

        self.records
            .lock()
            .map_err(|_| OpenAuthError::LockPoisoned {
                context: "rate limit store",
            })?
            .retain(|_, record| now_ms.saturating_sub(record.last_request) <= record.window_ms);
        Ok(())
    }
}

impl RateLimitStore for GovernorMemoryRateLimitStore {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a> {
        Box::pin(async move {
            validate_rule(&input.rule)?;
            self.cleanup_if_due(input.now_ms)?;
            let window_ms = rule_window_ms(&input.rule)?;
            let mut records = self
                .records
                .lock()
                .map_err(|_| OpenAuthError::LockPoisoned {
                    context: "rate limit store",
                })?;
            let decision = match records.get_mut(&input.key) {
                Some(record)
                    if input.now_ms.saturating_sub(record.last_request) <= window_ms
                        && record.count >= input.rule.max =>
                {
                    denied_decision(&input, record.last_request)
                }
                Some(record) if input.now_ms.saturating_sub(record.last_request) <= window_ms => {
                    record.count = record.count.saturating_add(1);
                    record.last_request = input.now_ms;
                    record.window_ms = window_ms;
                    allowed_decision(&input, record.count)
                }
                _ => {
                    records.insert(
                        input.key.clone(),
                        MemoryRateLimitRecord {
                            count: 1,
                            last_request: input.now_ms,
                            window_ms,
                        },
                    );
                    allowed_decision(&input, 1)
                }
            };
            Ok(decision)
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
            validate_rule(&input.rule)?;
            let window_ms = rule_window_ms(&input.rule)?;
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

/// Derive a stable, non-reversible rate-limit scope identifier.
///
/// Uses `HMAC-SHA256(secret, scope)` hex-encoded so storage keys never contain
/// raw challenge tokens or other client-controlled secrets.
pub fn hash_rate_limit_scope(secret: &str, scope: &str) -> Result<String, OpenAuthError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| {
        OpenAuthError::InvalidConfig("secret is invalid for rate limit scope HMAC".to_owned())
    })?;
    mac.update(scope.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Consume a rate-limit bucket keyed by client IP, path, and an opaque scope.
///
/// Scope values are digested with [`hash_rate_limit_scope`] before being stored.
/// Returns `None` when rate limiting is disabled, the request is permitted, or no
/// client IP can be resolved under the configured [`MissingIpPolicy::Allow`] policy.
pub async fn consume_scoped_rate_limit(
    context: &AuthContext,
    request: &Request<Body>,
    path: &str,
    scope: &str,
    rule: RateLimitRule,
) -> Result<Option<RateLimitRejection>, OpenAuthError> {
    if !context.rate_limit.enabled {
        return Ok(None);
    }
    let scope_suffix = format!(
        "challenge:{}",
        hash_rate_limit_scope(&context.secret, scope)?
    );
    let key = match resolve_rate_limit_key_plan(context, request, path, Some(&scope_suffix))? {
        RateLimitKeyPlan::Skip => return Ok(None),
        RateLimitKeyPlan::Deny => {
            return Ok(Some(RateLimitRejection {
                retry_after: rule.window,
            }));
        }
        RateLimitKeyPlan::Consume { key } => key,
    };
    consume_rate_limit_bucket(context, key, rule).await
}

pub async fn consume_rate_limit(
    context: &AuthContext,
    request: &Request<Body>,
) -> Result<Option<RateLimitRejection>, OpenAuthError> {
    if !context.rate_limit.enabled {
        return Ok(None);
    }
    let config = match resolve_config(context, request)? {
        RateLimitPlan::Skip => return Ok(None),
        RateLimitPlan::Deny { retry_after } => {
            return Ok(Some(RateLimitRejection { retry_after }));
        }
        RateLimitPlan::Consume(config) => config,
    };
    consume_rate_limit_bucket(context, config.key, config.rule).await
}

async fn consume_rate_limit_bucket(
    context: &AuthContext,
    key: String,
    rule: RateLimitRule,
) -> Result<Option<RateLimitRejection>, OpenAuthError> {
    let store = store(context)?;
    let decision = store
        .consume(RateLimitConsumeInput {
            key,
            rule,
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
    match resolve_config(context, request)? {
        RateLimitPlan::Skip => Ok(None),
        RateLimitPlan::Deny { retry_after } => Ok(Some(RateLimitRejection { retry_after })),
        RateLimitPlan::Consume(_) => Err(OpenAuthError::Api(
            "async rate limit storage requires AuthRouter::handle_async".to_owned(),
        )),
    }
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

/// Outcome of resolving how a request should be rate limited.
enum RateLimitPlan {
    /// No applicable rule, or IP tracking is intentionally disabled.
    Skip,
    /// Rate limiting is enabled with a rule but no client IP could be resolved.
    Deny { retry_after: u64 },
    /// Consume the resolved rule against the resolved bucket key.
    Consume(ResolvedRateLimit),
}

/// Outcome of resolving a rate-limit bucket key.
enum RateLimitKeyPlan {
    Skip,
    Deny,
    Consume { key: String },
}

/// Shared bucket key segment used when no client IP can be resolved and the
/// configured policy is [`MissingIpPolicy::SharedBucket`]. It is not a valid IP,
/// so it never collides with a real per-IP bucket.
const ANONYMOUS_IP_BUCKET: &str = "missing-ip";

fn resolve_config(
    context: &AuthContext,
    request: &Request<Body>,
) -> Result<RateLimitPlan, OpenAuthError> {
    let path = normalize_pathname(&request.uri().to_string(), &context.base_path);
    let Some(rule) = resolve_rule(context, request, &path)? else {
        return Ok(RateLimitPlan::Skip);
    };
    match resolve_rate_limit_key_plan(context, request, &path, None)? {
        RateLimitKeyPlan::Skip => Ok(RateLimitPlan::Skip),
        RateLimitKeyPlan::Deny => Ok(RateLimitPlan::Deny {
            retry_after: rule.window,
        }),
        RateLimitKeyPlan::Consume { key } => {
            Ok(RateLimitPlan::Consume(ResolvedRateLimit { key, rule }))
        }
    }
}

fn resolve_rate_limit_key_plan(
    context: &AuthContext,
    request: &Request<Body>,
    path: &str,
    key_suffix: Option<&str>,
) -> Result<RateLimitKeyPlan, OpenAuthError> {
    if let Some(ip) = resolve_client_ip(context, request) {
        let key = match key_suffix {
            Some(suffix) => create_rate_limit_key_with_suffix(&ip, path, suffix),
            None => create_rate_limit_key(&ip, path),
        };
        return Ok(RateLimitKeyPlan::Consume { key });
    }
    // No client IP could be resolved. When IP tracking is intentionally
    // disabled, per-IP limiting cannot apply, so skip. Otherwise apply the
    // configured fail-closed policy instead of silently bypassing the limit.
    if context.options.advanced.ip_address.disable_ip_tracking {
        return Ok(RateLimitKeyPlan::Skip);
    }
    match context.rate_limit.missing_ip_policy {
        MissingIpPolicy::Allow => Ok(RateLimitKeyPlan::Skip),
        MissingIpPolicy::SharedBucket => {
            let key = match key_suffix {
                Some(suffix) => {
                    create_rate_limit_key_with_suffix(ANONYMOUS_IP_BUCKET, path, suffix)
                }
                None => create_rate_limit_key(ANONYMOUS_IP_BUCKET, path),
            };
            Ok(RateLimitKeyPlan::Consume { key })
        }
        MissingIpPolicy::Deny => {
            context.logger.warn(
                "Rate limiting denied a request because no client IP could be resolved; inject RequestClientIp or set advanced.ip_address.headers",
                &[path],
            );
            Ok(RateLimitKeyPlan::Deny)
        }
    }
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

/// Resolve the trusted client IP for a request using `advanced.ip_address`
/// configuration. Shared by rate limiting and request metadata so the two
/// never disagree about the same request. Returns `None` when no trusted IP
/// can be resolved instead of trusting raw forwarding headers.
///
/// Exposed so plugin crates that create sessions outside the core auth flows
/// (e.g. passkey login) persist the same validated client IP rather than
/// trusting raw forwarding headers.
pub fn resolve_client_ip(context: &AuthContext, request: &Request<Body>) -> Option<String> {
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

    if let Some(client_ip) = request.extensions().get::<RequestClientIp>() {
        return Some(normalize_ip_with_options(
            &client_ip.0.to_string(),
            NormalizeIpOptions {
                ipv6_subnet: context.options.advanced.ip_address.ipv6_subnet,
            },
        ));
    }

    if !context.options.production && !is_production() {
        return Some("127.0.0.1".to_owned());
    }

    None
}

fn store(context: &AuthContext) -> Result<Arc<dyn RateLimitStore>, OpenAuthError> {
    if let Some(store) = &context.rate_limit.custom_store {
        if context.rate_limit.hybrid.enabled {
            return Ok(Arc::new(HybridRateLimitStore::new(
                Arc::clone(&context.rate_limit.memory_store),
                Arc::clone(store),
                context.rate_limit.hybrid.local_multiplier,
            )));
        }
        return Ok(Arc::clone(store));
    }
    match context.rate_limit.storage {
        RateLimitStorageOption::Memory => Ok(context.rate_limit.memory_store.clone()),
        RateLimitStorageOption::Database => Err(OpenAuthError::InvalidConfig(
            "database rate limit storage requires a concrete RateLimitStore".to_owned(),
        )),
        RateLimitStorageOption::SecondaryStorage => Err(OpenAuthError::InvalidConfig(
            "secondary-storage rate limit storage requires a concrete RateLimitStore".to_owned(),
        )),
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
    let window_ms = i64::try_from(input.rule.window.saturating_mul(1000)).unwrap_or(i64::MAX);
    let retry_after = last_request
        .saturating_add(window_ms)
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

fn validate_rule(rule: &RateLimitRule) -> Result<(), OpenAuthError> {
    if rule.window == 0 {
        return Err(OpenAuthError::InvalidConfig(
            "rate limit window must be greater than zero".to_owned(),
        ));
    }
    if rule.max == 0 {
        return Err(OpenAuthError::InvalidConfig(
            "rate limit max must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

fn rule_window_ms(rule: &RateLimitRule) -> Result<i64, OpenAuthError> {
    let milliseconds = rule
        .window
        .checked_mul(1000)
        .ok_or_else(|| OpenAuthError::InvalidConfig("rate limit window is too large".to_owned()))?;
    i64::try_from(milliseconds)
        .map_err(|_| OpenAuthError::InvalidConfig("rate limit window is too large".to_owned()))
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
