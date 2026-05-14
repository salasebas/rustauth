//! Router-level rate limiting.

use crate::context::AuthContext;
use crate::env::is_production;
use crate::error::OpenAuthError;
use crate::options::{RateLimitRecord, RateLimitRule, RateLimitStorage, RateLimitStorageOption};
use crate::utils::ip::{
    create_rate_limit_key, is_valid_ip, normalize_ip_with_options, NormalizeIpOptions,
};
use crate::utils::url::normalize_pathname;
use http::Request;
use std::collections::HashMap;
use std::sync::Mutex;

pub type Body = Vec<u8>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRejection {
    pub retry_after: u64,
}

#[derive(Debug, Default)]
pub struct MemoryRateLimitStorage {
    entries: Mutex<HashMap<String, MemoryRateLimitEntry>>,
}

#[derive(Debug, Clone)]
struct MemoryRateLimitEntry {
    record: RateLimitRecord,
    expires_at: i64,
}

impl MemoryRateLimitStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RateLimitStorage for MemoryRateLimitStorage {
    fn get(&self, key: &str) -> Result<Option<RateLimitRecord>, OpenAuthError> {
        let now = now_seconds();
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OpenAuthError::Api("rate limit storage lock poisoned".to_owned()))?;
        let Some(entry) = entries.get(key) else {
            return Ok(None);
        };
        if now >= entry.expires_at {
            entries.remove(key);
            return Ok(None);
        }
        Ok(Some(entry.record.clone()))
    }

    fn set(
        &self,
        key: &str,
        value: RateLimitRecord,
        ttl_seconds: u64,
        _update: bool,
    ) -> Result<(), OpenAuthError> {
        let expires_at = now_seconds().saturating_add(ttl_seconds as i64);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OpenAuthError::Api("rate limit storage lock poisoned".to_owned()))?;
        entries.insert(
            key.to_owned(),
            MemoryRateLimitEntry {
                record: value,
                expires_at,
            },
        );
        Ok(())
    }
}

pub fn on_request_rate_limit(
    context: &AuthContext,
    request: &Request<Body>,
) -> Result<Option<RateLimitRejection>, OpenAuthError> {
    if !context.rate_limit.enabled {
        return Ok(None);
    }
    let Some(config) = resolve_config(context, request)? else {
        return Ok(None);
    };
    let storage = storage(context);
    let Some(record) = storage.get(&config.key)? else {
        return Ok(None);
    };

    if should_rate_limit(config.rule.max, config.rule.window, &record) {
        return Ok(Some(RateLimitRejection {
            retry_after: retry_after(record.last_request, config.rule.window),
        }));
    }

    Ok(None)
}

pub fn on_response_rate_limit(
    context: &AuthContext,
    request: &Request<Body>,
) -> Result<(), OpenAuthError> {
    if !context.rate_limit.enabled {
        return Ok(());
    }
    let Some(config) = resolve_config(context, request)? else {
        return Ok(());
    };
    let storage = storage(context);
    let now = now_seconds();
    let next_record = match storage.get(&config.key)? {
        Some(record) if now.saturating_sub(record.last_request) <= config.rule.window as i64 => {
            RateLimitRecord {
                key: config.key.clone(),
                count: record.count.saturating_add(1),
                last_request: now,
            }
        }
        _ => RateLimitRecord {
            key: config.key.clone(),
            count: 1,
            last_request: now,
        },
    };

    let update = next_record.count > 1;
    storage.set(&config.key, next_record, config.rule.window, update)
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

fn storage(context: &AuthContext) -> &dyn RateLimitStorage {
    if let Some(storage) = &context.rate_limit.custom_storage {
        return storage.as_ref();
    }
    match context.rate_limit.storage {
        RateLimitStorageOption::Memory
        | RateLimitStorageOption::Database
        | RateLimitStorageOption::SecondaryStorage => context.rate_limit.memory_storage.as_ref(),
    }
}

fn should_rate_limit(max: u64, window: u64, record: &RateLimitRecord) -> bool {
    let time_since_last_request = now_seconds().saturating_sub(record.last_request);
    time_since_last_request < window as i64 && record.count >= max
}

fn retry_after(last_request: i64, window: u64) -> u64 {
    let retry_after = last_request
        .saturating_add(window as i64)
        .saturating_sub(now_seconds());
    retry_after.max(0) as u64
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return path.starts_with(prefix) && path.ends_with(suffix);
    }
    pattern == path
}

fn now_seconds() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
