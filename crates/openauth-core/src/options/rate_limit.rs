use std::fmt;
use std::sync::Arc;

use http::Request;

use crate::error::OpenAuthError;

/// Rate limiting defaults.
#[derive(Clone)]
pub struct RateLimitOptions {
    pub enabled: Option<bool>,
    pub window: u64,
    pub max: u64,
    pub storage: RateLimitStorageOption,
    pub custom_rules: Vec<RateLimitPathRule>,
    pub dynamic_rules: Vec<DynamicRateLimitPathRule>,
    pub custom_storage: Option<Arc<dyn RateLimitStorage>>,
}

impl Default for RateLimitOptions {
    fn default() -> Self {
        Self {
            enabled: None,
            window: 10,
            max: 100,
            storage: RateLimitStorageOption::Memory,
            custom_rules: Vec::new(),
            dynamic_rules: Vec::new(),
            custom_storage: None,
        }
    }
}

impl fmt::Debug for RateLimitOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitOptions")
            .field("enabled", &self.enabled)
            .field("window", &self.window)
            .field("max", &self.max)
            .field("storage", &self.storage)
            .field("custom_rules", &self.custom_rules)
            .field("dynamic_rules", &self.dynamic_rules)
            .field(
                "custom_storage",
                &self.custom_storage.as_ref().map(|_| "<custom-storage>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRule {
    pub window: u64,
    pub max: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitPathRule {
    pub path: String,
    pub rule: Option<RateLimitRule>,
}

pub trait RateLimitRuleProvider: Send + Sync + 'static {
    fn resolve(
        &self,
        request: &Request<Vec<u8>>,
        current_rule: &RateLimitRule,
    ) -> Result<Option<RateLimitRule>, OpenAuthError>;
}

impl<F> RateLimitRuleProvider for F
where
    F: Fn(&Request<Vec<u8>>, &RateLimitRule) -> Result<Option<RateLimitRule>, OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn resolve(
        &self,
        request: &Request<Vec<u8>>,
        current_rule: &RateLimitRule,
    ) -> Result<Option<RateLimitRule>, OpenAuthError> {
        self(request, current_rule)
    }
}

#[derive(Clone)]
pub struct DynamicRateLimitPathRule {
    pub path: String,
    pub provider: Arc<dyn RateLimitRuleProvider>,
}

impl DynamicRateLimitPathRule {
    pub fn new<P>(path: impl Into<String>, provider: P) -> Self
    where
        P: RateLimitRuleProvider,
    {
        Self {
            path: path.into(),
            provider: Arc::new(provider),
        }
    }
}

impl fmt::Debug for DynamicRateLimitPathRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynamicRateLimitPathRule")
            .field("path", &self.path)
            .field("provider", &"<request-aware>")
            .finish()
    }
}

/// Rate limit storage record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRecord {
    pub key: String,
    pub count: u64,
    pub last_request: i64,
}

/// Synchronous storage contract for router-level rate limiting.
pub trait RateLimitStorage: Send + Sync + 'static {
    fn get(&self, key: &str) -> Result<Option<RateLimitRecord>, OpenAuthError>;
    fn set(
        &self,
        key: &str,
        value: RateLimitRecord,
        ttl_seconds: u64,
        update: bool,
    ) -> Result<(), OpenAuthError>;
}

/// Rate limit storage selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitStorageOption {
    Memory,
    Database,
    SecondaryStorage,
}
