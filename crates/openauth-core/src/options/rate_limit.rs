use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

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
    pub custom_store: Option<Arc<dyn RateLimitStore>>,
    pub custom_storage: Option<Arc<dyn RateLimitStorage>>,
    pub hybrid: HybridRateLimitOptions,
    pub memory_idle_ttl: Option<Duration>,
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
            custom_store: None,
            custom_storage: None,
            hybrid: HybridRateLimitOptions::default(),
            memory_idle_ttl: Some(Duration::from_secs(60 * 60)),
        }
    }
}

impl RateLimitOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    pub fn memory() -> Self {
        Self {
            storage: RateLimitStorageOption::Memory,
            ..Self::default()
        }
    }

    pub fn database<S>(store: S) -> Self
    where
        S: RateLimitStore,
    {
        Self::database_arc(Arc::new(store))
    }

    pub fn database_arc(store: Arc<dyn RateLimitStore>) -> Self {
        Self {
            storage: RateLimitStorageOption::Database,
            custom_store: Some(store),
            ..Self::default()
        }
    }

    pub fn secondary_storage<S>(store: S) -> Self
    where
        S: RateLimitStore,
    {
        Self::secondary_storage_arc(Arc::new(store))
    }

    pub fn secondary_storage_arc(store: Arc<dyn RateLimitStore>) -> Self {
        Self {
            storage: RateLimitStorageOption::SecondaryStorage,
            custom_store: Some(store),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    #[must_use]
    pub fn window(mut self, window: u64) -> Self {
        self.window = window;
        self
    }

    #[must_use]
    pub fn max(mut self, max: u64) -> Self {
        self.max = max;
        self
    }

    #[must_use]
    pub fn storage(mut self, storage: RateLimitStorageOption) -> Self {
        self.storage = storage;
        self
    }

    #[must_use]
    pub fn custom_store<S>(mut self, store: S) -> Self
    where
        S: RateLimitStore,
    {
        self.custom_store = Some(Arc::new(store));
        self
    }

    #[must_use]
    pub fn custom_store_arc(mut self, store: Arc<dyn RateLimitStore>) -> Self {
        self.custom_store = Some(store);
        self
    }

    #[must_use]
    pub fn custom_storage(mut self, storage: Arc<dyn RateLimitStorage>) -> Self {
        self.custom_storage = Some(storage);
        self
    }

    #[must_use]
    pub fn custom_rule(mut self, path: impl Into<String>, rule: RateLimitRule) -> Self {
        self.custom_rules.push(RateLimitPathRule {
            path: path.into(),
            rule: Some(rule),
        });
        self
    }

    #[must_use]
    pub fn disabled_path(mut self, path: impl Into<String>) -> Self {
        self.custom_rules.push(RateLimitPathRule {
            path: path.into(),
            rule: None,
        });
        self
    }

    #[must_use]
    pub fn dynamic_rule<P>(mut self, path: impl Into<String>, provider: P) -> Self
    where
        P: RateLimitRuleProvider,
    {
        self.dynamic_rules
            .push(DynamicRateLimitPathRule::new(path, provider));
        self
    }

    #[must_use]
    pub fn hybrid(mut self, hybrid: HybridRateLimitOptions) -> Self {
        self.hybrid = hybrid;
        self
    }

    #[must_use]
    pub fn memory_idle_ttl(mut self, ttl: Option<Duration>) -> Self {
        self.memory_idle_ttl = ttl;
        self
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
                "custom_store",
                &self.custom_store.as_ref().map(|_| "<custom-store>"),
            )
            .field(
                "custom_storage",
                &self.custom_storage.as_ref().map(|_| "<custom-storage>"),
            )
            .field("hybrid", &self.hybrid)
            .field("memory_idle_ttl", &self.memory_idle_ttl)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitRule {
    pub window: u64,
    pub max: u64,
}

impl RateLimitRule {
    pub fn new(window: u64, max: u64) -> Self {
        Self { window, max }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridRateLimitOptions {
    pub enabled: bool,
    pub local_multiplier: u64,
}

impl Default for HybridRateLimitOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            local_multiplier: 2,
        }
    }
}

impl HybridRateLimitOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    pub fn disabled() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn set_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    #[must_use]
    pub fn local_multiplier(mut self, multiplier: u64) -> Self {
        self.local_multiplier = multiplier;
        self
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConsumeInput {
    pub key: String,
    pub rule: RateLimitRule,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub permitted: bool,
    pub retry_after: u64,
    pub limit: u64,
    pub remaining: u64,
    pub reset_after: u64,
}

pub type RateLimitFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RateLimitDecision, OpenAuthError>> + Send + 'a>>;

/// Atomic rate limit storage contract.
///
/// Implementations must make the check-and-increment decision in one atomic
/// operation when used for cross-process or distributed enforcement.
pub trait RateLimitStore: Send + Sync + 'static {
    fn consume<'a>(&'a self, input: RateLimitConsumeInput) -> RateLimitFuture<'a>;
}

/// Synchronous storage contract for router-level rate limiting.
///
/// This legacy contract is preserved for compatibility. It is not atomic across
/// multiple processes unless the implementation makes `get`/`set` externally
/// serializable.
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
