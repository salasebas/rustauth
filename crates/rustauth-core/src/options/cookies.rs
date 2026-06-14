use time::Duration;

/// Session cookie cache configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieCacheOptions {
    pub enabled: bool,
    pub max_age: Option<Duration>,
    pub strategy: CookieCacheStrategy,
    pub refresh_cache: bool,
    pub version: Option<String>,
}

impl Default for CookieCacheOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age: None,
            strategy: CookieCacheStrategy::Compact,
            refresh_cache: false,
            version: None,
        }
    }
}

impl CookieCacheOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    #[must_use]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    #[must_use]
    pub fn strategy(mut self, strategy: CookieCacheStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    #[must_use]
    pub fn refresh_cache(mut self, refresh_cache: bool) -> Self {
        self.refresh_cache = refresh_cache;
        self
    }

    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}

/// Cookie cache encoding strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieCacheStrategy {
    Compact,
    Jwt,
    Jwe,
}

/// Cross-subdomain cookie configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CookieConfig {
    pub enabled: bool,
    pub domain: Option<String>,
}

impl CookieConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> Self {
        Self::new()
    }

    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    #[must_use]
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }
}
