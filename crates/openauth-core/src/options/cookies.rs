/// Session cookie cache configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieCacheOptions {
    pub enabled: bool,
    pub max_age: Option<u64>,
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
