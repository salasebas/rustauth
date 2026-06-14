use std::sync::Arc;

use rustauth_core::error::RustAuthError;
use rustauth_core::options::{RateLimitOptions, RustAuthOptions};

use crate::rate_limit::{RedisRateLimitOptions, RedisRateLimitStore};
use crate::secondary::{RedisSecondaryStorage, RedisSecondaryStorageOptions};

/// Shared connection options for rate limiting and secondary storage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedisOptions {
    pub rate_limit: RedisRateLimitOptions,
    pub secondary_storage: RedisSecondaryStorageOptions,
}

/// Previous name for [`RedisOptions`]; kept for migration.
pub type RedisRustAuthOptions = RedisOptions;

/// Rate limit and secondary storage backed by one `ConnectionManager`.
#[derive(Clone)]
pub struct RedisStores {
    pub rate_limit: RedisRateLimitStore,
    pub secondary_storage: RedisSecondaryStorage,
}

/// Previous name for [`RedisStores`]; kept for migration.
pub type RedisRustAuthStores = RedisStores;

impl RedisStores {
    pub async fn connect(url: &str) -> Result<Self, RustAuthError> {
        Self::connect_with_options(url, RedisOptions::default()).await
    }

    pub async fn connect_with_options(
        url: &str,
        options: RedisOptions,
    ) -> Result<Self, RustAuthError> {
        let manager = crate::connect_manager(url).await?;
        Ok(Self {
            rate_limit: RedisRateLimitStore::new(manager.clone(), options.rate_limit),
            secondary_storage: RedisSecondaryStorage::new(manager, options.secondary_storage),
        })
    }

    /// Wires both stores into [`RustAuthOptions`] (secondary storage + distributed rate limit).
    #[must_use]
    pub fn apply_to_options(&self, options: RustAuthOptions) -> RustAuthOptions {
        options
            .secondary_storage(Arc::new(self.secondary_storage.clone()))
            .rate_limit(RateLimitOptions::secondary_storage(self.rate_limit.clone()))
    }
}
