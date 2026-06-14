use std::sync::Arc;

use rustauth_core::error::RustAuthError;
use rustauth_core::options::{RateLimitOptions, RustAuthOptions};

use crate::config::{FredRateLimitOptions, FredSecondaryStorageOptions};
use crate::storage::FredSecondaryStorage;
use crate::store::{connect_client, FredRateLimitStore};

/// Shared connection options for rate limiting and secondary storage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FredOptions {
    pub rate_limit: FredRateLimitOptions,
    pub secondary_storage: FredSecondaryStorageOptions,
}

/// Previous name for [`FredOptions`]; kept for migration.
pub type FredRustAuthOptions = FredOptions;

/// Rate limit and secondary storage backed by one `fred` client.
#[derive(Clone)]
pub struct FredStores {
    pub rate_limit: FredRateLimitStore,
    pub secondary_storage: FredSecondaryStorage,
}

/// Previous name for [`FredStores`]; kept for migration.
pub type FredRustAuthStores = FredStores;

impl FredStores {
    pub async fn connect(url: &str) -> Result<Self, RustAuthError> {
        Self::connect_with_options(url, FredOptions::default()).await
    }

    pub async fn connect_with_options(
        url: &str,
        options: FredOptions,
    ) -> Result<Self, RustAuthError> {
        let client = connect_client(url).await?;
        Ok(Self {
            rate_limit: FredRateLimitStore::new(client.clone(), options.rate_limit),
            secondary_storage: FredSecondaryStorage::new(client, options.secondary_storage),
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
