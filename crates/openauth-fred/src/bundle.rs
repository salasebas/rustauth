use std::sync::Arc;

use openauth_core::error::OpenAuthError;
use openauth_core::options::{OpenAuthOptions, RateLimitOptions};

use crate::config::{FredRateLimitOptions, FredSecondaryStorageOptions};
use crate::storage::FredSecondaryStorage;
use crate::store::{connect_client, FredRateLimitStore};

/// Shared connection options for rate limiting and secondary storage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FredOpenAuthOptions {
    pub rate_limit: FredRateLimitOptions,
    pub secondary_storage: FredSecondaryStorageOptions,
}

/// Rate limit and secondary storage backed by one `fred` client.
#[derive(Clone)]
pub struct FredOpenAuthStores {
    pub rate_limit: FredRateLimitStore,
    pub secondary_storage: FredSecondaryStorage,
}

impl FredOpenAuthStores {
    pub async fn connect(url: &str) -> Result<Self, OpenAuthError> {
        Self::connect_with_options(url, FredOpenAuthOptions::default()).await
    }

    pub async fn connect_redis(url: &str) -> Result<Self, OpenAuthError> {
        Self::connect(url).await
    }

    pub async fn connect_valkey(url: &str) -> Result<Self, OpenAuthError> {
        Self::connect(url).await
    }

    pub async fn connect_with_options(
        url: &str,
        options: FredOpenAuthOptions,
    ) -> Result<Self, OpenAuthError> {
        let client = connect_client(url).await?;
        Ok(Self {
            rate_limit: FredRateLimitStore::new(client.clone(), options.rate_limit),
            secondary_storage: FredSecondaryStorage::new(client, options.secondary_storage),
        })
    }

    /// Wires both stores into [`OpenAuthOptions`] (secondary storage + distributed rate limit).
    #[must_use]
    pub fn apply_to_options(&self, options: OpenAuthOptions) -> OpenAuthOptions {
        options
            .secondary_storage(Arc::new(self.secondary_storage.clone()))
            .rate_limit(RateLimitOptions::secondary_storage(self.rate_limit.clone()))
    }
}
