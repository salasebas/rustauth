use std::future::Future;
use std::pin::Pin;

use crate::error::OpenAuthError;

pub type SecondaryStorageFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, OpenAuthError>> + Send + 'a>>;

/// Async key-value storage for plugin data that can live outside the primary database.
pub trait SecondaryStorage: Send + Sync + 'static {
    fn get<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, Option<String>>;

    fn set<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, ()>;

    /// Store `value` only when `key` is absent.
    ///
    /// Returns `Ok(true)` when the key was created, or `Ok(false)` when it already existed.
    fn set_if_not_exists<'a>(
        &'a self,
        key: &'a str,
        value: String,
        ttl_seconds: Option<u64>,
    ) -> SecondaryStorageFuture<'a, bool>;

    fn delete<'a>(&'a self, key: &'a str) -> SecondaryStorageFuture<'a, ()>;
}
