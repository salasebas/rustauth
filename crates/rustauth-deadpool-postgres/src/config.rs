use std::fmt;

use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use rustauth_core::error::RustAuthError;
use tokio_postgres::{
    tls::{MakeTlsConnect, TlsConnect},
    Client, Socket,
};

pub(crate) const DEFAULT_POOL_MAX_SIZE: usize = 16;

pub(crate) fn apply_default_pool_config(config: &mut Config, max_size: usize) {
    if config.pool.is_none() {
        config.pool = Some(PoolConfig::new(max_size));
    }
}

pub(crate) fn create_pool<T>(config: Config, tls: T) -> Result<Pool, RustAuthError>
where
    T: MakeTlsConnect<Socket> + Clone + Sync + Send + 'static,
    T::Stream: Sync + Send,
    T::TlsConnect: Sync + Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    config
        .create_pool(Some(Runtime::Tokio1), tls)
        .map_err(deadpool_error)
}

pub(crate) fn pg_client(client: &deadpool_postgres::Client) -> &Client {
    client
}

pub(crate) fn deadpool_error(error: impl fmt::Display + fmt::Debug) -> RustAuthError {
    RustAuthError::Adapter(format!(
        "deadpool-postgres error: {error}; detail: {error:?}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct DebugOnlyContext;

    impl fmt::Display for DebugOnlyContext {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("display context")
        }
    }

    #[test]
    fn deadpool_error_includes_debug_context() {
        let error = deadpool_error(DebugOnlyContext);

        let message = error.to_string();
        assert!(message.contains("display context"));
        assert!(message.contains("DebugOnlyContext"));
    }

    #[test]
    fn apply_default_pool_config_preserves_existing_pool_config() {
        let mut config = Config::new();
        config.pool = Some(PoolConfig::new(3));

        apply_default_pool_config(&mut config, 16);

        assert_eq!(config.pool.map(|pool| pool.max_size), Some(3));
    }

    #[test]
    fn apply_default_pool_config_sets_pool_config_when_missing() {
        let mut config = Config::new();

        apply_default_pool_config(&mut config, 16);

        assert_eq!(config.pool.map(|pool| pool.max_size), Some(16));
    }
}
