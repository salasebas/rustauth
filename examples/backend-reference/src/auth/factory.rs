//! [`RustAuth`] assembly: Postgres adapter and the live instance.

use std::sync::Arc;

use rustauth::options::RateLimitOptions;
use rustauth::RustAuth;
use rustauth_deadpool_postgres::{DeadpoolPostgresAdapter, DeadpoolPostgresStores};

use crate::auth::options::{apply_rate_limit_rules, build_rustauth_options};
use crate::auth::schema::resolve_schema;
use crate::config::AppConfig;
use crate::database::postgres::connect_postgres;
use crate::error::AppResult;

/// Fully initialized RustAuth stack backed by Deadpool Postgres.
pub struct AuthStack {
    pub auth: Arc<RustAuth>,
    pub config: AppConfig,
}

impl AuthStack {
    pub async fn from_config(config: AppConfig) -> AppResult<Self> {
        let schema = resolve_schema()?;
        let stores = connect_postgres(&config.database_url, schema).await?;
        let options = build_rustauth_options(&config)?;
        let options = stores.apply_to_options(options);
        let options = options.rate_limit(apply_rate_limit_rules(RateLimitOptions::database(
            stores.rate_limit.clone(),
        )));

        let auth = RustAuth::builder()
            .options(options)
            .adapter_arc(stores.adapter())
            .build()
            .await?;

        Ok(Self {
            auth: Arc::new(auth),
            config,
        })
    }

    /// In-memory stack for tests and local exploration without Docker.
    pub async fn in_memory(config: AppConfig) -> AppResult<Self> {
        let options = build_rustauth_options(&config)?;
        let auth = RustAuth::builder()
            .options(options)
            .adapter(rustauth::db::MemoryAdapter::new())
            .build()
            .await?;
        Ok(Self {
            auth: Arc::new(auth),
            config,
        })
    }
}

/// Convenience for callers that already hold a configured stores bundle.
pub async fn build_with_stores(
    config: AppConfig,
    stores: DeadpoolPostgresStores,
) -> AppResult<Arc<RustAuth>> {
    let options = build_rustauth_options(&config)?;
    let options = stores.apply_to_options(options);
    let options = options.rate_limit(apply_rate_limit_rules(RateLimitOptions::database(
        stores.rate_limit.clone(),
    )));
    let auth = RustAuth::builder()
        .options(options)
        .adapter_arc(stores.adapter())
        .build()
        .await?;
    Ok(Arc::new(auth))
}

/// Convenience for callers that already hold a configured adapter.
pub async fn build_with_adapter(
    config: AppConfig,
    adapter: DeadpoolPostgresAdapter,
) -> AppResult<Arc<RustAuth>> {
    let rate_limit = rustauth_deadpool_postgres::DeadpoolPostgresRateLimitStore::from(&adapter);
    let options = build_rustauth_options(&config)?;
    let options = options.rate_limit(apply_rate_limit_rules(RateLimitOptions::database(
        rate_limit,
    )));
    let auth = RustAuth::builder()
        .options(options)
        .adapter(adapter)
        .build()
        .await?;
    Ok(Arc::new(auth))
}

/// Expose the underlying context for advanced server-side integrations.
pub fn context(auth: &RustAuth) -> &rustauth::context::AuthContext {
    auth.context()
}
