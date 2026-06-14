//! Pooled Postgres database adapter for RustAuth.
//!
//! This crate is the recommended Postgres adapter for production deployments.
//! It keeps pooling in `deadpool-postgres` and reuses RustAuth's shared SQL
//! planning plus `rustauth-tokio-postgres` driver helpers.

mod adapter;
mod builder;
mod config;
mod rate_limit;
mod transaction;
mod tx_guard;

pub use self::adapter::DeadpoolPostgresAdapter;
pub use self::builder::{
    DeadpoolPostgresBuilder, DeadpoolPostgresStores, DeadpoolPostgresStoresBuilder,
};
pub use self::rate_limit::DeadpoolPostgresRateLimitStore;
