//! Minimal `tokio-postgres` database adapter for RustAuth.
//!
//! This crate is useful when the application already owns a single
//! `tokio_postgres::Client` or wants the smallest async Postgres adapter.
//! Production applications that need pooling should prefer
//! `rustauth-deadpool-postgres`.

mod adapter;
mod connection;
#[doc(hidden)]
pub mod driver;
mod errors;
mod query;
mod rate_limit;
mod row;
mod schema;
mod stores;
mod transaction;
mod tx_guard;

pub use self::adapter::TokioPostgresAdapter;
pub use self::connection::TokioPostgresConnection;
pub use self::rate_limit::TokioPostgresRateLimitStore;
pub use self::stores::{TokioPostgresStores, TokioPostgresStoresBuilder};
