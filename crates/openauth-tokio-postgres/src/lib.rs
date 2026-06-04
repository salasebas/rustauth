//! Minimal `tokio-postgres` database adapter for OpenAuth.
//!
//! This crate is useful when the application already owns a single
//! `tokio_postgres::Client` or wants the smallest async Postgres adapter.
//! Production applications that need pooling should prefer
//! `openauth-deadpool-postgres`.

mod adapter;
mod connection;
pub mod driver;
mod errors;
pub mod migration;
mod query;
mod rate_limit;
mod row;
mod schema;
mod transaction;
mod tx_guard;

pub use self::adapter::TokioPostgresAdapter;
pub use self::connection::TokioPostgresConnection;
pub use self::migration::{
    ColumnToAdd, IndexToCreate, MigrationStatement, MigrationStatementKind, SchemaMigrationPlan,
    SchemaMigrationWarning, TableToCreate,
};
pub use self::rate_limit::TokioPostgresRateLimitStore;
