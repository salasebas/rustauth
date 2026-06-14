//! SQLx database adapters for RustAuth.

pub(crate) mod migration;
mod stores;

#[cfg(feature = "sqlite")]
mod sqlite;

#[cfg(feature = "postgres")]
mod postgres;

#[cfg(feature = "mysql")]
mod mysql;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteAdapter;

#[cfg(feature = "postgres")]
pub use postgres::PostgresAdapter;

#[cfg(feature = "mysql")]
pub use mysql::MySqlAdapter;

#[cfg(feature = "mysql")]
pub use mysql::MySqlRateLimitStore;

#[cfg(feature = "postgres")]
pub use postgres::PostgresRateLimitStore;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteRateLimitStore;

#[cfg(feature = "sqlite")]
pub use stores::{SqliteStores, SqliteStoresBuilder};

#[cfg(feature = "postgres")]
pub use stores::{PostgresStores, PostgresStoresBuilder};

#[cfg(feature = "mysql")]
pub use stores::{MySqlStores, MySqlStoresBuilder};

pub(crate) use rustauth_core::db::{
    consume_sql_rate_limit_record as consume_record, rate_limit_count_from_i64 as count_from_i64,
    rate_limit_count_to_i64 as count_to_i64, SqlRateLimitNames as RateLimitSqlNames,
};
