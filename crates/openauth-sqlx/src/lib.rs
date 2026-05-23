//! SQLx database adapters for OpenAuth.

pub mod migration;

mod rate_limit;

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

pub(crate) use openauth_core::db::{
    consume_sql_rate_limit_record as consume_record, SqlRateLimitNames as RateLimitSqlNames,
};
pub(crate) use rate_limit::{count_from_i64, count_to_i64};
