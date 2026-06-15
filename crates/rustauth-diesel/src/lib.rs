//! Diesel database adapters for RustAuth.
//!
//! ## Row decoding strategy
//!
//! **Chosen:** dynamic row capture via [`postgres::row::DieselPostgresRow`], which
//! implements [`diesel::deserialize::QueryableByName`] by storing raw column bytes
//! and type OIDs at build time, then decoding through `tokio_postgres` [`FromSql`]
//! in the shared [`SqlRowReader`] boundary.
//!
//! Direct [`diesel::row::NamedRow`] decoding remains available for feasibility tests
//! in [`row`].
//!
//! ## Adapter shape
//!
//! - Crate name: `rustauth-diesel` (async-only on `diesel-async`; no sync adapter).
//! - Initial backends: Postgres and MySQL (`postgres` / `mysql` features).
//! - SQLite and sync Diesel are deferred by design.

#![cfg(any(feature = "postgres", feature = "mysql"))]

pub(crate) mod migration;
mod stores;

mod bind;
mod row;

#[cfg(feature = "postgres")]
mod postgres;

#[cfg(feature = "mysql")]
mod mysql;

#[cfg(feature = "mysql")]
pub use bind::bind_mysql_params;
#[cfg(feature = "postgres")]
pub use bind::bind_postgres_params;

#[cfg(feature = "mysql")]
pub use row::decode_mysql_row;
#[cfg(feature = "postgres")]
pub use row::decode_postgres_row;

pub use row::RowDecodeStrategy;

#[cfg(feature = "postgres")]
pub use postgres::{DieselPostgresAdapter, DieselPostgresRateLimitStore};

#[cfg(feature = "mysql")]
pub use mysql::{DieselMysqlAdapter, DieselMysqlRateLimitStore};

#[cfg(feature = "postgres")]
pub use stores::{DieselPostgresStores, DieselPostgresStoresBuilder};

#[cfg(feature = "mysql")]
pub use stores::{DieselMysqlStores, DieselMysqlStoresBuilder};

pub(crate) use rustauth_core::db::{
    consume_sql_rate_limit_record as consume_record, rate_limit_count_from_i64 as count_from_i64,
    rate_limit_count_to_i64 as count_to_i64, SqlRateLimitNames as RateLimitSqlNames,
};

#[cfg(not(any(feature = "postgres", feature = "mysql")))]
compile_error!("enable at least one of `postgres` or `mysql` features");
