//! Fred-backed Redis and Valkey integrations for RustAuth.

mod bundle;
mod config;
mod error;
mod script;
mod storage;
mod store;
mod url;

pub use bundle::{FredOptions, FredRustAuthOptions, FredRustAuthStores, FredStores};
pub use config::{FredRateLimitOptions, FredSecondaryStorageOptions};
pub use storage::FredSecondaryStorage;
pub use store::FredRateLimitStore;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
