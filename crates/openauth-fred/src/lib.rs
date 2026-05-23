//! Fred-backed Redis and Valkey integrations for OpenAuth.

mod config;
mod error;
mod script;
mod storage;
mod store;
mod url;

pub use config::{FredRateLimitOptions, FredSecondaryStorageOptions};
pub use script::{parse_rate_limit_script_result, RateLimitScriptResult};
pub use storage::FredSecondaryStorage;
pub use store::FredRateLimitStore;
pub use url::normalize_fred_url;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
