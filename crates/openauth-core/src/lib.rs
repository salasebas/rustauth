//! Core types and primitives for OpenAuth.

pub mod api;
pub mod auth;
pub mod context;
pub mod cookies;
pub mod crypto;
pub mod db;
pub mod env;
pub mod error;
pub mod error_codes;
pub mod options;
pub mod plugin;
pub mod rate_limit;
pub mod secret;
pub mod session;
pub mod user;
pub mod utils;
pub mod verification;

#[cfg(any(test, feature = "test-utils"))]
#[path = "options/storage_contract.rs"]
pub mod storage_contract;

#[cfg(feature = "oauth")]
pub use openauth_oauth as oauth;
#[cfg(feature = "social-providers")]
pub use openauth_social_providers as social_providers;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
