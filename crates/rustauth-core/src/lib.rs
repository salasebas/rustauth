//! Core types and primitives for RustAuth.

pub mod api;
pub mod auth;
pub mod background;
pub mod context;
pub mod cookies;
pub mod crypto;
pub mod db;
pub mod env;
pub mod error;
pub mod error_codes;
pub mod options;
pub mod outbound;
pub mod plugin;
pub mod rate_limit;
pub mod secret;
pub mod session;
pub mod user;
pub mod utils;
pub mod verification;

pub use background::tokio::TokioBackgroundTaskRunner;
pub use outbound::{dispatch_outbound, ready_outbound, OutboundSendFuture};

#[cfg(any(test, feature = "test-utils"))]
#[path = "options/storage_contract.rs"]
pub mod storage_contract;

#[cfg(feature = "test-utils")]
pub mod test_utils;

#[cfg(feature = "oauth")]
pub use rustauth_oauth as oauth;
#[cfg(feature = "social-providers")]
pub use rustauth_social_providers as social_providers;

/// Current crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::RustAuthError;
pub use options::RustAuthOptions;
