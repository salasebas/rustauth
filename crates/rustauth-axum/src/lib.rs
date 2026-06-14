//! Axum integration for RustAuth.

mod error;
mod options;
mod request;
mod response;
mod router;

#[cfg(feature = "test-utils")]
pub mod test_utils;

pub use error::RustAuthAxumError;
pub use options::RustAuthAxumOptions;
pub use router::{handle, validate_mount_config, RustAuthAxumExt};
