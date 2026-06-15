//! Actix Web integration for RustAuth.

mod error;
mod options;
mod request;
mod response;
mod router;

#[cfg(feature = "test-utils")]
pub mod test_utils;

pub use error::RustAuthActixWebError;
pub use options::RustAuthActixWebOptions;
pub use router::{handle, validate_mount_config, RustAuthActixWebExt};
