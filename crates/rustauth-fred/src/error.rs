use std::fmt;

use rustauth_core::error::RustAuthError;

pub(crate) fn fred_error(operation: &str, error: impl fmt::Display) -> RustAuthError {
    RustAuthError::Adapter(format!("fred {operation} failed: {error}"))
}
