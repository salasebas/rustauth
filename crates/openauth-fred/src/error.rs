use std::fmt;

use openauth_core::error::OpenAuthError;

pub(crate) fn fred_error(operation: &str, error: impl fmt::Display) -> OpenAuthError {
    OpenAuthError::Adapter(format!("fred {operation} failed: {error}"))
}
