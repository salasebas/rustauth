use rustauth_core::error::RustAuthError;

pub(super) fn inactive_transaction() -> RustAuthError {
    RustAuthError::Adapter("diesel mysql transaction is no longer active".to_owned())
}

pub(super) fn diesel_error(error: impl std::fmt::Display) -> RustAuthError {
    RustAuthError::Adapter(error.to_string())
}

pub(super) fn diesel_error_with_context(
    operation: &str,
    sql: &str,
    params: usize,
    error: impl std::fmt::Display,
) -> RustAuthError {
    RustAuthError::Adapter(format!(
        "diesel mysql {operation} failed for SQL `{sql}` with {params} bound parameters: {error}"
    ))
}

pub(super) fn pool_error(error: impl std::fmt::Display) -> RustAuthError {
    RustAuthError::Adapter(format!("diesel mysql pool error: {error}"))
}

pub(super) fn json_error(error: serde_json::Error) -> RustAuthError {
    RustAuthError::Adapter(format!("diesel mysql json decode: {error}"))
}
