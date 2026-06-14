use rustauth_core::error::RustAuthError;

pub(super) fn inactive_transaction() -> RustAuthError {
    RustAuthError::Adapter("sqlite transaction is no longer active".to_owned())
}

pub(super) fn sql_error(error: sqlx::Error) -> RustAuthError {
    RustAuthError::Adapter(error.to_string())
}

pub(super) fn sql_error_with_context(
    operation: &str,
    sql: &str,
    params: usize,
    error: sqlx::Error,
) -> RustAuthError {
    RustAuthError::Adapter(format!(
        "sqlite {operation} failed for SQL `{sql}` with {params} bound parameters: {error}"
    ))
}

pub(super) fn argument_error(error: Box<dyn std::error::Error + Send + Sync>) -> RustAuthError {
    RustAuthError::Adapter(error.to_string())
}

pub(super) fn time_error(error: impl std::fmt::Display) -> RustAuthError {
    RustAuthError::Adapter(error.to_string())
}

pub(super) fn json_error(error: serde_json::Error) -> RustAuthError {
    RustAuthError::Adapter(error.to_string())
}
