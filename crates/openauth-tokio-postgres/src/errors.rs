use openauth_core::error::OpenAuthError;

pub fn postgres_error(error: tokio_postgres::Error) -> OpenAuthError {
    OpenAuthError::Adapter(format!("tokio-postgres error: {error}"))
}

pub fn json_error(error: serde_json::Error) -> OpenAuthError {
    OpenAuthError::Adapter(format!("tokio-postgres JSON error: {error}"))
}
