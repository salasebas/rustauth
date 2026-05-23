use openauth_core::error::OpenAuthError;

pub fn postgres_error(error: tokio_postgres::Error) -> OpenAuthError {
    let Some(db_error) = error.as_db_error() else {
        return OpenAuthError::Adapter(format!("tokio-postgres error: {error}"));
    };

    let mut parts = vec![
        format!("SQLSTATE {}", db_error.code().code()),
        db_error.message().to_owned(),
    ];
    if let Some(detail) = db_error.detail() {
        parts.push(format!("detail: {detail}"));
    }
    if let Some(schema) = db_error.schema() {
        parts.push(format!("schema: {schema}"));
    }
    if let Some(table) = db_error.table() {
        parts.push(format!("table: {table}"));
    }
    if let Some(column) = db_error.column() {
        parts.push(format!("column: {column}"));
    }
    if let Some(constraint) = db_error.constraint() {
        parts.push(format!("constraint: {constraint}"));
    }

    OpenAuthError::Adapter(format!("tokio-postgres error: {}", parts.join("; ")))
}

pub fn json_error(error: serde_json::Error) -> OpenAuthError {
    OpenAuthError::Adapter(format!("tokio-postgres JSON error: {error}"))
}
