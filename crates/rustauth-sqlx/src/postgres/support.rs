use rustauth_core::db::SqlDialect;
use rustauth_core::error::RustAuthError;

pub(super) fn sanitize_identifier(identifier: &str) -> Result<String, RustAuthError> {
    SqlDialect::Postgres.sanitize_identifier(identifier)
}
