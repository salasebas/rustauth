use openauth_core::db::SqlDialect;
use openauth_core::error::OpenAuthError;

pub(super) fn sanitize_identifier(identifier: &str) -> Result<String, OpenAuthError> {
    SqlDialect::Postgres.sanitize_identifier(identifier)
}
