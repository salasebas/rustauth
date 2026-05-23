#![allow(dead_code)]

use openauth_core::error::OpenAuthError;

pub const DEFAULT_POSTGRES_URL: &str = "postgres://user:password@localhost:5432/openauth";
pub const DEFAULT_MYSQL_URL: &str = "mysql://user:password@localhost:3306/openauth";

pub fn database_url_from_env(value: Option<String>, default_url: &str) -> String {
    value.unwrap_or_else(|| default_url.to_owned())
}

pub fn postgres_database_url() -> String {
    database_url_from_env(
        std::env::var("OPENAUTH_TEST_POSTGRES_URL").ok(),
        DEFAULT_POSTGRES_URL,
    )
}

pub fn mysql_database_url() -> String {
    database_url_from_env(
        std::env::var("OPENAUTH_TEST_MYSQL_URL").ok(),
        DEFAULT_MYSQL_URL,
    )
}

pub fn preflight_error(adapter: &str, database_url: &str, error: sqlx::Error) -> OpenAuthError {
    OpenAuthError::Adapter(format!(
        "{adapter} test database preflight failed for `{database_url}`: {error}. Ensure the Docker Compose service exists, the `openauth` database exists, and the configured user has permissions. Override with OPENAUTH_TEST_POSTGRES_URL or OPENAUTH_TEST_MYSQL_URL when needed."
    ))
}
