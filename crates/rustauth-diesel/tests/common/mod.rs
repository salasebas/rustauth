#![allow(dead_code)]

use rustauth_core::error::RustAuthError;

pub const DEFAULT_POSTGRES_URL: &str = "postgres://user:password@localhost:5432/rustauth";

pub const DEFAULT_MYSQL_URL: &str = "mysql://user:password@localhost:3306/rustauth";

pub fn database_url_from_env(value: Option<String>, default_url: &str) -> String {
    value.unwrap_or_else(|| default_url.to_owned())
}

pub fn postgres_database_url() -> String {
    database_url_from_env(
        rustauth_core::env::env_var("TEST_POSTGRES_URL")
            .or_else(|| rustauth_core::env::env_var("RUSTAUTH_TEST_POSTGRES_URL")),
        DEFAULT_POSTGRES_URL,
    )
}

pub fn mysql_database_url() -> String {
    database_url_from_env(
        rustauth_core::env::env_var("TEST_MYSQL_URL")
            .or_else(|| rustauth_core::env::env_var("RUSTAUTH_TEST_MYSQL_URL")),
        DEFAULT_MYSQL_URL,
    )
}

pub fn preflight_error(
    adapter: &str,
    database_url: &str,
    error: impl std::fmt::Display,
) -> RustAuthError {
    RustAuthError::Adapter(format!(
        "{adapter} test database preflight failed for `{database_url}`: {error}. Ensure the Docker Compose service exists, the `rustauth` database exists, and the configured user has permissions. Override with TEST_POSTGRES_URL, TEST_MYSQL_URL, or RUSTAUTH_TEST_*_URL when needed."
    ))
}
