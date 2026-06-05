//! Environment helpers for OpenAuth core.

pub mod logger;

use crate::options::OpenAuthOptions;

/// Returns true when OpenAuth is running in a production environment.
pub fn is_production() -> bool {
    std::env::var("RUST_ENV").is_ok_and(|value| value == "production")
}

/// Returns true when the process is running under a development-oriented environment.
fn is_development_env() -> bool {
    match std::env::var("RUST_ENV") {
        Ok(value) => value == "development" || value == "test",
        Err(_) => is_test_runtime(),
    }
}

fn is_test_runtime() -> bool {
    std::env::var("RUST_TEST_THREADS").is_ok()
        || std::env::var("NEXTEST").is_ok_and(|value| value == "1")
        || std::env::var("TEST")
            .is_ok_and(|value| !value.is_empty() && value != "0" && value.to_lowercase() != "false")
}

/// Whether security-sensitive defaults should assume a production deployment.
///
/// Ambiguous deployments (neither explicitly production nor development) fail closed
/// and are treated as production.
pub fn is_production_posture(options: &OpenAuthOptions) -> bool {
    !allows_development_defaults(options)
}

/// Whether development-oriented security defaults are explicitly allowed.
pub fn allows_development_defaults(options: &OpenAuthOptions) -> bool {
    if options.production || is_production() {
        return false;
    }
    options.development || is_development_env()
}
