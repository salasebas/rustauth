//! Environment helpers for RustAuth core.

pub mod logger;

use crate::options::{DeploymentMode, RustAuthOptions};

/// Reads `RUSTAUTH_{suffix}` from the process environment.
///
/// Empty values are treated as unset.
pub fn env_var(suffix: &str) -> Option<String> {
    let key = format!("RUSTAUTH_{suffix}");
    std::env::var(&key).ok().filter(|value| !value.is_empty())
}

/// Returns true when RustAuth is running in a production environment.
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
pub fn is_production_posture(options: &RustAuthOptions) -> bool {
    !allows_development_defaults(options)
}

/// Whether development-oriented security defaults are explicitly allowed.
pub fn allows_development_defaults(options: &RustAuthOptions) -> bool {
    match options.mode {
        DeploymentMode::Production => false,
        DeploymentMode::Development => !is_production(),
        DeploymentMode::Auto => !is_production() && is_development_env(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::*;

    struct EnvRestore(Vec<(&'static str, Option<String>)>);

    impl EnvRestore {
        fn unset(keys: &[&'static str]) -> Self {
            let saved = keys
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect::<Vec<_>>();
            for key in keys {
                std::env::remove_var(key);
            }
            Self(saved)
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn lock_env() -> MutexGuard<'static, ()> {
        env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn env_var_reads_rustauth_prefix() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(&["RUSTAUTH_SECRET"]);
        std::env::set_var("RUSTAUTH_SECRET", "rustauth-secret");

        assert_eq!(env_var("SECRET").as_deref(), Some("rustauth-secret"));
    }

    #[test]
    fn env_var_ignores_empty_values() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(&["RUSTAUTH_SECRET"]);
        std::env::set_var("RUSTAUTH_SECRET", "");

        assert_eq!(env_var("SECRET"), None);
    }

    #[test]
    fn env_var_returns_none_when_unset() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(&["RUSTAUTH_SECRET"]);

        assert_eq!(env_var("SECRET"), None);
    }
}
