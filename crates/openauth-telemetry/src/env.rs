//! Telemetry-related environment variables use the **`OPENAUTH_*`** prefix.

/// Returns the first non-empty env value among given keys.
pub fn first_env(keys: &[&'static str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn parse_bool(value: &str) -> bool {
    value != "0" && value.to_lowercase() != "false"
}

fn bool_env_single(key: &'static str, fallback: bool) -> bool {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => parse_bool(&value),
        _ => fallback,
    }
}

pub fn telemetry_endpoint() -> Option<String> {
    std::env::var("OPENAUTH_TELEMETRY_ENDPOINT")
        .ok()
        .filter(|value| !value.is_empty())
}

/// Three-state read of the `OPENAUTH_TELEMETRY` master switch.
///
/// - `None` when unset or empty (defer to [`TelemetryOptions`]).
/// - `Some(false)` for `0` / `false` (explicit opt-out, a hard override).
/// - `Some(true)` for any other value (explicit opt-in).
///
/// [`TelemetryOptions`]: openauth_core::options::TelemetryOptions
pub fn telemetry_env_setting() -> Option<bool> {
    match std::env::var("OPENAUTH_TELEMETRY") {
        Ok(value) if !value.is_empty() => Some(parse_bool(&value)),
        _ => None,
    }
}

pub fn telemetry_debug_env() -> bool {
    bool_env_single("OPENAUTH_TELEMETRY_DEBUG", false)
}

pub fn rust_env() -> Option<String> {
    first_env(&["RUST_ENV"])
}

pub fn is_test() -> bool {
    rust_env().as_deref() == Some("test") || bool_env_single("TEST", false)
}

pub fn is_ci() -> bool {
    if std::env::var("CI").ok().as_deref() == Some("false") {
        return false;
    }
    [
        "BUILD_ID",
        "BUILD_NUMBER",
        "CI",
        "CI_APP_ID",
        "CI_BUILD_ID",
        "CI_BUILD_NUMBER",
        "CI_NAME",
        "CONTINUOUS_INTEGRATION",
        "RUN_ID",
    ]
    .into_iter()
    .any(|key| std::env::var_os(key).is_some())
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
    fn rust_env_reads_rust_env() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(&["RUST_ENV"]);
        std::env::set_var("RUST_ENV", "production");

        assert_eq!(rust_env().as_deref(), Some("production"));
    }

    #[test]
    fn rust_env_returns_none_when_unset() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(&["RUST_ENV"]);

        assert_eq!(rust_env(), None);
    }

    #[test]
    fn is_test_uses_rust_environment_names() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(&["RUST_ENV", "TEST"]);
        std::env::set_var("RUST_ENV", "test");

        assert!(is_test());
    }
}
