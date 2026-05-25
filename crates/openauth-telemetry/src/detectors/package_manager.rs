//! Rust package manager detection.

use crate::types::DetectionInfo;

pub fn detect_package_manager() -> Option<DetectionInfo> {
    let cargo_manifest_present = std::env::var_os("CARGO_MANIFEST_DIR").is_some()
        || std::env::current_dir()
            .ok()
            .is_some_and(|dir| dir.join("Cargo.toml").exists());
    let cargo_version = std::env::var("CARGO_VERSION").ok();
    detect_cargo_package_manager(cargo_manifest_present, cargo_version.as_deref())
}

fn detect_cargo_package_manager(
    cargo_manifest_present: bool,
    cargo_version: Option<&str>,
) -> Option<DetectionInfo> {
    cargo_manifest_present.then(|| DetectionInfo {
        name: "cargo".to_owned(),
        version: cargo_version
            .filter(|version| !version.is_empty())
            .map(ToOwned::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

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
    fn detects_cargo_when_rust_manifest_env_exists() {
        assert_eq!(
            detect_cargo_package_manager(true, Some("1.85.0")),
            Some(DetectionInfo {
                name: "cargo".to_owned(),
                version: Some("1.85.0".to_owned()),
            })
        );
    }

    #[test]
    fn detects_null_cargo_version_when_version_env_is_empty() {
        assert_eq!(
            detect_cargo_package_manager(true, Some("")),
            Some(DetectionInfo {
                name: "cargo".to_owned(),
                version: None,
            })
        );
    }

    #[test]
    fn detects_cargo_from_process_env() {
        let _guard = lock_env();
        let _restore = EnvRestore::unset(&["CARGO_MANIFEST_DIR", "CARGO_VERSION"]);
        std::env::set_var("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"));
        std::env::set_var("CARGO_VERSION", "1.85.0");

        assert_eq!(
            detect_package_manager(),
            Some(DetectionInfo {
                name: "cargo".to_owned(),
                version: Some("1.85.0".to_owned()),
            })
        );
    }
}
