use openauth_core::context::{AuthEnvironment, SecretMaterial};
use openauth_core::crypto::{SecretConfig, SecretEntry};
use openauth_core::env::{allows_development_defaults, is_production, is_production_posture};
use openauth_core::options::{EmailPasswordOptions, ExperimentalOptions, OpenAuthOptions};
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
fn openauth_options_debug_redacts_secret_material() {
    let options = OpenAuthOptions {
        secret: Some("legacy-secret-should-not-appear".to_owned()),
        secrets: vec![SecretEntry {
            version: 1,
            value: "rotating-secret-should-not-appear".to_owned(),
        }],
        ..OpenAuthOptions::default()
    };

    let output = format!("{options:?}");

    assert!(output.contains("<redacted>"));
    assert!(!output.contains("legacy-secret-should-not-appear"));
    assert!(!output.contains("rotating-secret-should-not-appear"));
}

#[test]
fn secret_rotation_debug_redacts_secret_material() {
    let entry = SecretEntry {
        version: 1,
        value: "entry-secret-should-not-appear".to_owned(),
    };
    let config = SecretConfig::new([(1, "config-secret-should-not-appear")])
        .with_legacy_secret("legacy-rotation-secret-should-not-appear");
    let material = SecretMaterial::Rotating(config.clone());

    let entry_output = format!("{entry:?}");
    let config_output = format!("{config:?}");
    let material_output = format!("{material:?}");

    assert!(!entry_output.contains("entry-secret-should-not-appear"));
    assert!(!config_output.contains("config-secret-should-not-appear"));
    assert!(!config_output.contains("legacy-rotation-secret-should-not-appear"));
    assert!(!material_output.contains("config-secret-should-not-appear"));
    assert!(!material_output.contains("legacy-rotation-secret-should-not-appear"));
}

#[test]
fn auth_environment_debug_redacts_secret_material() {
    let environment = AuthEnvironment {
        openauth_secret: Some("openauth-secret-should-not-appear".to_owned()),
        openauth_secrets: Some("1:rotating-env-secret-should-not-appear".to_owned()),
    };

    let output = format!("{environment:?}");

    assert!(!output.contains("openauth-secret-should-not-appear"));
    assert!(!output.contains("rotating-env-secret-should-not-appear"));
}

#[test]
fn auth_environment_from_process_is_empty_when_secret_env_is_unset() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["OPENAUTH_SECRET", "OPENAUTH_SECRETS"]);

    assert_eq!(AuthEnvironment::from_process(), AuthEnvironment::default());
}

#[test]
fn auth_environment_from_process_reads_mocked_secret_env() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["OPENAUTH_SECRET", "OPENAUTH_SECRETS"]);
    std::env::set_var("OPENAUTH_SECRET", "openauth-secret");
    std::env::set_var("OPENAUTH_SECRETS", "2:next,1:prev");

    assert_eq!(
        AuthEnvironment::from_process(),
        AuthEnvironment {
            openauth_secret: Some("openauth-secret".to_owned()),
            openauth_secrets: Some("2:next,1:prev".to_owned()),
        }
    );
}

#[test]
fn is_production_is_false_when_rust_env_is_unset() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV"]);

    assert!(!is_production());
}

#[test]
fn is_production_only_accepts_exact_production_rust_env() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    std::env::set_var("RUST_ENV", "development");
    assert!(!is_production());

    std::env::set_var("RUST_ENV", "production");
    assert!(is_production());
}

#[test]
fn ambiguous_deployment_fails_closed_without_explicit_development() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    let options = OpenAuthOptions::default();
    assert!(is_production_posture(&options));
    assert!(!allows_development_defaults(&options));
}

#[test]
fn explicit_development_option_allows_development_defaults() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    let options = OpenAuthOptions::default().development(true);
    assert!(!is_production_posture(&options));
    assert!(allows_development_defaults(&options));
}

#[test]
fn production_option_overrides_development_flag() {
    let _guard = lock_env();
    let _restore = EnvRestore::unset(&["RUST_ENV", "RUST_TEST_THREADS", "TEST", "NEXTEST"]);

    let options = OpenAuthOptions::default()
        .development(true)
        .production(true);
    assert!(is_production_posture(&options));
    assert!(!allows_development_defaults(&options));
}

#[test]
fn email_password_is_disabled_by_default_until_explicitly_opted_in() {
    assert!(!EmailPasswordOptions::default().enabled);
    assert!(!OpenAuthOptions::default().email_password.enabled);
}

#[test]
fn experimental_joins_default_to_enabled_and_can_be_disabled() {
    assert!(OpenAuthOptions::default().experimental.joins);

    let options = OpenAuthOptions {
        experimental: ExperimentalOptions { joins: false },
        ..OpenAuthOptions::default()
    };

    assert!(!options.experimental.joins);
    assert!(format!("{options:?}").contains("experimental"));
}
