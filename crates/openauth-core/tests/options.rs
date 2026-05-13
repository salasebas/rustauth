use openauth_core::context::{AuthEnvironment, SecretMaterial};
use openauth_core::crypto::{SecretConfig, SecretEntry};
use openauth_core::options::{ExperimentalOptions, OpenAuthOptions};

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
        better_auth_secret: Some("better-auth-secret-should-not-appear".to_owned()),
        auth_secret: Some("auth-secret-should-not-appear".to_owned()),
        better_auth_secrets: Some("1:rotating-env-secret-should-not-appear".to_owned()),
    };

    let output = format!("{environment:?}");

    assert!(!output.contains("better-auth-secret-should-not-appear"));
    assert!(!output.contains("auth-secret-should-not-appear"));
    assert!(!output.contains("rotating-env-secret-should-not-appear"));
}

#[test]
fn experimental_joins_default_to_disabled_and_can_be_enabled() {
    assert!(!OpenAuthOptions::default().experimental.joins);

    let options = OpenAuthOptions {
        experimental: ExperimentalOptions { joins: true },
        ..OpenAuthOptions::default()
    };

    assert!(options.experimental.joins);
    assert!(format!("{options:?}").contains("experimental"));
}
