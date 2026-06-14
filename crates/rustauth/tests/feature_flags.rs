#![allow(clippy::expect_used)]

use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_manifest(relative: &str) -> String {
    std::fs::read_to_string(manifest_dir().join(relative)).expect("failed to read manifest")
}

fn feature_line(manifest: &str, feature: &str) -> String {
    manifest
        .lines()
        .find(|line| line.trim_start().starts_with(&format!("{feature} =")))
        .expect("feature not found in manifest")
        .to_owned()
}

#[test]
fn sqlx_postgres_feature_does_not_enable_sqlite_driver() {
    let rustauth = read_manifest("Cargo.toml");
    let sqlx_postgres = feature_line(&rustauth, "sqlx-postgres");
    assert!(sqlx_postgres.contains("rustauth-sqlx/postgres"));
    assert!(!sqlx_postgres.contains("sqlite"));

    let sqlx_manifest = read_manifest("../rustauth-sqlx/Cargo.toml");
    let postgres = feature_line(&sqlx_manifest, "postgres");
    assert!(!postgres.contains("sqlite"));
}

#[test]
fn telemetry_feature_declares_oauth_on_telemetry_crate() {
    let contents = read_manifest("Cargo.toml");
    assert!(
        contents.contains("\"rustauth-telemetry/oauth\""),
        "telemetry feature should enable rustauth-telemetry/oauth for social-provider snapshots"
    );
}

#[test]
fn default_rustauth_build_does_not_enable_telemetry_crate() {
    let contents = read_manifest("Cargo.toml");
    assert!(
        contents.contains("default = []"),
        "rustauth should ship with no default features"
    );
    assert!(
        contents.contains("rustauth-telemetry = { workspace = true")
            && contents.contains("optional = true"),
        "telemetry must remain an optional dependency"
    );
}

#[test]
fn async_initializers_available_without_telemetry_feature() {
    let contents = read_manifest("Cargo.toml");
    assert!(
        contents.contains("default = []"),
        "async init without telemetry is supported when the telemetry feature is off"
    );
    assert!(
        !contents.contains("default = [\"telemetry\"]"),
        "telemetry must not be enabled by default"
    );
    // Runtime smoke: `public_api::async_init_without_telemetry_feature`.
}

#[test]
fn core_dependency_does_not_force_default_feature_alias() {
    let contents = read_manifest("Cargo.toml");
    assert!(
        !contents.contains("features = [\"default\"]"),
        "rustauth must not enable rustauth-core via features = [\"default\"]"
    );
}

#[test]
fn rustauth_forwards_oauth_features() {
    let contents = read_manifest("Cargo.toml");
    for feature in ["jose =", "oauth =", "social-providers =", "full ="] {
        assert!(
            contents.contains(feature),
            "missing forwarded feature declaration: {feature}"
        );
    }
}

#[test]
fn oidc_feature_does_not_enable_saml_or_xml_dependencies() {
    let rustauth = read_manifest("Cargo.toml");
    let oidc = feature_line(&rustauth, "oidc");
    for forbidden in ["rustauth-saml", "saml", "quick-xml", "x509-parser"] {
        assert!(
            !oidc.contains(forbidden),
            "OIDC-only feature unexpectedly references {forbidden}: {oidc}"
        );
    }
}
