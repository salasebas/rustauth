#![allow(clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;

#[cfg(feature = "deadpool-postgres")]
fn write_minimal_cargo_project(dir: &Path) {
    fs::create_dir_all(dir.join("src")).expect("create src dir");
    fs::write(
        dir.join("Cargo.toml"),
        r#"
[package]
name = "rustauth-doctor-test"
version = "0.1.0"
edition = "2021"

[dependencies]
"#,
    )
    .expect("write Cargo.toml");
    fs::write(dir.join("src/main.rs"), "fn main() {}\n").expect("write main.rs");
}

#[test]
fn doctor_reports_missing_production_secret_as_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("rustauth.toml"),
        r#"
[project]
framework = "axum"
base_url = "https://app.example.com/api/auth"
base_path = "/api/auth"
production = true

[database]
adapter = "sqlx"
provider = "sqlite"
url_env = "DATABASE_URL"
migrations_dir = "migrations/rustauth"

[security]
secret_env = "RUSTAUTH_SECRET_FOR_TEST"

[plugins]
enabled = []
"#,
    )
    .expect("write config");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "doctor",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--production",
        ])
        .env_remove("RUSTAUTH_SECRET_FOR_TEST")
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .failure()
        .stdout(predicate::str::contains("[ERROR] security.secret"));
}

#[test]
fn info_json_redacts_sensitive_values() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("rustauth.toml"),
        r#"
[project]
framework = "axum"
base_url = "http://localhost:3000/api/auth"
base_path = "/api/auth"
production = false

[database]
adapter = "sqlx"
provider = "sqlite"
url_env = "DATABASE_URL"
migrations_dir = "migrations/rustauth"

[security]
secret_env = "RUSTAUTH_SECRET_FOR_TEST"

[plugins]
enabled = []
"#,
    )
    .expect("write config");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "info",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--json",
        ])
        .env(
            "RUSTAUTH_SECRET_FOR_TEST",
            "super-secret-value-that-should-not-appear",
        )
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .success()
        .stdout(predicate::str::contains("[REDACTED]"))
        .stdout(predicate::str::contains("normalized_provider"))
        .stdout(predicate::str::contains("rustauth_version"))
        .stdout(predicate::str::contains("super-secret-value").not());
}

#[test]
#[cfg(feature = "deadpool-postgres")]
fn doctor_deadpool_postgres_adapter_without_dependency_reports_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_minimal_cargo_project(temp.path());
    fs::write(
        temp.path().join("rustauth.toml"),
        r#"
[project]
framework = "axum"
base_url = "http://localhost:3000/api/auth"
base_path = "/api/auth"
production = false

[database]
adapter = "deadpool-postgres"
provider = "postgres"
url_env = "DATABASE_URL"
migrations_dir = "migrations/rustauth"

[security]
secret_env = "RUSTAUTH_SECRET"

[plugins]
enabled = []
"#,
    )
    .expect("write config");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "doctor",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--json",
        ])
        .env_remove("DATABASE_URL")
        .env("RUSTAUTH_SECRET", "RustAuthSecretForCliTests-1234567890!")
        .assert()
        .failure()
        .stdout(predicate::str::contains("database.adapter_mismatch"))
        .stdout(predicate::str::contains("rustauth-deadpool-postgres"));
}

#[test]
fn doctor_magic_link_plugin_does_not_report_cli_feature_disabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("rustauth.toml"),
        r#"
[project]
framework = "axum"
base_url = "http://localhost:3000/api/auth"
base_path = "/api/auth"
production = false

[database]
adapter = "sqlx"
provider = "sqlite"
url_env = "DATABASE_URL"
migrations_dir = "migrations/rustauth"

[security]
secret_env = "RUSTAUTH_SECRET"

[plugins]
enabled = ["magic-link"]
"#,
    )
    .expect("write config");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "doctor",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--json",
        ])
        .env("RUSTAUTH_SECRET", "RustAuthSecretForCliTests-1234567890!")
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .success()
        .stdout(predicate::str::contains("plugins.cli_feature_disabled").not());
}

#[test]
#[cfg(not(feature = "passkey"))]
fn doctor_passkey_without_cli_feature_reports_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("rustauth.toml"),
        r#"
[project]
framework = "axum"
base_url = "http://localhost:3000/api/auth"
base_path = "/api/auth"
production = false

[database]
adapter = "sqlx"
provider = "sqlite"
url_env = "DATABASE_URL"
migrations_dir = "migrations/rustauth"

[security]
secret_env = "RUSTAUTH_SECRET"

[plugins]
enabled = ["passkey"]
"#,
    )
    .expect("write config");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "doctor",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--json",
        ])
        .env("RUSTAUTH_SECRET", "RustAuthSecretForCliTests-1234567890!")
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .failure()
        .stdout(predicate::str::contains("plugins.cli_feature_disabled"));
}
