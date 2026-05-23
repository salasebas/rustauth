#![allow(clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[test]
fn doctor_reports_missing_production_secret_as_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("openauth.toml"),
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
migrations_dir = "migrations/openauth"

[security]
secret_env = "OPENAUTH_SECRET_FOR_TEST"

[plugins]
enabled = []
"#,
    )
    .expect("write config");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "doctor",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--production",
        ])
        .env_remove("OPENAUTH_SECRET_FOR_TEST")
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .failure()
        .stdout(predicate::str::contains("[ERROR] security.secret"));
}

#[test]
fn info_json_redacts_sensitive_values() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("openauth.toml"),
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
migrations_dir = "migrations/openauth"

[security]
secret_env = "OPENAUTH_SECRET_FOR_TEST"

[plugins]
enabled = []
"#,
    )
    .expect("write config");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "info",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--json",
        ])
        .env(
            "OPENAUTH_SECRET_FOR_TEST",
            "super-secret-value-that-should-not-appear",
        )
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .success()
        .stdout(predicate::str::contains("[REDACTED]"))
        .stdout(predicate::str::contains("normalized_provider"))
        .stdout(predicate::str::contains("openauth_version"))
        .stdout(predicate::str::contains("super-secret-value").not());
}
