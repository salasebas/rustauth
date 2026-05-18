#![allow(clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn write_config(dir: &std::path::Path, database_url: &str, plugins: &[&str]) {
    let plugins = plugins
        .iter()
        .map(|plugin| format!("\"{plugin}\""))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        dir.join("openauth.toml"),
        format!(
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
secret_env = "OPENAUTH_SECRET"

[plugins]
enabled = [{plugins}]
"#
        ),
    )
    .expect("write config");
    fs::write(
        dir.join(".env.example"),
        format!("DATABASE_URL={database_url}\n"),
    )
    .expect("write env example");
}

#[test]
fn sqlite_status_migrate_and_second_status_are_consistent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Tables to create:"));

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "migrate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--yes",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Migration completed successfully.",
        ));

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--check",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Tables to create: 0"));
}

#[test]
fn generate_does_not_duplicate_same_plan_hash() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated migration:"));

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "A migration for this plan already exists",
        ));
}

#[test]
fn adding_schema_plugin_updates_config_and_reports_database_impact() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "plugins",
            "add",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "two-factor",
            "--yes",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("changes the database schema"));

    let config = fs::read_to_string(temp.path().join("openauth.toml")).expect("config");
    assert!(config.contains("\"two-factor\""));
}
