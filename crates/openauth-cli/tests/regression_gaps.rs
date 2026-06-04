#![allow(clippy::expect_used)]

use assert_cmd::Command;
use openauth_cli::secret::{assess_secret, SecretSeverity};
use predicates::prelude::*;
use std::fs;

fn write_sqlite_config(dir: &std::path::Path, adapter: &str, plugins: &[&str]) {
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
adapter = "{adapter}"
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
}

#[test]
fn migrate_dry_run_does_not_apply_changes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_sqlite_config(temp.path(), "sqlx", &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
            "--yes",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "migrate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--dry-run",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run complete"))
        .stderr(predicate::str::contains("\"outcome\": \"dry_run\"").not());

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
        .failure();
}

#[test]
fn generate_force_overwrites_duplicate_plan() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_sqlite_config(temp.path(), "sqlx", &[]);

    for _ in 0..2 {
        Command::cargo_bin("openauth")
            .expect("binary")
            .args([
                "db",
                "generate",
                "--cwd",
                temp.path().to_str().expect("utf8 path"),
                "--from-empty",
                "--force",
                "--yes",
            ])
            .env("DATABASE_URL", &database_url)
            .assert()
            .success()
            .stdout(predicate::str::contains("Generated migration:"));
    }
}

#[test]
fn doctor_strict_fails_on_warnings() {
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
secret_env = "OPENAUTH_SECRET"

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
            "--strict",
        ])
        .env_remove("OPENAUTH_SECRET")
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .failure()
        .stdout(predicate::str::contains("[WARN]"));
}

#[test]
fn plugins_remove_updates_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlx", &["username"]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "plugins",
            "remove",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "username",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "does not generate destructive migrations",
        ));

    let config = fs::read_to_string(temp.path().join("openauth.toml")).expect("config");
    assert!(!config.contains("\"username\""));
}

#[test]
fn schema_print_json_format() {
    Command::cargo_bin("openauth")
        .expect("binary")
        .args(["schema", "print", "--format", "json", "--dialect", "sqlite"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"tables\""));
}

#[test]
fn completions_prints_script_for_bash() {
    Command::cargo_bin("openauth")
        .expect("binary")
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("openauth"));
}

#[test]
fn init_force_overwrites_existing_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(
        temp.path().join("openauth.toml"),
        "[project]\nframework = \"actix-web\"\n",
    )
    .expect("write config");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "init",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--force",
            "--yes",
        ])
        .assert()
        .success();

    let config = fs::read_to_string(temp.path().join("openauth.toml")).expect("config");
    assert!(config.contains("framework = \"axum\""));
}

#[test]
fn init_creates_env_when_missing() {
    let temp = tempfile::tempdir().expect("tempdir");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "init",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--yes",
        ])
        .assert()
        .success();

    let env = fs::read_to_string(temp.path().join(".env")).expect(".env");
    assert!(env.contains("OPENAUTH_SECRET="));
    assert!(env.contains("DATABASE_URL="));
}

#[test]
fn secret_check_dev_mode_allows_development_placeholder() {
    let assessment = assess_secret("openauth-secret-123456789012345678901", false);
    assert_eq!(assessment.severity, SecretSeverity::Ok);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "secret",
            "--check",
            "openauth-secret-123456789012345678901",
            "--dev",
        ])
        .assert()
        .success();
}

#[test]
fn migrate_unsupported_prisma_adapter_exits_successfully() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "prisma", &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "migrate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .code(0)
        .stderr(predicate::str::contains("sqlx adapter"));
}

#[test]
fn migrate_unsupported_adapter_emits_telemetry_when_debug_enabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "memory", &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "migrate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env("OPENAUTH_TELEMETRY", "true")
        .env("OPENAUTH_TELEMETRY_DEBUG", "true")
        .env(
            "OPENAUTH_TELEMETRY_ENDPOINT",
            "http://telemetry.invalid/collect",
        )
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .code(0)
        .stderr(predicate::str::contains("\"type\": \"cli_migrate\""))
        .stderr(predicate::str::contains(
            "\"outcome\": \"unsupported_adapter\"",
        ));
}

#[test]
fn env_local_is_loaded_without_overriding_existing_variables() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlx", &[]);
    fs::write(
        temp.path().join(".env.local"),
        "DATABASE_URL=sqlite://from-local.sqlite\n",
    )
    .expect("write env local");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env("DATABASE_URL", "sqlite://from-process.sqlite")
        .assert()
        .success();

    assert!(!temp.path().join("from-local.sqlite").exists());
}

#[test]
fn global_cwd_short_flag_is_equivalent_to_long_flag() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlx", &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "-c",
            temp.path().to_str().expect("utf8 path"),
            "plugins",
            "list",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"id\": \"username\""));
}

#[test]
fn info_json_includes_cli_version() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlx", &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "info",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"cli_version\""))
        .stdout(predicate::str::contains("\"config_loaded\": true"));
}

#[test]
fn init_seed_secrets_writes_generated_secret_to_new_env() {
    let temp = tempfile::tempdir().expect("tempdir");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "init",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--yes",
            "--seed-secrets",
        ])
        .assert()
        .success();

    let example = fs::read_to_string(temp.path().join(".env.example")).expect("example");
    assert!(example.contains("OPENAUTH_SECRET=<generate-with-openauth-secret>"));

    let env = fs::read_to_string(temp.path().join(".env")).expect("env");
    let secret_line = env
        .lines()
        .find(|line| line.starts_with("OPENAUTH_SECRET="))
        .expect("secret line");
    let secret = secret_line.trim_start_matches("OPENAUTH_SECRET=");
    assert!(!secret.is_empty());
    assert_ne!(secret, "<generate-with-openauth-secret>");
}

#[test]
fn plugins_add_requires_existing_config() {
    let temp = tempfile::tempdir().expect("tempdir");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "plugins",
            "add",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "username",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("openauth init"));
}
