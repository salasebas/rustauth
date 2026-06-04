#![allow(clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[test]
fn init_creates_config_and_env_example() {
    let temp = tempfile::tempdir().expect("tempdir");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "init",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--framework",
            "axum",
            "--adapter",
            "sqlx",
            "--database",
            "sqlite",
            "--base-url",
            "http://localhost:3000/api/auth",
            "--plugins",
            "two-factor,username",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created openauth.toml"));

    let config = fs::read_to_string(temp.path().join("openauth.toml")).expect("config");
    assert!(config.contains("framework = \"axum\""));
    assert!(config.contains("\"two-factor\""));

    let env = fs::read_to_string(temp.path().join(".env.example")).expect("env example");
    assert!(env.contains("OPENAUTH_SECRET=<generate-with-openauth-secret>"));
    assert!(env.contains("DATABASE_URL="));
}

#[test]
fn commands_accept_global_config_path() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = temp.path().join("config").join("auth.toml");
    fs::create_dir_all(config_path.parent().expect("config parent")).expect("mkdir config");
    fs::write(
        &config_path,
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
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--config",
            "config/auth.toml",
            "schema",
            "print",
            "--dialect",
            "sqlite",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CREATE TABLE"));
}

#[test]
fn init_refuses_to_overwrite_existing_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    fs::write(temp.path().join("openauth.toml"), "[project]\n").expect("write config");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "init",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn cargo_openauth_wrapper_drops_cargo_subcommand_name() {
    Command::cargo_bin("cargo-openauth")
        .expect("binary")
        .args(["openauth", "secret", "--check", "short"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret is too short"));
}

#[test]
fn better_auth_alias_runs_the_same_command_tree() {
    Command::cargo_bin("better-auth")
        .expect("binary")
        .args(["secret", "--check", "short"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret is too short"));
}

#[test]
fn open_auth_alias_runs_the_same_command_tree() {
    Command::cargo_bin("open-auth")
        .expect("binary")
        .args(["secret", "--check", "short"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret is too short"));
}

#[test]
fn cargo_better_auth_wrapper_drops_cargo_subcommand_name() {
    Command::cargo_bin("cargo-better-auth")
        .expect("binary")
        .args(["better-auth", "secret", "--check", "short"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret is too short"));
}

#[test]
fn cargo_open_auth_wrapper_drops_cargo_subcommand_name() {
    Command::cargo_bin("cargo-open-auth")
        .expect("binary")
        .args(["open-auth", "secret", "--check", "short"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret is too short"));
}

#[test]
fn compact_betterauth_aliases_work() {
    Command::cargo_bin("betterauth")
        .expect("binary")
        .args(["secret", "--check", "short"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret is too short"));

    Command::cargo_bin("cargo-betterauth")
        .expect("binary")
        .args(["betterauth", "secret", "--check", "short"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret is too short"));
}

#[test]
fn plugins_list_json_exposes_enriched_contract() {
    Command::cargo_bin("openauth")
        .expect("binary")
        .args(["plugins", "list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"official\""))
        .stdout(predicate::str::contains("\"schema_supported\""))
        .stdout(predicate::str::contains("\"snippet_supported\""))
        .stdout(predicate::str::contains("\"migration_impact\""));
}

#[test]
fn generate_emits_debug_telemetry_when_enabled() {
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
enabled = ["username"]
"#,
    )
    .expect("write config");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
            "--output",
            "migrations/openauth/0001_init.sql",
            "--yes",
        ])
        .env("OPENAUTH_TELEMETRY", "true")
        .env("OPENAUTH_TELEMETRY_DEBUG", "true")
        .env(
            "OPENAUTH_TELEMETRY_ENDPOINT",
            "http://telemetry.invalid/collect",
        )
        .env("RUST_ENV", "development")
        .env("TEST", "false")
        .assert()
        .success()
        .stderr(predicate::str::contains("\"type\": \"cli_generate\""))
        .stderr(predicate::str::contains("\"outcome\": \"generated\""))
        .stderr(predicate::str::contains("\"adapter\": \"sqlx\""))
        .stderr(predicate::str::contains("\"database\": \"sqlite\""))
        .stderr(predicate::str::contains("\"plugins\": ["))
        .stderr(predicate::str::contains("\"username\""));
}
