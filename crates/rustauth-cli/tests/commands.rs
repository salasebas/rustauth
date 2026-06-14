#![allow(clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[test]
fn init_creates_config_and_env_example() {
    let temp = tempfile::tempdir().expect("tempdir");

    Command::cargo_bin("rustauth")
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
        .stdout(predicate::str::contains("Created rustauth.toml"));
    // init writes the resolved default config path (rustauth.toml)
    assert!(temp.path().join("rustauth.toml").exists());

    let config = fs::read_to_string(temp.path().join("rustauth.toml")).expect("config");
    assert!(config.contains("framework = \"axum\""));
    assert!(config.contains("\"two-factor\""));
    assert!(config.contains("migrations_dir = \"migrations/rustauth\""));
    assert!(config.contains("secret_env = \"RUSTAUTH_SECRET\""));

    let env = fs::read_to_string(temp.path().join(".env.example")).expect("env example");
    assert!(env.contains("RUSTAUTH_SECRET=<generate-with-rustauth-secret>"));
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
    fs::write(temp.path().join("rustauth.toml"), "[project]\n").expect("write config");

    Command::cargo_bin("rustauth")
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
fn cargo_rustauth_wrapper_drops_cargo_subcommand_name() {
    Command::cargo_bin("cargo-rustauth")
        .expect("binary")
        .args(["rustauth", "secret", "--check", "short"])
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
fn rust_auth_alias_runs_the_same_command_tree() {
    Command::cargo_bin("rust-auth")
        .expect("binary")
        .args(["secret", "--check", "short"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Secret is too short"));
}

#[test]
fn cargo_rust_auth_wrapper_drops_cargo_subcommand_name() {
    Command::cargo_bin("cargo-rust-auth")
        .expect("binary")
        .args(["rust-auth", "secret", "--check", "short"])
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
    Command::cargo_bin("rustauth")
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
#[cfg(all(feature = "sqlx", feature = "telemetry"))]
fn generate_emits_debug_telemetry_when_enabled() {
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
enabled = ["username"]
"#,
    )
    .expect("write config");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
            "--output",
            "migrations/rustauth/0001_init.sql",
            "--yes",
        ])
        .env("RUSTAUTH_TELEMETRY", "true")
        .env("RUSTAUTH_TELEMETRY_DEBUG", "true")
        .env(
            "RUSTAUTH_TELEMETRY_ENDPOINT",
            "http://telemetry.invalid/collect",
        )
        .env("RUST_ENV", "development")
        .env("TEST", "false")
        .env("RUSTAUTH_SECRET_FOR_TEST", "super-secret-value-12345")
        .env(
            "DATABASE_URL",
            format!("sqlite://{}/auth.sqlite", temp.path().display()),
        )
        .assert()
        .success()
        .stderr(predicate::str::contains("\"type\": \"init\""))
        .stderr(predicate::str::contains("\"type\": \"cli_generate\""))
        .stderr(predicate::str::contains("\"outcome\": \"generated\""))
        .stderr(predicate::str::contains("\"adapter\": \"sqlx\""))
        .stderr(predicate::str::contains("\"database\": \"sqlite\""))
        .stderr(predicate::str::contains("\"plugins\": ["))
        .stderr(predicate::str::contains("\"username\""))
        .stderr(predicate::str::contains("http://localhost:3000/api/auth").not())
        .stderr(predicate::str::contains("super-secret-value-12345").not())
        .stderr(predicate::str::contains("RUSTAUTH_SECRET_FOR_TEST").not())
        .stderr(predicate::str::contains("sqlite://").not());
}
