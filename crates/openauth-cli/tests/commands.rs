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
    assert!(env.contains("OPENAUTH_SECRET="));
    assert!(env.contains("DATABASE_URL="));
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
