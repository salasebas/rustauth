#![allow(clippy::expect_used)]

//! Exercises the README quick start in an empty directory (no rustauth.toml).
//! See OPE-51: config-free commands must work, and `doctor` must degrade
//! gracefully instead of hard-erroring on a missing config.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

const STRONG_SECRET: &str = "Str0ng-Secret-Value-For-Tests-1234567890";

fn rustauth(cwd: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("rustauth").expect("binary");
    command.args(["--cwd", cwd.to_str().expect("utf8 path")]);
    command
}

#[test]
fn config_free_quick_start_commands_succeed_without_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    assert!(!temp.path().join("rustauth.toml").exists());

    rustauth(temp.path())
        .args(["secret", "--bytes", "32"])
        .assert()
        .success();

    rustauth(temp.path())
        .args(["plugins", "list"])
        .assert()
        .success();

    rustauth(temp.path())
        .args(["schema", "print", "--dialect", "sqlite"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            r#"CREATE TABLE IF NOT EXISTS "users""#,
        ));
}

#[test]
fn doctor_degrades_without_config_instead_of_hard_erroring() {
    let temp = tempfile::tempdir().expect("tempdir");

    rustauth(temp.path())
        .arg("doctor")
        .env("RUSTAUTH_SECRET", STRONG_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("config.missing"))
        .stdout(predicate::str::contains("No RustAuth CLI config found").not());
}

#[test]
fn readme_documents_init_env_side_effects() {
    let readme =
        fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).expect("readme");

    for phrase in [
        "syncs `.env.example`",
        "creates or updates",
        "`.env` in the current directory",
        "Missing keys are merged in without overwriting",
        "--seed-secrets",
        "rustauth init                # rustauth.toml + .env.example + .env",
    ] {
        assert!(
            readme.contains(phrase),
            "README quick start should document init env side effects; missing `{phrase}`"
        );
    }
}

#[test]
fn init_unlocks_the_config_bound_workflow() {
    let temp = tempfile::tempdir().expect("tempdir");

    rustauth(temp.path())
        .args(["init", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created rustauth.toml"));
    assert!(temp.path().join("rustauth.toml").exists());

    rustauth(temp.path())
        .arg("doctor")
        .env("RUSTAUTH_SECRET", STRONG_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("config.loaded"));
}
