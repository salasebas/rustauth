#![allow(clippy::expect_used)]

//! Exercises the README quick start in an empty directory (no openauth.toml).
//! See OPE-51: config-free commands must work, and `doctor` must degrade
//! gracefully instead of hard-erroring on a missing config.

use assert_cmd::Command;
use predicates::prelude::*;

const STRONG_SECRET: &str = "Str0ng-Secret-Value-For-Tests-1234567890";

fn openauth(cwd: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("openauth").expect("binary");
    command.args(["--cwd", cwd.to_str().expect("utf8 path")]);
    command
}

#[test]
fn config_free_quick_start_commands_succeed_without_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    assert!(!temp.path().join("openauth.toml").exists());

    openauth(temp.path())
        .args(["secret", "--bytes", "32"])
        .assert()
        .success();

    openauth(temp.path())
        .args(["plugins", "list"])
        .assert()
        .success();

    openauth(temp.path())
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

    openauth(temp.path())
        .arg("doctor")
        .env("OPENAUTH_SECRET", STRONG_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("config.missing"))
        .stdout(predicate::str::contains("No OpenAuth CLI config found").not());
}

#[test]
fn init_unlocks_the_config_bound_workflow() {
    let temp = tempfile::tempdir().expect("tempdir");

    openauth(temp.path())
        .args(["init", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Created openauth.toml"));

    openauth(temp.path())
        .arg("doctor")
        .env("OPENAUTH_SECRET", STRONG_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("config.loaded"));
}
