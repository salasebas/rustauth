#![allow(clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use rustauth_cli::secret::{assess_secret, generate_secret, SecretSeverity};

#[test]
fn generated_secret_passes_strength_check() {
    let secret = generate_secret(32);
    let assessment = assess_secret(&secret, true);

    assert_eq!(assessment.severity, SecretSeverity::Ok);
}

#[test]
fn weak_secret_is_rejected_for_production() {
    let assessment = assess_secret("secret-a-at-least-32-chars-long!!", true);

    assert_eq!(assessment.severity, SecretSeverity::Error);
}

#[test]
fn secret_env_line_uses_rustauth_secret_key() {
    Command::cargo_bin("rustauth")
        .expect("binary")
        .args(["secret", "--env-line"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("RUSTAUTH_SECRET="));
}

#[test]
fn secret_check_env_reports_missing_variable_name() {
    Command::cargo_bin("rustauth")
        .expect("binary")
        .args(["secret", "--check-env", "RUSTAUTH_SECRET_MISSING_FOR_TEST"])
        .env_remove("RUSTAUTH_SECRET_MISSING_FOR_TEST")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "RUSTAUTH_SECRET_MISSING_FOR_TEST is not set",
        ));
}
