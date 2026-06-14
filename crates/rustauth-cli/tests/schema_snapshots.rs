#![allow(clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn write_config(dir: &std::path::Path, plugins: &[&str]) {
    let plugins = plugins
        .iter()
        .map(|plugin| format!("\"{plugin}\""))
        .collect::<Vec<_>>()
        .join(", ");
    fs::write(
        dir.join("rustauth.toml"),
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
migrations_dir = "migrations/rustauth"

[security]
secret_env = "RUSTAUTH_SECRET"

[plugins]
enabled = [{plugins}]
"#
        ),
    )
    .expect("write config");
}

#[test]
fn schema_print_sqlite_matches_base_snapshot() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config(temp.path(), &[]);

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "schema",
            "print",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--dialect",
            "sqlite",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            r#"CREATE TABLE IF NOT EXISTS "users""#,
        ))
        .stdout(predicate::str::contains(
            r#"CREATE INDEX IF NOT EXISTS "idx_sessions_user_id""#,
        ));
}

#[test]
fn schema_print_postgres_matches_base_snapshot() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config(temp.path(), &[]);

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "schema",
            "print",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--dialect",
            "postgres",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            r#"CREATE TABLE IF NOT EXISTS "users""#,
        ))
        .stdout(predicate::str::contains(
            r#""email_verified" BOOLEAN NOT NULL"#,
        ));
}

#[test]
fn schema_print_mysql_matches_base_snapshot() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config(temp.path(), &[]);

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "schema",
            "print",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--dialect",
            "mysql",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            r#"CREATE TABLE IF NOT EXISTS `users`"#,
        ))
        .stdout(predicate::str::contains(
            r#"`email_verified` BOOLEAN NOT NULL"#,
        ));
}

#[test]
#[cfg(feature = "plugins")]
fn schema_print_plugin_snapshot_includes_schema_plugin_tables() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config(temp.path(), &["api-key", "organization"]);

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "schema",
            "print",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--dialect",
            "sqlite",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("api_keys"))
        .stdout(predicate::str::contains("organizations"));
}
