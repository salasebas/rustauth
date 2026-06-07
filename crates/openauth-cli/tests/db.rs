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

fn write_config_with_adapter(
    dir: &std::path::Path,
    adapter: &str,
    provider: &str,
    migrations_dir: &str,
    plugins: &[&str],
) {
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
provider = "{provider}"
url_env = "DATABASE_URL"
migrations_dir = "{migrations_dir}"

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
        .success();

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
            "--yes",
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
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "A migration for this plan already exists",
        ));
}

#[test]
fn generate_output_treats_sql_path_as_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);
    let output = temp.path().join("schema").join("openauth.sql");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
            "--output",
            output.to_str().expect("utf8 path"),
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(output.display().to_string()));

    assert!(output.is_file());
}

#[test]
fn db_status_loads_project_env_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(temp.path(), "sqlx", "sqlite", "migrations/openauth", &[]);
    let database_url = format!("sqlite://{}", temp.path().join("from-env.sqlite").display());
    fs::write(
        temp.path().join(".env"),
        format!("DATABASE_URL={database_url}\n"),
    )
    .expect("write env");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env_remove("DATABASE_URL")
        .assert()
        .success()
        .stdout(predicate::str::contains("Tables to create:"));
}

#[test]
fn sqlite_relative_database_url_resolves_against_project_cwd() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(temp.path(), "sqlx", "sqlite", "migrations/openauth", &[]);
    fs::write(
        temp.path().join(".env"),
        "DATABASE_URL=sqlite://data/auth.sqlite\n",
    )
    .expect("write env");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "migrate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--yes",
        ])
        .env_remove("DATABASE_URL")
        .assert()
        .success();

    assert!(temp.path().join("data/auth.sqlite").is_file());
}

#[test]
fn schema_print_includes_api_key_plugin_schema() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "sqlx",
        "sqlite",
        "migrations/openauth",
        &["api-key"],
    );

    Command::cargo_bin("openauth")
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
        .stdout(predicate::str::contains("api_keys"));
}

#[test]
fn non_sql_adapter_does_not_attempt_sql_migration_checks() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(temp.path(), "memory", "memory", "migrations/openauth", &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "doctor",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--json",
        ])
        .env("DATABASE_URL", "sqlite::memory:")
        .env("OPENAUTH_SECRET", "OpenAuthSecretForCliTests-1234567890!")
        .assert()
        .success()
        .stdout(predicate::str::contains("database.migrations_unsupported"))
        .stdout(predicate::str::contains("database.connection").not());
}

#[test]
fn output_dir_flag_writes_generated_migration_to_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);
    let output_dir = temp.path().join("custom-migrations");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
            "--output-dir",
            output_dir.to_str().expect("utf8 path"),
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated migration:"));

    let entries = fs::read_dir(output_dir).expect("read output dir").count();
    assert_eq!(entries, 1);
}

#[test]
fn generate_adapter_and_dialect_writes_sql_without_config_or_database_url() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("schema.sql");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--adapter",
            "kysely",
            "--dialect",
            "postgresql",
            "--output",
            output.to_str().expect("utf8 path"),
            "--yes",
        ])
        .env_remove("DATABASE_URL")
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated migration:"));

    let sql = fs::read_to_string(output).expect("generated sql");
    assert!(sql.contains("-- dialect: postgres"));
    assert!(sql.contains(r#"CREATE TABLE IF NOT EXISTS "users""#));
}

#[test]
fn generate_sqlx_adapter_and_dialect_writes_sql_without_config_or_database_url() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("schema.sql");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--adapter",
            "sqlx",
            "--dialect",
            "sqlite",
            "--output",
            output.to_str().expect("utf8 path"),
            "--yes",
        ])
        .env_remove("DATABASE_URL")
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated migration:"));

    let sql = fs::read_to_string(output).expect("generated sql");
    assert!(sql.contains("-- dialect: sqlite"));
    assert!(sql.contains(r#"CREATE TABLE IF NOT EXISTS "users""#));
}

#[test]
fn generate_unsupported_orm_adapter_without_config_prints_guidance() {
    let temp = tempfile::tempdir().expect("tempdir");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--adapter",
            "drizzle",
            "--dialect",
            "sqlite",
            "--yes",
        ])
        .env_remove("DATABASE_URL")
        .assert()
        .code(0)
        .stderr(predicate::str::contains("Drizzle"));
}

/// OPE-118: non-interactive runs must not write schema artifacts without `--yes`.
#[test]
fn non_interactive_generate_without_yes_fails_without_writing_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);
    let migrations_dir = temp.path().join("migrations/openauth");

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "db",
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--yes"));

    assert!(
        !migrations_dir.exists()
            || fs::read_dir(&migrations_dir)
                .map(|entries| entries.count())
                .unwrap_or(0)
                == 0
    );
}

/// OPE-118: non-interactive runs must not apply migrations without `--yes`.
#[test]
fn non_interactive_migrate_without_yes_fails_without_applying() {
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
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--yes"));

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
fn non_interactive_db_commands_succeed_with_yes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--from-empty",
            "--yes",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Generated migration:"));

    Command::cargo_bin("openauth")
        .expect("binary")
        .args([
            "migrate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--yes",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Migration completed successfully"));

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
        .success();
}

#[test]
#[ignore = "requires docker compose postgres service"]
fn postgres_status_and_migrate_work_against_docker_compose() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "sqlx",
        "postgres",
        "migrations/openauth",
        &["api-key"],
    );
    let database_url = std::env::var("OPENAUTH_CLI_TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost:5432/openauth".to_owned());

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
        .success();

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
        .success();
}

#[test]
#[ignore = "requires docker compose mysql service"]
fn mysql_status_and_migrate_work_against_docker_compose() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "sqlx",
        "mysql",
        "migrations/openauth",
        &["api-key"],
    );
    let database_url = std::env::var("OPENAUTH_CLI_TEST_MYSQL_URL")
        .unwrap_or_else(|_| "mysql://user:password@localhost:3306/openauth".to_owned());

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
        .success();

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
        .success();
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
