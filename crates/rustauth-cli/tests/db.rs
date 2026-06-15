#![allow(clippy::expect_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_config(dir: &std::path::Path, database_url: &str, plugins: &[&str]) {
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
        dir.join("rustauth.toml"),
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
secret_env = "RUSTAUTH_SECRET"

[plugins]
enabled = [{plugins}]
"#
        ),
    )
    .expect("write config");
}

fn isolated_postgres_database_url(test_name: &str) -> String {
    let database_url = std::env::var("RUSTAUTH_CLI_TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost:5432/rustauth".to_owned());
    let schema = unique_postgres_schema(test_name);
    create_postgres_schema(&database_url, &schema);

    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}options=-c%20search_path%3D{schema}")
}

fn unique_postgres_schema(test_name: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    let test_name = test_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();

    format!("oa_cli_{test_name}_{}_{}", std::process::id(), timestamp)
}

fn create_postgres_schema(database_url: &str, schema: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    runtime.block_on(async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await
            .expect("connect postgres for isolated CLI test schema");
        sqlx::query(&format!(r#"DROP SCHEMA IF EXISTS "{schema}" CASCADE"#))
            .execute(&pool)
            .await
            .expect("drop isolated CLI test schema");
        sqlx::query(&format!(r#"CREATE SCHEMA "{schema}""#))
            .execute(&pool)
            .await
            .expect("create isolated CLI test schema");
        pool.close().await;
    });
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_status_migrate_and_second_status_are_consistent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn generate_does_not_duplicate_same_plan_hash() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn generate_output_treats_sql_path_as_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);
    let output = temp.path().join("schema").join("rustauth.sql");

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn db_status_loads_project_env_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(temp.path(), "sqlx", "sqlite", "migrations/rustauth", &[]);
    let database_url = format!("sqlite://{}", temp.path().join("from-env.sqlite").display());
    fs::write(
        temp.path().join(".env"),
        format!("DATABASE_URL={database_url}\n"),
    )
    .expect("write env");

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn sqlite_relative_database_url_resolves_against_project_cwd() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(temp.path(), "sqlx", "sqlite", "migrations/rustauth", &[]);
    fs::write(
        temp.path().join(".env"),
        "DATABASE_URL=sqlite://data/auth.sqlite\n",
    )
    .expect("write env");

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "plugins")]
fn schema_print_includes_api_key_plugin_schema() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "sqlx",
        "sqlite",
        "migrations/rustauth",
        &["api-key"],
    );

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
        .stdout(predicate::str::contains("api_keys"));
}

#[test]
fn non_sql_adapter_does_not_attempt_sql_migration_checks() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(temp.path(), "memory", "memory", "migrations/rustauth", &[]);

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "doctor",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--json",
        ])
        .env("DATABASE_URL", "sqlite::memory:")
        .env("RUSTAUTH_SECRET", "RustAuthSecretForCliTests-1234567890!")
        .assert()
        .success()
        .stdout(predicate::str::contains("database.migrations_unsupported"))
        .stdout(predicate::str::contains("database.connection").not());
}

#[test]
#[cfg(feature = "sqlx")]
fn output_dir_flag_writes_generated_migration_to_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);
    let output_dir = temp.path().join("custom-migrations");

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn generate_adapter_and_dialect_writes_sql_without_config_or_database_url() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("schema.sql");

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn generate_sqlx_adapter_and_dialect_writes_sql_without_config_or_database_url() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("schema.sql");

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn non_interactive_generate_without_yes_fails_without_writing_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);
    let migrations_dir = temp.path().join("migrations/rustauth");

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn non_interactive_migrate_without_yes_fails_without_applying() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
fn non_interactive_db_commands_succeed_with_yes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "tokio-postgres")]
fn generate_tokio_postgres_adapter_and_dialect_writes_sql_without_config_or_database_url() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("schema.sql");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--adapter",
            "tokio-postgres",
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
#[cfg(feature = "deadpool-postgres")]
fn generate_deadpool_postgres_adapter_and_dialect_writes_sql_without_config_or_database_url() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("schema.sql");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--adapter",
            "deadpool-postgres",
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
#[cfg(feature = "tokio-postgres")]
fn tokio_postgres_adapter_with_sqlite_provider_reports_unsupported_provider() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "tokio-postgres",
        "sqlite",
        "migrations/rustauth",
        &[],
    );

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported database provider"));
}

#[test]
#[cfg(feature = "tokio-postgres")]
#[ignore = "requires docker compose postgres service"]
fn tokio_postgres_status_and_migrate_work_against_docker_compose() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "tokio-postgres",
        "postgres",
        "migrations/rustauth",
        &["api-key"],
    );
    let database_url = isolated_postgres_database_url("tokio_pg");

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "deadpool-postgres")]
#[ignore = "requires docker compose postgres service"]
fn deadpool_postgres_status_and_migrate_work_against_docker_compose() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "deadpool-postgres",
        "postgres",
        "migrations/rustauth",
        &["api-key"],
    );
    let database_url = isolated_postgres_database_url("deadpool_pg");

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
#[ignore = "requires docker compose postgres service"]
fn postgres_status_and_migrate_work_against_docker_compose() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "sqlx",
        "postgres",
        "migrations/rustauth",
        &["api-key"],
    );
    let database_url = isolated_postgres_database_url("sqlx_pg");

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "sqlx")]
#[ignore = "requires docker compose mysql service"]
fn mysql_status_and_migrate_work_against_docker_compose() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "sqlx",
        "mysql",
        "migrations/rustauth",
        &["api-key"],
    );
    let database_url = std::env::var("RUSTAUTH_CLI_TEST_MYSQL_URL")
        .unwrap_or_else(|_| "mysql://user:password@localhost:3306/rustauth".to_owned());

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(not(feature = "tokio-postgres"))]
fn db_status_tokio_postgres_without_cli_feature_reports_disabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "tokio-postgres",
        "postgres",
        "migrations/rustauth",
        &[],
    );

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env(
            "DATABASE_URL",
            "postgres://user:password@localhost:5432/rustauth",
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("not enabled in this CLI build"))
        .stderr(predicate::str::contains("tokio-postgres"));
}

#[test]
#[cfg(not(feature = "sqlx"))]
fn db_status_sqlx_without_cli_feature_reports_disabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(temp.path(), "sqlx", "sqlite", "migrations/rustauth", &[]);
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not enabled in this CLI build"))
        .stderr(predicate::str::contains("sqlx"));
}

#[test]
#[cfg(all(feature = "sqlx", not(feature = "passkey")))]
fn db_generate_passkey_without_cli_feature_reports_disabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "sqlx",
        "sqlite",
        "migrations/rustauth",
        &["passkey"],
    );
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());

    Command::cargo_bin("rustauth")
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
        .failure()
        .stderr(predicate::str::contains("feature `passkey` is required"));
}

#[test]
#[cfg(feature = "diesel")]
fn generate_diesel_adapter_and_dialect_writes_sql_without_config_or_database_url() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("schema.sql");

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "generate",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
            "--adapter",
            "diesel",
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
#[cfg(feature = "diesel")]
fn diesel_adapter_with_sqlite_provider_reports_unsupported_provider() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(temp.path(), "diesel", "sqlite", "migrations/rustauth", &[]);

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported database provider"));
}

#[test]
#[cfg(feature = "diesel")]
#[ignore = "requires docker compose postgres service"]
fn diesel_postgres_status_and_migrate_work_against_docker_compose() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "diesel",
        "postgres",
        "migrations/rustauth",
        &["api-key"],
    );
    let database_url = isolated_postgres_database_url("diesel_pg");

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(feature = "diesel")]
#[ignore = "requires docker compose mysql service"]
fn diesel_mysql_status_and_migrate_work_against_docker_compose() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "diesel",
        "mysql",
        "migrations/rustauth",
        &["api-key"],
    );
    let database_url = std::env::var("RUSTAUTH_CLI_TEST_MYSQL_URL")
        .unwrap_or_else(|_| "mysql://user:password@localhost:3306/rustauth".to_owned());

    Command::cargo_bin("rustauth")
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

    Command::cargo_bin("rustauth")
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
#[cfg(not(feature = "diesel"))]
fn db_status_diesel_without_cli_feature_reports_disabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_config_with_adapter(
        temp.path(),
        "diesel",
        "postgres",
        "migrations/rustauth",
        &[],
    );

    Command::cargo_bin("rustauth")
        .expect("binary")
        .args([
            "db",
            "status",
            "--cwd",
            temp.path().to_str().expect("utf8 path"),
        ])
        .env(
            "DATABASE_URL",
            "postgres://user:password@localhost:5432/rustauth",
        )
        .assert()
        .failure()
        .stderr(predicate::str::contains("not enabled in this CLI build"))
        .stderr(predicate::str::contains("diesel"));
}

#[test]
#[cfg(feature = "sqlx")]
fn adding_schema_plugin_updates_config_and_reports_database_impact() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = format!("sqlite://{}", temp.path().join("auth.sqlite").display());
    write_config(temp.path(), &database_url, &[]);

    Command::cargo_bin("rustauth")
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

    let config = fs::read_to_string(temp.path().join("rustauth.toml")).expect("config");
    assert!(config.contains("\"two-factor\""));
}
