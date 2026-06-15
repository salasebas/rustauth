#![allow(clippy::expect_used)]

mod support;

use assert_cmd::Command;
use predicates::prelude::*;
use support::*;

#[test]
fn doctor_warns_on_legacy_router_pattern() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlite::memory:", &[]);
    write_minimal_rust_src(
        temp.path(),
        "fn main() { let _ = rustauth_axum::router(()); }",
    );

    rustauth_cmd(temp.path())
        .args(["doctor", "--json"])
        .env("DATABASE_URL", "sqlite::memory:")
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("integration.legacy_router"));
}

#[test]
fn doctor_warns_on_double_nest_pattern() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlite::memory:", &[]);
    write_minimal_rust_src(
        temp.path(),
        "fn main() { auth.mount_at_base_path(); router.nest(\"/api\", routes); }",
    );

    rustauth_cmd(temp.path())
        .args(["doctor", "--json"])
        .env("DATABASE_URL", "sqlite::memory:")
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("integration.double_nest"));
}

#[test]
#[cfg(feature = "sqlx")]
fn doctor_reports_pending_schema_before_migrate() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "doctor_pending.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["doctor", "--json"])
        .env("DATABASE_URL", &database_url)
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("database.pending_schema"));
}

#[test]
#[cfg(feature = "sqlx")]
fn doctor_reports_schema_up_to_date_after_migrate() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "doctor_current.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["doctor", "--json"])
        .env("DATABASE_URL", &database_url)
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("database.schema"))
        .stdout(predicate::str::contains("database.pending_schema").not());
}

#[test]
fn doctor_production_requires_https_base_url() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("rustauth.toml"),
        r#"
[project]
framework = "axum"
base_url = "http://app.example.com/api/auth"
base_path = "/api/auth"
production = true

[database]
adapter = "sqlx"
provider = "sqlite"
url_env = "DATABASE_URL"
migrations_dir = "migrations/rustauth"

[security]
secret_env = "RUSTAUTH_SECRET"

[plugins]
enabled = []
"#,
    )
    .expect("write config");

    rustauth_cmd(temp.path())
        .args(["doctor", "--production", "--json"])
        .env("DATABASE_URL", "sqlite::memory:")
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .failure()
        .stdout(predicate::str::contains("security.base_url_https"));
}

#[test]
fn info_human_output_lists_findings() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlite::memory:", &[]);

    rustauth_cmd(temp.path())
        .args(["info"])
        .env("DATABASE_URL", "sqlite::memory:")
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("RustAuth info"))
        .stdout(
            predicate::str::contains("[INFO]")
                .or(predicate::str::contains("[WARN]"))
                .or(predicate::str::contains("[ERROR]")),
        );
}

#[test]
#[cfg(feature = "sqlx")]
fn doctor_strict_fails_on_pending_schema() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "doctor_strict.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["doctor", "--strict"])
        .env("DATABASE_URL", &database_url)
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .failure()
        .stdout(predicate::str::contains("database.pending_schema"));
}

#[test]
fn init_rejects_unknown_plugin() {
    let temp = tempfile::tempdir().expect("tempdir");

    rustauth_cmd(temp.path())
        .args([
            "init",
            "--framework",
            "axum",
            "--plugins",
            "not-a-real-plugin",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not an official RustAuth plugin"));
}

#[test]
#[cfg(feature = "plugins")]
fn plugins_add_rejects_unknown_plugin() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlite::memory:", &[]);

    rustauth_cmd(temp.path())
        .args(["plugins", "add", "fake-plugin", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not an official RustAuth plugin"));
}

#[test]
#[cfg(feature = "plugins")]
fn plugins_remove_is_idempotent_in_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlite::memory:", &["username"]);

    for _ in 0..2 {
        rustauth_cmd(temp.path())
            .args(["plugins", "remove", "username", "--yes"])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "does not generate destructive migrations",
            ));
    }

    let config = std::fs::read_to_string(temp.path().join("rustauth.toml")).expect("config");
    assert!(!config.contains("\"username\""));
}

#[test]
#[cfg(all(feature = "sqlx", feature = "plugins"))]
fn plugins_remove_then_migrate_keeps_tables() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "plugins_remove.sqlite");
    write_sqlite_config(temp.path(), &database_url, &["api-key"]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["plugins", "remove", "api-key", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .env("RUSTAUTH_SECRET", CLI_TEST_SECRET)
        .assert()
        .success()
        .stdout(predicate::str::contains("No migrations needed."));

    assert!(
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(sqlite_table_exists(&database_url, "api_keys")),
        "plugins remove must not drop existing tables"
    );
}

#[test]
fn schema_print_rejects_unknown_dialect() {
    let temp = tempfile::tempdir().expect("tempdir");

    rustauth_cmd(temp.path())
        .args(["schema", "print", "--dialect", "cockroachdb"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported dialect"));
}

#[test]
#[cfg(feature = "plugins")]
fn schema_print_json_honors_config_plugins() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_sqlite_config(temp.path(), "sqlite::memory:", &["admin"]);

    rustauth_cmd(temp.path())
        .args(["schema", "print", "--format", "json", "--dialect", "sqlite"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"role\""));
}

#[test]
#[cfg(feature = "sqlx")]
fn db_generate_rejects_output_and_output_dir_together() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "generate_flags.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args([
            "db",
            "generate",
            "--from-empty",
            "--output",
            "foo.sql",
            "--output-dir",
            "dir",
            "--yes",
        ])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Use only one of --output or --output-dir",
        ));
}

#[test]
#[cfg(feature = "sqlx")]
fn db_commands_fail_on_malformed_toml() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_invalid_toml(temp.path());

    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", "sqlite::memory:")
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to parse RustAuth config"));
}

#[test]
fn completions_emits_zsh_script() {
    Command::cargo_bin("rustauth")
        .expect("binary")
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef").or(predicate::str::contains("_rustauth")));
}

#[test]
fn completions_emits_fish_script() {
    Command::cargo_bin("rustauth")
        .expect("binary")
        .args(["completions", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}
