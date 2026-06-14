#![allow(clippy::expect_used)]

mod support;

use predicates::prelude::*;
use support::*;

#[test]
#[cfg(all(feature = "sqlx", feature = "plugins"))]
fn sqlite_incremental_plugin_migration_adds_only_new_tables() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "incremental.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("users"));

    rustauth_cmd(temp.path())
        .args(["db", "status", "--check"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Tables to create: 0"));

    write_sqlite_config(temp.path(), &database_url, &["api-key"]);
    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("api_keys"))
        .stdout(predicate::str::contains("Tables to create: 1"));

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("api_keys"));

    write_sqlite_config(temp.path(), &database_url, &["api-key", "jwt"]);
    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("jwks"))
        .stdout(predicate::str::contains("Tables to create: 1"));

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["db", "status", "--check"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Tables to create: 0"));
}

#[test]
#[cfg(all(feature = "sqlx", feature = "plugins"))]
fn sqlite_incremental_multiple_table_plugins_in_one_pass() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "multi.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    write_sqlite_config(
        temp.path(),
        &database_url,
        &["api-key", "jwt", "two-factor"],
    );
    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Tables to create: 3"))
        .stdout(predicate::str::contains("api_keys"))
        .stdout(predicate::str::contains("jwks"))
        .stdout(predicate::str::contains("two_factors"));

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["db", "status", "--check"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();
}

#[test]
#[cfg(all(feature = "sqlx", feature = "plugins"))]
fn sqlite_incremental_column_plugin_admin_adds_user_columns() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "admin.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    write_sqlite_config(temp.path(), &database_url, &["admin"]);
    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Tables to create: 0"))
        .stdout(predicate::str::contains("Columns to add:"))
        .stdout(predicate::str::contains("users.role"))
        .stdout(predicate::str::contains("users.banned"));

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["db", "status", "--check"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();
}

#[test]
#[cfg(all(feature = "sqlx", feature = "plugins"))]
fn sqlite_plugins_add_command_triggers_incremental_migrate() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "plugins_add.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["plugins", "add", "two-factor", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("changes the database schema"));

    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("two_factors"));

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();
}

#[test]
#[cfg(all(feature = "sqlx", feature = "plugins"))]
fn sqlite_removed_plugin_from_toml_does_not_drop_tables() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "nondestructive.sqlite");
    write_sqlite_config(temp.path(), &database_url, &["api-key"]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    assert!(
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(sqlite_table_exists(&database_url, "api_keys")),
        "api_keys should exist after first migrate"
    );

    write_sqlite_config(temp.path(), &database_url, &[]);
    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("No migrations needed."));

    assert!(
        tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(sqlite_table_exists(&database_url, "api_keys")),
        "removing a plugin id must not drop existing tables"
    );
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_db_status_check_exits_nonzero_when_pending() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "check.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "status", "--check"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stdout(predicate::str::contains("Tables to create:"));
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_db_status_json_reports_pending_plan() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "json.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "status", "--json"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"tables_to_create\""))
        .stdout(predicate::str::contains("\"tables_to_create\": 4"));
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_migrate_rejects_incompatible_existing_table() {
    let temp = tempfile::tempdir().expect("tempdir");
    let db_path = temp.path().join("conflict.sqlite");
    let database_url = sqlite_database_url(temp.path(), "conflict.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);
    seed_incompatible_users_table(&database_url);

    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("ColumnTypeMismatch").or(predicate::str::contains("WARNING")),
        );

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "migration has non-executable warnings",
        ));

    assert!(db_path.exists());
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_migrate_blocks_on_foreign_key_mismatch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "fk.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);
    seed_sessions_foreign_key_mismatch(&database_url);

    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(
            predicate::str::contains("ForeignKeyMismatch").or(predicate::str::contains("WARNING")),
        );

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "migration has non-executable warnings",
        ));
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_migrate_dry_run_reports_unsafe_plan_without_applying() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "dry_run.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);
    seed_incompatible_users_table(&database_url);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--dry-run", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "migration has non-executable warnings",
        ))
        .stdout(predicate::str::contains("Dry run complete").not());
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_second_migrate_reports_no_changes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "noop.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("No migrations needed."));
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_migrate_fails_when_adding_unique_column_to_existing_sqlite_table() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "partial.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    block_on_sqlite(&database_url, |pool| async move {
        sqlx::query("CREATE TABLE users (id TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("seed partial users table");
    });

    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Columns to add: 6"))
        .stdout(predicate::str::contains("users.email"))
        .stdout(predicate::str::contains("  - sessions"));

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cannot add a UNIQUE column"));
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_generate_after_full_migrate_is_up_to_date() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "generate.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["db", "generate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("Schema is already up to date."));
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_db_migrate_without_config_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "missing_config.sqlite");

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains("No RustAuth CLI config found"));
}

#[test]
#[cfg(feature = "sqlx")]
fn sqlite_db_migrate_without_database_url_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "missing_url.sqlite");
    write_sqlite_config(temp.path(), &database_url, &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env_remove("DATABASE_URL")
        .assert()
        .failure()
        .stderr(predicate::str::contains("DATABASE_URL"));
}

#[test]
#[cfg(all(feature = "sqlx", not(feature = "passkey")))]
fn sqlite_db_migrate_passkey_without_cli_feature_reports_disabled() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = sqlite_database_url(temp.path(), "passkey.sqlite");
    write_sqlite_config(temp.path(), &database_url, &["passkey"]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .failure()
        .stderr(predicate::str::contains("feature `passkey` is required"));
}

#[test]
#[cfg(feature = "sqlx")]
#[ignore = "requires docker compose postgres service"]
fn postgres_incremental_plugin_migration_adds_only_new_tables() {
    run_postgres_incremental_plugin_migration("sqlx", "postgres");
}

#[test]
#[cfg(feature = "tokio-postgres")]
#[ignore = "requires docker compose postgres service"]
fn tokio_postgres_incremental_plugin_migration_adds_only_new_tables() {
    run_postgres_incremental_plugin_migration("tokio-postgres", "postgres");
}

#[test]
#[cfg(feature = "deadpool-postgres")]
#[ignore = "requires docker compose postgres service"]
fn deadpool_postgres_incremental_plugin_migration_adds_only_new_tables() {
    run_postgres_incremental_plugin_migration("deadpool-postgres", "postgres");
}

#[cfg(any(
    feature = "sqlx",
    feature = "tokio-postgres",
    feature = "deadpool-postgres"
))]
fn run_postgres_incremental_plugin_migration(adapter: &str, provider: &str) {
    let temp = tempfile::tempdir().expect("tempdir");
    let database_url = isolated_postgres_database_url(&format!("{adapter}_incremental"));
    write_config_with_adapter(temp.path(), adapter, provider, "migrations/rustauth", &[]);

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    write_config_with_adapter(
        temp.path(),
        adapter,
        provider,
        "migrations/rustauth",
        &["api-key"],
    );
    rustauth_cmd(temp.path())
        .args(["db", "status"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success()
        .stdout(predicate::str::contains("api_keys"))
        .stdout(predicate::str::contains("Tables to create: 1"));

    rustauth_cmd(temp.path())
        .args(["db", "migrate", "--yes"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();

    rustauth_cmd(temp.path())
        .args(["db", "status", "--check"])
        .env("DATABASE_URL", &database_url)
        .assert()
        .success();
}
