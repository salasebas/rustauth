//! Shared helpers for `rustauth-cli` integration tests.
//!
//! See [`README.md`](README.md) for the migration test matrix and how to run
//! Docker-backed cases locally.

#![allow(dead_code, clippy::expect_used)]

use assert_cmd::Command;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn write_sqlite_config(dir: &Path, database_url: &str, plugins: &[&str]) {
    write_config_with_adapter(dir, "sqlx", "sqlite", "migrations/rustauth", plugins);
    fs::write(
        dir.join(".env.example"),
        format!("DATABASE_URL={database_url}\n"),
    )
    .expect("write env example");
}

pub fn write_config_with_adapter(
    dir: &Path,
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

pub fn write_minimal_rust_src(dir: &Path, contents: &str) {
    fs::create_dir_all(dir.join("src")).expect("create src dir");
    fs::write(dir.join("src/main.rs"), contents).expect("write main.rs");
}

pub fn write_invalid_toml(dir: &Path) {
    fs::write(dir.join("rustauth.toml"), "[project\nframework = \n").expect("write invalid toml");
}

pub const CLI_TEST_SECRET: &str = "RustAuthSecretForCliTests-1234567890!";

pub fn sqlite_database_url(dir: &Path, name: &str) -> String {
    format!("sqlite://{}", dir.join(name).display())
}

pub fn rustauth_cmd(cwd: &Path) -> Command {
    let mut command = Command::cargo_bin("rustauth").expect("binary");
    command.args(["--cwd", cwd.to_str().expect("utf8 path")]);
    command
}

pub async fn connect_sqlite(database_url: &str) -> sqlx::Pool<sqlx::Sqlite> {
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr;

    let options = SqliteConnectOptions::from_str(database_url)
        .expect("sqlite url")
        .create_if_missing(true);
    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("connect sqlite")
}

pub fn seed_incompatible_users_table(database_url: &str) {
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let pool = connect_sqlite(database_url).await;
            sqlx::query(
                "CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email INTEGER NOT NULL,
                    email_verified INTEGER NOT NULL,
                    image TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )",
            )
            .execute(&pool)
            .await
            .expect("seed incompatible users table");
            pool.close().await;
        });
}

pub fn seed_sessions_foreign_key_mismatch(database_url: &str) {
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let pool = connect_sqlite(database_url).await;
            sqlx::query("PRAGMA foreign_keys = ON")
                .execute(&pool)
                .await
                .expect("enable foreign keys");
            sqlx::query("CREATE TABLE users (id TEXT PRIMARY KEY)")
                .execute(&pool)
                .await
                .expect("seed users");
            sqlx::query(
                "CREATE TABLE sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT
                )",
            )
            .execute(&pool)
            .await
            .expect("seed sessions with mismatched fk");
            pool.close().await;
        });
}

pub fn block_on_sqlite<F, Fut>(database_url: &str, f: F)
where
    F: FnOnce(sqlx::Pool<sqlx::Sqlite>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let pool = connect_sqlite(database_url).await;
            f(pool).await;
        });
}

pub async fn sqlite_table_exists(database_url: &str, table: &str) -> bool {
    let pool = connect_sqlite(database_url).await;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
            .bind(table)
            .fetch_one(&pool)
            .await
            .expect("query sqlite_master");
    pool.close().await;
    count > 0
}

pub fn isolated_postgres_database_url(test_name: &str) -> String {
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
