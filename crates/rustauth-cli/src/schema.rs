use rustauth_core::db::sql::{plan_schema_migration, SqlDialect, SqlSchemaSnapshot};
use rustauth_core::db::{auth_schema, AuthSchemaOptions, DbSchema, SchemaMigrationPlan};
use rustauth_core::error::RustAuthError;

use crate::config::CliConfig;
use crate::plugins::schema_context_for_config;

pub fn target_schema(config: &CliConfig) -> Result<DbSchema, RustAuthError> {
    if config.plugins.enabled.is_empty() {
        return Ok(auth_schema(AuthSchemaOptions::default()));
    }
    Ok(schema_context_for_config(&config.plugins.enabled)?.db_schema)
}

pub fn dialect_from_provider(provider: &str) -> Option<SqlDialect> {
    match provider {
        "postgres" | "postgresql" | "pg" => Some(SqlDialect::Postgres),
        "mysql" => Some(SqlDialect::MySql),
        "sqlite" | "sqlite3" => Some(SqlDialect::Sqlite),
        _ => None,
    }
}

pub fn full_schema_plan(
    dialect: SqlDialect,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, RustAuthError> {
    plan_schema_migration(dialect, schema, &SqlSchemaSnapshot::default())
}

pub fn dialect_name(dialect: SqlDialect) -> &'static str {
    match dialect {
        SqlDialect::MySql => "mysql",
        SqlDialect::Postgres => "postgres",
        SqlDialect::Sqlite => "sqlite",
    }
}
