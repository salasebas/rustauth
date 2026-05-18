use openauth_core::db::sql::{plan_schema_migration, SqlDialect, SqlSchemaSnapshot};
use openauth_core::db::{auth_schema, AuthSchemaOptions, DbSchema, SchemaMigrationPlan};
use openauth_core::error::OpenAuthError;

use crate::config::CliConfig;
use crate::plugins::apply_configured_plugins;

pub fn target_schema(config: &CliConfig) -> Result<DbSchema, OpenAuthError> {
    let mut schema = auth_schema(AuthSchemaOptions::default());
    apply_configured_plugins(&mut schema, &config.plugins.enabled)?;
    Ok(schema)
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
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    plan_schema_migration(dialect, schema, &SqlSchemaSnapshot::default())
}

pub fn dialect_name(dialect: SqlDialect) -> &'static str {
    match dialect {
        SqlDialect::MySql => "mysql",
        SqlDialect::Postgres => "postgres",
        SqlDialect::Sqlite => "sqlite",
    }
}
