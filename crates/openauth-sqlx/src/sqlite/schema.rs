use super::errors::{inactive_transaction, sql_error};
use super::foreign_keys;
use super::state::SqliteExecutor;
use super::support::sanitize_identifier;
use crate::migration::SchemaMigrationPlan;
use openauth_core::db::{
    plan_schema_migration, DbSchema, ForeignKey, IdGeneration, OnDelete, SqlColumnSnapshot,
    SqlDialect, SqlSchemaSnapshot,
};
use openauth_core::error::OpenAuthError;

pub(super) async fn plan_migrations(
    mut executor: SqliteExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    build_migration_plan(&mut executor, schema).await
}

pub(super) async fn create_schema(
    mut executor: SqliteExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<(), OpenAuthError> {
    let plan = build_migration_plan(&mut executor, schema).await?;
    crate::migration::ensure_executable(&plan)?;
    execute_migration_plan(&mut executor, &plan).await
}

async fn build_migration_plan(
    executor: &mut SqliteExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    let snapshot = load_schema_snapshot(executor, schema).await?;
    plan_schema_migration(SqlDialect::Sqlite, schema, &snapshot)
}

async fn load_schema_snapshot(
    executor: &mut SqliteExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SqlSchemaSnapshot, OpenAuthError> {
    let mut snapshot = SqlSchemaSnapshot::default();
    let mut tables = schema.tables().collect::<Vec<_>>();
    tables.sort_by_key(|(_, table)| table.order.unwrap_or(u16::MAX));

    for (_, table) in &tables {
        if table_exists(executor, &table.name).await? {
            snapshot = snapshot.with_table(&table.name);
            for (_, field) in &table.fields {
                if let Some(column) = column_snapshot(executor, &table.name, &field.name).await? {
                    snapshot = snapshot.with_column(&table.name, column);
                }
                if field.unique && unique_column_exists(executor, &table.name, &field.name).await? {
                    snapshot = snapshot.with_unique_column(&table.name, &field.name);
                }
            }
        }

        for (logical_name, field) in &table.fields {
            if field.index || field.unique {
                let prefix = if field.unique { "uidx" } else { "idx" };
                let index_name = format!("{prefix}_{}_{}", table.name, logical_name);
                let index_name = sanitize_identifier(&index_name)?;
                if index_exists(executor, &index_name).await? {
                    snapshot = snapshot.with_index(&table.name, index_name);
                }
            }
        }
    }

    Ok(snapshot)
}

pub(super) async fn execute_migration_plan(
    executor: &mut SqliteExecutor<'_, '_>,
    plan: &SchemaMigrationPlan,
) -> Result<(), OpenAuthError> {
    for statement in &plan.statements {
        execute_schema_sql(executor, &statement.sql).await?;
    }
    Ok(())
}

async fn table_exists(
    executor: &mut SqliteExecutor<'_, '_>,
    table: &str,
) -> Result<bool, OpenAuthError> {
    let count = match executor {
        SqliteExecutor::Pool(pool) => {
            let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                .await
                .map_err(sql_error)?;
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(&mut *connection)
            .await
            .map_err(sql_error)?
        }
        SqliteExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            )
            .bind(table)
            .fetch_one(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    Ok(count > 0)
}

async fn column_snapshot(
    executor: &mut SqliteExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<Option<SqlColumnSnapshot>, OpenAuthError> {
    let sql = format!(
        "SELECT type, \"notnull\", pk FROM pragma_table_info({}) WHERE name = ?",
        sql_string_literal(table),
    );
    let row = match executor {
        SqliteExecutor::Pool(pool) => {
            let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                .await
                .map_err(sql_error)?;
            sqlx::query_as::<_, (String, i64, i64)>(&sql)
                .bind(column)
                .fetch_optional(&mut *connection)
                .await
                .map_err(sql_error)?
        }
        SqliteExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_as::<_, (String, i64, i64)>(&sql)
                .bind(column)
                .fetch_optional(&mut **tx)
                .await
                .map_err(sql_error)?
        }
    };
    let Some((data_type, not_null, primary_key)) = row else {
        return Ok(None);
    };
    let primary_key = primary_key > 0;
    let generated_id = if primary_key && data_type.eq_ignore_ascii_case("integer") {
        Some(IdGeneration::Serial)
    } else {
        None
    };
    Ok(Some(
        SqlColumnSnapshot::new(column, data_type)
            .nullable(!primary_key && not_null == 0)
            .primary_key(primary_key)
            .generated_id(generated_id)
            .with_optional_foreign_key(foreign_key(executor, table, column).await?),
    ))
}

async fn index_exists(
    executor: &mut SqliteExecutor<'_, '_>,
    index: &str,
) -> Result<bool, OpenAuthError> {
    let count = match executor {
        SqliteExecutor::Pool(pool) => {
            let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                .await
                .map_err(sql_error)?;
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?",
            )
            .bind(index)
            .fetch_one(&mut *connection)
            .await
            .map_err(sql_error)?
        }
        SqliteExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?",
            )
            .bind(index)
            .fetch_one(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    Ok(count > 0)
}

async fn unique_column_exists(
    executor: &mut SqliteExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<bool, OpenAuthError> {
    let sql = format!(
        "SELECT COUNT(*) \
         FROM pragma_index_list({}) AS indexes \
         JOIN pragma_index_info(indexes.name) AS columns \
         WHERE indexes.\"unique\" = 1 AND columns.name = ?",
        sql_string_literal(table),
    );
    let count = match executor {
        SqliteExecutor::Pool(pool) => {
            let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                .await
                .map_err(sql_error)?;
            sqlx::query_scalar::<_, i64>(&sql)
                .bind(column)
                .fetch_one(&mut *connection)
                .await
                .map_err(sql_error)?
        }
        SqliteExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, i64>(&sql)
                .bind(column)
                .fetch_one(&mut **tx)
                .await
                .map_err(sql_error)?
        }
    };
    Ok(count > 0)
}

async fn foreign_key(
    executor: &mut SqliteExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<Option<ForeignKey>, OpenAuthError> {
    let sql = format!(
        "SELECT \"table\", \"to\", on_delete FROM pragma_foreign_key_list({}) WHERE \"from\" = ?",
        sql_string_literal(table),
    );
    let row = match executor {
        SqliteExecutor::Pool(pool) => {
            let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                .await
                .map_err(sql_error)?;
            sqlx::query_as::<_, (String, String, String)>(&sql)
                .bind(column)
                .fetch_optional(&mut *connection)
                .await
                .map_err(sql_error)?
        }
        SqliteExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_as::<_, (String, String, String)>(&sql)
                .bind(column)
                .fetch_optional(&mut **tx)
                .await
                .map_err(sql_error)?
        }
    };
    Ok(row.map(|(table, field, on_delete)| {
        ForeignKey::new(table, field, parse_on_delete(&on_delete))
    }))
}

fn parse_on_delete(value: &str) -> OnDelete {
    match value.to_ascii_uppercase().as_str() {
        "RESTRICT" => OnDelete::Restrict,
        "CASCADE" => OnDelete::Cascade,
        "SET NULL" => OnDelete::SetNull,
        "SET DEFAULT" => OnDelete::SetDefault,
        _ => OnDelete::NoAction,
    }
}

trait OptionalForeignKey {
    fn with_optional_foreign_key(self, foreign_key: Option<ForeignKey>) -> Self;
}

impl OptionalForeignKey for SqlColumnSnapshot {
    fn with_optional_foreign_key(self, foreign_key: Option<ForeignKey>) -> Self {
        if let Some(foreign_key) = foreign_key {
            self.references(foreign_key)
        } else {
            self
        }
    }
}

fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(super) async fn execute_schema_sql(
    executor: &mut SqliteExecutor<'_, '_>,
    sql: &str,
) -> Result<(), OpenAuthError> {
    match executor {
        SqliteExecutor::Pool(pool) => {
            let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                .await
                .map_err(sql_error)?;
            sqlx::query(sql)
                .execute(&mut *connection)
                .await
                .map_err(sql_error)?;
        }
        SqliteExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query(sql)
                .execute(&mut **tx)
                .await
                .map_err(sql_error)?;
        }
    }
    Ok(())
}
