use rustauth_core::db::{
    plan_schema_migration, DbSchema, ForeignKey, IdGeneration, OnDelete, SqlColumnSnapshot,
    SqlDialect, SqlSchemaSnapshot,
};
use rustauth_core::error::RustAuthError;

use super::errors::{inactive_transaction, sql_error};
use super::state::MySqlExecutor;
use super::support::sanitize_identifier;
use rustauth_core::db::{MigrationStatement, MigrationStatementKind, SchemaMigrationPlan};

pub(super) async fn plan_migrations(
    mut executor: MySqlExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, RustAuthError> {
    build_migration_plan(&mut executor, schema).await
}

pub(super) async fn create_schema(
    mut executor: MySqlExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<(), RustAuthError> {
    let plan = build_migration_plan(&mut executor, schema).await?;
    crate::migration::ensure_executable(&plan)?;
    match executor {
        MySqlExecutor::Pool(pool) => execute_migration_plan_on_pool(pool, &plan).await,
        MySqlExecutor::Transaction(guard) => {
            execute_migration_plan(&mut MySqlExecutor::Transaction(guard), &plan).await
        }
    }
}

async fn build_migration_plan(
    executor: &mut MySqlExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, RustAuthError> {
    let snapshot = load_schema_snapshot(executor, schema).await?;
    plan_schema_migration(SqlDialect::MySql, schema, &snapshot)
}

async fn load_schema_snapshot(
    executor: &mut MySqlExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SqlSchemaSnapshot, RustAuthError> {
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
                if index_exists(executor, &table.name, &index_name).await? {
                    snapshot = snapshot.with_index(&table.name, index_name);
                }
            }
        }
    }

    Ok(snapshot)
}

pub(super) async fn execute_migration_plan(
    executor: &mut MySqlExecutor<'_, '_>,
    plan: &SchemaMigrationPlan,
) -> Result<(), RustAuthError> {
    for statement in &plan.statements {
        execute_schema_sql(executor, &statement.sql).await?;
    }
    Ok(())
}

/// MySQL DDL performs implicit commits, so a SQL transaction cannot roll back a
/// multi-statement migration. On failure we best-effort undo earlier statements.
pub(super) async fn execute_migration_plan_on_pool(
    pool: &sqlx::MySqlPool,
    plan: &SchemaMigrationPlan,
) -> Result<(), RustAuthError> {
    let mut applied = Vec::new();
    for statement in &plan.statements {
        match sqlx::query(&statement.sql).execute(pool).await {
            Ok(_) => applied.push(statement),
            Err(error) => {
                compensate_mysql_applied_statements(pool, &applied).await;
                return Err(sql_error(error));
            }
        }
    }
    Ok(())
}

async fn compensate_mysql_applied_statements(
    pool: &sqlx::MySqlPool,
    applied: &[&MigrationStatement],
) {
    for statement in applied.iter().rev() {
        let Some(rollback_sql) = mysql_rollback_statement(statement) else {
            continue;
        };
        let _ = sqlx::query(&rollback_sql).execute(pool).await;
    }
}

fn mysql_rollback_statement(statement: &MigrationStatement) -> Option<String> {
    match statement.kind {
        MigrationStatementKind::CreateTable => {
            let rest = statement.sql.strip_prefix("CREATE TABLE IF NOT EXISTS ")?;
            let end = rest.find('(')?;
            let table = rest[..end].trim();
            Some(format!("DROP TABLE IF EXISTS {table}"))
        }
        MigrationStatementKind::AddColumn => {
            let rest = statement.sql.strip_prefix("ALTER TABLE ")?;
            let mut parts = rest.split_whitespace();
            let table = parts.next()?;
            if parts.next()? != "ADD" || parts.next()? != "COLUMN" {
                return None;
            }
            let column = parts.next()?;
            Some(format!("ALTER TABLE {table} DROP COLUMN {column}"))
        }
        MigrationStatementKind::CreateIndex => {
            let rest = statement
                .sql
                .strip_prefix("CREATE UNIQUE INDEX ")
                .or_else(|| statement.sql.strip_prefix("CREATE INDEX "))?;
            let (index, table_and_columns) = rest.split_once(" ON ")?;
            let table = table_and_columns.split('(').next()?.trim();
            Some(format!("DROP INDEX {index} ON {table}"))
        }
    }
}

async fn table_exists(
    executor: &mut MySqlExecutor<'_, '_>,
    table: &str,
) -> Result<bool, RustAuthError> {
    let exists = match executor {
        MySqlExecutor::Pool(pool) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' AND table_name = ?)",
        )
        .bind(table)
        .fetch_one(*pool)
        .await
        .map_err(sql_error)?,
        MySqlExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' AND table_name = ?)",
            )
            .bind(table)
            .fetch_one(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    Ok(exists)
}

async fn column_snapshot(
    executor: &mut MySqlExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<Option<SqlColumnSnapshot>, RustAuthError> {
    let row = match executor {
        MySqlExecutor::Pool(pool) => sqlx::query_as::<_, (String, bool, bool, String)>(
            "SELECT CAST(data_type AS CHAR CHARACTER SET utf8mb4), \
                    is_nullable = 'YES', \
                    column_key = 'PRI', \
                    CAST(extra AS CHAR CHARACTER SET utf8mb4) \
             FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(*pool)
        .await
        .map_err(sql_error)?,
        MySqlExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_as::<_, (String, bool, bool, String)>(
                "SELECT CAST(data_type AS CHAR CHARACTER SET utf8mb4), \
                        is_nullable = 'YES', \
                        column_key = 'PRI', \
                        CAST(extra AS CHAR CHARACTER SET utf8mb4) \
                 FROM information_schema.columns \
                 WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
            )
            .bind(table)
            .bind(column)
            .fetch_optional(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    let Some((data_type, nullable, primary_key, extra)) = row else {
        return Ok(None);
    };
    let generated_id = if extra.to_ascii_lowercase().contains("auto_increment") {
        Some(IdGeneration::Serial)
    } else {
        None
    };
    Ok(Some(
        SqlColumnSnapshot::new(column, data_type)
            .nullable(nullable)
            .primary_key(primary_key)
            .generated_id(generated_id)
            .with_optional_foreign_key(foreign_key(executor, table, column).await?),
    ))
}

async fn index_exists(
    executor: &mut MySqlExecutor<'_, '_>,
    table: &str,
    index: &str,
) -> Result<bool, RustAuthError> {
    let exists = match executor {
        MySqlExecutor::Pool(pool) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?)",
        )
        .bind(table)
        .bind(index)
        .fetch_one(*pool)
        .await
        .map_err(sql_error)?,
        MySqlExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?)",
            )
            .bind(table)
            .bind(index)
            .fetch_one(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    Ok(exists)
}

async fn unique_column_exists(
    executor: &mut MySqlExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<bool, RustAuthError> {
    let exists = match executor {
        MySqlExecutor::Pool(pool) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? AND non_unique = 0)",
        )
        .bind(table)
        .bind(column)
        .fetch_one(*pool)
        .await
        .map_err(sql_error)?,
        MySqlExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? AND non_unique = 0)",
            )
            .bind(table)
            .bind(column)
            .fetch_one(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    Ok(exists)
}

async fn foreign_key(
    executor: &mut MySqlExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<Option<ForeignKey>, RustAuthError> {
    let row = match executor {
        MySqlExecutor::Pool(pool) => sqlx::query_as::<_, (String, String, String)>(
            "SELECT CAST(kcu.referenced_table_name AS CHAR CHARACTER SET utf8mb4), \
                    CAST(kcu.referenced_column_name AS CHAR CHARACTER SET utf8mb4), \
                    CAST(rc.delete_rule AS CHAR CHARACTER SET utf8mb4) \
             FROM information_schema.key_column_usage kcu \
             JOIN information_schema.referential_constraints rc \
               ON rc.constraint_schema = kcu.constraint_schema \
              AND rc.constraint_name = kcu.constraint_name \
             WHERE kcu.table_schema = DATABASE() \
               AND kcu.table_name = ? \
               AND kcu.column_name = ? \
               AND kcu.referenced_table_name IS NOT NULL",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(*pool)
        .await
        .map_err(sql_error)?,
        MySqlExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_as::<_, (String, String, String)>(
                "SELECT CAST(kcu.referenced_table_name AS CHAR CHARACTER SET utf8mb4), \
                        CAST(kcu.referenced_column_name AS CHAR CHARACTER SET utf8mb4), \
                        CAST(rc.delete_rule AS CHAR CHARACTER SET utf8mb4) \
                 FROM information_schema.key_column_usage kcu \
                 JOIN information_schema.referential_constraints rc \
                   ON rc.constraint_schema = kcu.constraint_schema \
                  AND rc.constraint_name = kcu.constraint_name \
                 WHERE kcu.table_schema = DATABASE() \
                   AND kcu.table_name = ? \
                   AND kcu.column_name = ? \
                   AND kcu.referenced_table_name IS NOT NULL",
            )
            .bind(table)
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

pub(super) async fn execute_schema_sql(
    executor: &mut MySqlExecutor<'_, '_>,
    sql: &str,
) -> Result<(), RustAuthError> {
    match executor {
        MySqlExecutor::Pool(pool) => {
            sqlx::query(sql).execute(*pool).await.map_err(sql_error)?;
        }
        MySqlExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query(sql)
                .execute(&mut **tx)
                .await
                .map_err(sql_error)?;
        }
    }
    Ok(())
}
