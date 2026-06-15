use rustauth_core::db::{
    plan_schema_migration, DbField, DbFieldType, DbSchema, ForeignKey, IdGeneration,
    MigrationStatement, MigrationStatementKind, OnDelete, SchemaMigrationPlan, SqlColumnSnapshot,
    SqlDialect, SqlParam, SqlSchemaSnapshot,
};
use rustauth_core::error::RustAuthError;

use diesel::deserialize::QueryableByName;
use diesel::sql_types::{Bool, Text};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::{AsyncMysqlConnection, RunQueryDsl};

use super::errors::{diesel_error, inactive_transaction, pool_error};
use super::state::DieselMysqlExecutor;
use super::support::sanitize_identifier;
use crate::bind_mysql_params;

pub(super) async fn plan_migrations(
    mut executor: DieselMysqlExecutor<'_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, RustAuthError> {
    build_migration_plan(&mut executor, schema).await
}

pub(super) async fn create_schema(
    mut executor: DieselMysqlExecutor<'_>,
    schema: &DbSchema,
) -> Result<(), RustAuthError> {
    let plan = build_migration_plan(&mut executor, schema).await?;
    crate::migration::ensure_executable(&plan)?;
    match executor {
        DieselMysqlExecutor::Pool(pool) => execute_migration_plan_on_pool(pool, &plan).await,
        DieselMysqlExecutor::Transaction(guard) => {
            execute_migration_plan(&mut DieselMysqlExecutor::Transaction(guard), &plan).await
        }
    }
}

async fn build_migration_plan(
    executor: &mut DieselMysqlExecutor<'_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, RustAuthError> {
    let snapshot = load_schema_snapshot(executor, schema).await?;
    plan_schema_migration(SqlDialect::MySql, schema, &snapshot)
}

async fn load_schema_snapshot(
    executor: &mut DieselMysqlExecutor<'_>,
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

#[derive(QueryableByName)]
struct ExistsRow {
    #[diesel(sql_type = Bool)]
    exists: bool,
}

#[derive(QueryableByName)]
struct ColumnInfoRow {
    #[diesel(sql_type = Text)]
    data_type: String,
    #[diesel(sql_type = Bool)]
    nullable: bool,
    #[diesel(sql_type = Bool)]
    primary_key: bool,
    #[diesel(sql_type = Text)]
    extra: String,
}

#[derive(QueryableByName)]
struct ForeignKeyRow {
    #[diesel(sql_type = Text)]
    ref_table: String,
    #[diesel(sql_type = Text)]
    ref_column: String,
    #[diesel(sql_type = Text)]
    delete_rule: String,
}

async fn table_exists(
    executor: &mut DieselMysqlExecutor<'_>,
    table: &str,
) -> Result<bool, RustAuthError> {
    let table_field = DbField::new("table", DbFieldType::String);
    let params = vec![SqlParam::new(
        &table_field,
        rustauth_core::db::DbValue::String(table.to_owned()),
    )];
    let sql = "SELECT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' AND table_name = ?
    ) AS `exists`";
    fetch_exists(executor, sql, params).await
}

async fn column_snapshot(
    executor: &mut DieselMysqlExecutor<'_>,
    table: &str,
    column: &str,
) -> Result<Option<SqlColumnSnapshot>, RustAuthError> {
    let table_field = DbField::new("table", DbFieldType::String);
    let column_field = DbField::new("column", DbFieldType::String);
    let params = vec![
        SqlParam::new(
            &table_field,
            rustauth_core::db::DbValue::String(table.to_owned()),
        ),
        SqlParam::new(
            &column_field,
            rustauth_core::db::DbValue::String(column.to_owned()),
        ),
    ];
    let sql = "SELECT CAST(data_type AS CHAR CHARACTER SET utf8mb4) AS data_type, \
        is_nullable = 'YES' AS nullable, \
        column_key = 'PRI' AS primary_key, \
        CAST(extra AS CHAR CHARACTER SET utf8mb4) AS extra \
        FROM information_schema.columns \
        WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?";
    let row = fetch_optional_row::<ColumnInfoRow>(executor, sql, params).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let generated_id = if row.extra.to_ascii_lowercase().contains("auto_increment") {
        Some(IdGeneration::Serial)
    } else {
        None
    };
    Ok(Some(
        SqlColumnSnapshot::new(column, row.data_type)
            .nullable(row.nullable)
            .primary_key(row.primary_key)
            .generated_id(generated_id)
            .with_optional_foreign_key(foreign_key(executor, table, column).await?),
    ))
}

async fn index_exists(
    executor: &mut DieselMysqlExecutor<'_>,
    table: &str,
    index: &str,
) -> Result<bool, RustAuthError> {
    let table_field = DbField::new("table", DbFieldType::String);
    let index_field = DbField::new("index", DbFieldType::String);
    let params = vec![
        SqlParam::new(
            &table_field,
            rustauth_core::db::DbValue::String(table.to_owned()),
        ),
        SqlParam::new(
            &index_field,
            rustauth_core::db::DbValue::String(index.to_owned()),
        ),
    ];
    let sql = "SELECT EXISTS (
        SELECT 1 FROM information_schema.statistics
        WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?
    ) AS `exists`";
    fetch_exists(executor, sql, params).await
}

async fn unique_column_exists(
    executor: &mut DieselMysqlExecutor<'_>,
    table: &str,
    column: &str,
) -> Result<bool, RustAuthError> {
    let table_field = DbField::new("table", DbFieldType::String);
    let column_field = DbField::new("column", DbFieldType::String);
    let params = vec![
        SqlParam::new(
            &table_field,
            rustauth_core::db::DbValue::String(table.to_owned()),
        ),
        SqlParam::new(
            &column_field,
            rustauth_core::db::DbValue::String(column.to_owned()),
        ),
    ];
    let sql = "SELECT EXISTS (
        SELECT 1 FROM information_schema.statistics
        WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ? AND non_unique = 0
    ) AS `exists`";
    fetch_exists(executor, sql, params).await
}

async fn foreign_key(
    executor: &mut DieselMysqlExecutor<'_>,
    table: &str,
    column: &str,
) -> Result<Option<ForeignKey>, RustAuthError> {
    let table_field = DbField::new("table", DbFieldType::String);
    let column_field = DbField::new("column", DbFieldType::String);
    let params = vec![
        SqlParam::new(
            &table_field,
            rustauth_core::db::DbValue::String(table.to_owned()),
        ),
        SqlParam::new(
            &column_field,
            rustauth_core::db::DbValue::String(column.to_owned()),
        ),
    ];
    let sql = "SELECT CAST(kcu.referenced_table_name AS CHAR CHARACTER SET utf8mb4) AS ref_table, \
        CAST(kcu.referenced_column_name AS CHAR CHARACTER SET utf8mb4) AS ref_column, \
        CAST(rc.delete_rule AS CHAR CHARACTER SET utf8mb4) AS delete_rule \
        FROM information_schema.key_column_usage kcu \
        JOIN information_schema.referential_constraints rc \
          ON rc.constraint_schema = kcu.constraint_schema \
         AND rc.constraint_name = kcu.constraint_name \
        WHERE kcu.table_schema = DATABASE() \
          AND kcu.table_name = ? \
          AND kcu.column_name = ? \
          AND kcu.referenced_table_name IS NOT NULL";
    let row = fetch_optional_row::<ForeignKeyRow>(executor, sql, params).await?;
    Ok(row.map(|row| {
        ForeignKey::new(
            row.ref_table,
            row.ref_column,
            parse_on_delete(&row.delete_rule),
        )
    }))
}

async fn fetch_exists(
    executor: &mut DieselMysqlExecutor<'_>,
    sql: &str,
    params: Vec<SqlParam>,
) -> Result<bool, RustAuthError> {
    let row = fetch_one_row::<ExistsRow>(executor, sql, params).await?;
    Ok(row.exists)
}

async fn fetch_one_row<T>(
    executor: &mut DieselMysqlExecutor<'_>,
    sql: &str,
    params: Vec<SqlParam>,
) -> Result<T, RustAuthError>
where
    T: QueryableByName<diesel::mysql::Mysql> + Send + 'static,
{
    let query = bind_mysql_params(sql, &params)?;
    match executor {
        DieselMysqlExecutor::Pool(pool) => {
            let mut pooled = pool.get().await.map_err(pool_error)?;
            let conn = &mut *pooled;
            query.get_result(conn).await.map_err(diesel_error)
        }
        DieselMysqlExecutor::Transaction(conn) => {
            let conn = conn.as_mut().ok_or_else(inactive_transaction)?.as_mut();
            query.get_result(conn).await.map_err(diesel_error)
        }
    }
}

async fn fetch_optional_row<T>(
    executor: &mut DieselMysqlExecutor<'_>,
    sql: &str,
    params: Vec<SqlParam>,
) -> Result<Option<T>, RustAuthError>
where
    T: QueryableByName<diesel::mysql::Mysql> + Send + 'static,
{
    let query = bind_mysql_params(sql, &params)?;
    match executor {
        DieselMysqlExecutor::Pool(pool) => {
            let mut pooled = pool.get().await.map_err(pool_error)?;
            let conn = &mut *pooled;
            query.get_result(conn).await.map(Some).or_else(|error| {
                if matches!(error, diesel::result::Error::NotFound) {
                    Ok(None)
                } else {
                    Err(diesel_error(error))
                }
            })
        }
        DieselMysqlExecutor::Transaction(conn) => {
            let conn = conn.as_mut().ok_or_else(inactive_transaction)?.as_mut();
            query.get_result(conn).await.map(Some).or_else(|error| {
                if matches!(error, diesel::result::Error::NotFound) {
                    Ok(None)
                } else {
                    Err(diesel_error(error))
                }
            })
        }
    }
}

pub(super) async fn execute_migration_plan(
    executor: &mut DieselMysqlExecutor<'_>,
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
    pool: &Pool<AsyncMysqlConnection>,
    plan: &SchemaMigrationPlan,
) -> Result<(), RustAuthError> {
    let mut applied = Vec::new();
    for statement in &plan.statements {
        match execute_schema_sql_on_pool(pool, &statement.sql).await {
            Ok(()) => applied.push(statement),
            Err(error) => {
                compensate_mysql_applied_statements(pool, &applied).await;
                return Err(error);
            }
        }
    }
    Ok(())
}

async fn compensate_mysql_applied_statements(
    pool: &Pool<AsyncMysqlConnection>,
    applied: &[&MigrationStatement],
) {
    for statement in applied.iter().rev() {
        let Some(rollback_sql) = mysql_rollback_statement(statement) else {
            continue;
        };
        let _ = execute_schema_sql_on_pool(pool, &rollback_sql).await;
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

async fn execute_schema_sql_on_pool(
    pool: &Pool<AsyncMysqlConnection>,
    sql: &str,
) -> Result<(), RustAuthError> {
    let mut pooled = pool.get().await.map_err(pool_error)?;
    let conn = &mut *pooled;
    diesel_async::RunQueryDsl::execute(diesel::sql_query(sql), conn)
        .await
        .map_err(diesel_error)?;
    Ok(())
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
    executor: &mut DieselMysqlExecutor<'_>,
    sql: &str,
) -> Result<(), RustAuthError> {
    match executor {
        DieselMysqlExecutor::Pool(pool) => execute_schema_sql_on_pool(pool, sql).await,
        DieselMysqlExecutor::Transaction(conn) => {
            let conn = conn.as_mut().ok_or_else(inactive_transaction)?.as_mut();
            diesel_async::RunQueryDsl::execute(diesel::sql_query(sql), conn)
                .await
                .map_err(diesel_error)?;
            Ok(())
        }
    }
}
