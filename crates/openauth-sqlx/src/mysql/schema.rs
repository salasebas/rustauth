use openauth_core::db::{
    plan_schema_migration, DbSchema, SqlColumnSnapshot, SqlDialect, SqlSchemaSnapshot,
};
use openauth_core::error::OpenAuthError;

use super::errors::{inactive_transaction, sql_error};
use super::state::MySqlExecutor;
use super::support::sanitize_identifier;
use crate::migration::SchemaMigrationPlan;

pub(super) async fn plan_migrations(
    mut executor: MySqlExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    build_migration_plan(&mut executor, schema).await
}

pub(super) async fn create_schema(
    mut executor: MySqlExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<(), OpenAuthError> {
    let plan = build_migration_plan(&mut executor, schema).await?;
    execute_migration_plan(&mut executor, &plan).await
}

async fn build_migration_plan(
    executor: &mut MySqlExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    let snapshot = load_schema_snapshot(executor, schema).await?;
    plan_schema_migration(SqlDialect::MySql, schema, &snapshot)
}

async fn load_schema_snapshot(
    executor: &mut MySqlExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SqlSchemaSnapshot, OpenAuthError> {
    let mut snapshot = SqlSchemaSnapshot::default();
    let mut tables = schema.tables().collect::<Vec<_>>();
    tables.sort_by_key(|(_, table)| table.order.unwrap_or(u16::MAX));

    for (_, table) in &tables {
        if table_exists(executor, &table.name).await? {
            snapshot = snapshot.with_table(&table.name);
            for (_, field) in &table.fields {
                if let Some(actual_type) = column_type(executor, &table.name, &field.name).await? {
                    snapshot = snapshot.with_column(
                        &table.name,
                        SqlColumnSnapshot::new(&field.name, actual_type),
                    );
                }
            }
        }

        for (logical_name, field) in &table.fields {
            if field.index && !field.unique {
                let index_name = format!("idx_{}_{}", table.name, logical_name);
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
) -> Result<(), OpenAuthError> {
    for statement in &plan.statements {
        execute_schema_sql(executor, &statement.sql).await?;
    }
    Ok(())
}

async fn table_exists(
    executor: &mut MySqlExecutor<'_, '_>,
    table: &str,
) -> Result<bool, OpenAuthError> {
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

async fn column_type(
    executor: &mut MySqlExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<Option<String>, OpenAuthError> {
    let column_type = match executor {
        MySqlExecutor::Pool(pool) => sqlx::query_scalar::<_, String>(
            "SELECT CAST(data_type AS CHAR) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(*pool)
        .await
        .map_err(sql_error)?,
        MySqlExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, String>(
                "SELECT CAST(data_type AS CHAR) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
            )
            .bind(table)
            .bind(column)
            .fetch_optional(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    Ok(column_type)
}

async fn index_exists(
    executor: &mut MySqlExecutor<'_, '_>,
    table: &str,
    index: &str,
) -> Result<bool, OpenAuthError> {
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

pub(super) async fn execute_schema_sql(
    executor: &mut MySqlExecutor<'_, '_>,
    sql: &str,
) -> Result<(), OpenAuthError> {
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
