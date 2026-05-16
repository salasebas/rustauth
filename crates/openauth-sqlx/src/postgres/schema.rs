use openauth_core::db::{
    plan_schema_migration, DbSchema, SqlColumnSnapshot, SqlDialect, SqlSchemaSnapshot,
};
use openauth_core::error::OpenAuthError;

use super::errors::{inactive_transaction, sql_error};
use super::state::PostgresExecutor;
use super::support::sanitize_identifier;
use crate::migration::SchemaMigrationPlan;

pub(super) async fn plan_migrations(
    mut executor: PostgresExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    build_migration_plan(&mut executor, schema).await
}

pub(super) async fn create_schema(
    mut executor: PostgresExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<(), OpenAuthError> {
    let plan = build_migration_plan(&mut executor, schema).await?;
    execute_migration_plan(&mut executor, &plan).await
}

async fn build_migration_plan(
    executor: &mut PostgresExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    let snapshot = load_schema_snapshot(executor, schema).await?;
    plan_schema_migration(SqlDialect::Postgres, schema, &snapshot)
}

async fn load_schema_snapshot(
    executor: &mut PostgresExecutor<'_, '_>,
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
                if index_exists(executor, &index_name).await? {
                    snapshot = snapshot.with_index(&table.name, index_name);
                }
            }
        }
    }

    Ok(snapshot)
}

pub(super) async fn execute_migration_plan(
    executor: &mut PostgresExecutor<'_, '_>,
    plan: &SchemaMigrationPlan,
) -> Result<(), OpenAuthError> {
    for statement in &plan.statements {
        execute_schema_sql(executor, &statement.sql).await?;
    }
    Ok(())
}

async fn table_exists(
    executor: &mut PostgresExecutor<'_, '_>,
    table: &str,
) -> Result<bool, OpenAuthError> {
    let exists = match executor {
        PostgresExecutor::Pool(pool) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' AND table_name = $1)",
        )
        .bind(table)
        .fetch_one(*pool)
        .await
        .map_err(sql_error)?,
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' AND table_name = $1)",
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
    executor: &mut PostgresExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<Option<String>, OpenAuthError> {
    let column_type = match executor {
        PostgresExecutor::Pool(pool) => sqlx::query_scalar::<_, String>(
            "SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(*pool)
        .await
        .map_err(sql_error)?,
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, String>(
                "SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
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
    executor: &mut PostgresExecutor<'_, '_>,
    index: &str,
) -> Result<bool, OpenAuthError> {
    let exists = match executor {
        PostgresExecutor::Pool(pool) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1)",
        )
        .bind(index)
        .fetch_one(*pool)
        .await
        .map_err(sql_error)?,
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1)",
            )
            .bind(index)
            .fetch_one(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    Ok(exists)
}

pub(super) async fn execute_schema_sql(
    executor: &mut PostgresExecutor<'_, '_>,
    sql: &str,
) -> Result<(), OpenAuthError> {
    match executor {
        PostgresExecutor::Pool(pool) => {
            sqlx::query(sql).execute(*pool).await.map_err(sql_error)?;
        }
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query(sql)
                .execute(&mut **tx)
                .await
                .map_err(sql_error)?;
        }
    }
    Ok(())
}
