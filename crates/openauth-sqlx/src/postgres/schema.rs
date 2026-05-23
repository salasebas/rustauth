use openauth_core::db::{
    plan_schema_migration, DbSchema, ForeignKey, IdGeneration, OnDelete, SqlColumnSnapshot,
    SqlDialect, SqlSchemaSnapshot,
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
    crate::migration::ensure_executable(&plan)?;
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

async fn column_snapshot(
    executor: &mut PostgresExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<Option<SqlColumnSnapshot>, OpenAuthError> {
    let row = match executor {
        PostgresExecutor::Pool(pool) => sqlx::query_as::<_, (String, bool, Option<String>, bool)>(
            "SELECT CASE WHEN data_type = 'ARRAY' THEN udt_name ELSE data_type END, \
                    is_nullable = 'YES', \
                    column_default, \
                    is_identity = 'YES' \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(*pool)
        .await
        .map_err(sql_error)?,
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_as::<_, (String, bool, Option<String>, bool)>(
                "SELECT CASE WHEN data_type = 'ARRAY' THEN udt_name ELSE data_type END, \
                        is_nullable = 'YES', \
                        column_default, \
                        is_identity = 'YES' \
                 FROM information_schema.columns \
                 WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
            )
            .bind(table)
            .bind(column)
            .fetch_optional(&mut **tx)
            .await
            .map_err(sql_error)?
        }
    };
    let Some((data_type, nullable, column_default, is_identity)) = row else {
        return Ok(None);
    };
    let primary_key = primary_key_column_exists(executor, table, column).await?;
    let generated_id = if is_identity {
        Some(IdGeneration::Serial)
    } else if column_default
        .as_deref()
        .is_some_and(|default| default.contains("gen_random_uuid"))
    {
        Some(IdGeneration::Uuid)
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

async fn unique_column_exists(
    executor: &mut PostgresExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<bool, OpenAuthError> {
    let exists = match executor {
        PostgresExecutor::Pool(pool) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
             SELECT 1 \
             FROM pg_index i \
             JOIN pg_class tbl ON tbl.oid = i.indrelid \
             JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
             JOIN pg_attribute attr ON attr.attrelid = tbl.oid AND attr.attnum = ANY(i.indkey) \
             WHERE ns.nspname = current_schema() \
               AND tbl.relname = $1 \
               AND attr.attname = $2 \
               AND i.indisunique \
             )",
        )
        .bind(table)
        .bind(column)
        .fetch_one(*pool)
        .await
        .map_err(sql_error)?,
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS ( \
                 SELECT 1 \
                 FROM pg_index i \
                 JOIN pg_class tbl ON tbl.oid = i.indrelid \
                 JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
                 JOIN pg_attribute attr ON attr.attrelid = tbl.oid AND attr.attnum = ANY(i.indkey) \
                 WHERE ns.nspname = current_schema() \
                   AND tbl.relname = $1 \
                   AND attr.attname = $2 \
                   AND i.indisunique \
                 )",
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

async fn primary_key_column_exists(
    executor: &mut PostgresExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<bool, OpenAuthError> {
    let exists = match executor {
        PostgresExecutor::Pool(pool) => sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
             SELECT 1 \
             FROM pg_index i \
             JOIN pg_class tbl ON tbl.oid = i.indrelid \
             JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
             JOIN pg_attribute attr ON attr.attrelid = tbl.oid AND attr.attnum = ANY(i.indkey) \
             WHERE ns.nspname = current_schema() \
               AND tbl.relname = $1 \
               AND attr.attname = $2 \
               AND i.indisprimary \
             )",
        )
        .bind(table)
        .bind(column)
        .fetch_one(*pool)
        .await
        .map_err(sql_error)?,
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS ( \
                 SELECT 1 \
                 FROM pg_index i \
                 JOIN pg_class tbl ON tbl.oid = i.indrelid \
                 JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
                 JOIN pg_attribute attr ON attr.attrelid = tbl.oid AND attr.attnum = ANY(i.indkey) \
                 WHERE ns.nspname = current_schema() \
                   AND tbl.relname = $1 \
                   AND attr.attname = $2 \
                   AND i.indisprimary \
                 )",
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
    executor: &mut PostgresExecutor<'_, '_>,
    table: &str,
    column: &str,
) -> Result<Option<ForeignKey>, OpenAuthError> {
    let row = match executor {
        PostgresExecutor::Pool(pool) => sqlx::query_as::<_, (String, String, String)>(
            "SELECT ccu.table_name, ccu.column_name, rc.delete_rule \
             FROM information_schema.table_constraints tc \
             JOIN information_schema.key_column_usage kcu \
               ON tc.constraint_name = kcu.constraint_name AND tc.constraint_schema = kcu.constraint_schema \
             JOIN information_schema.constraint_column_usage ccu \
               ON ccu.constraint_name = tc.constraint_name AND ccu.constraint_schema = tc.constraint_schema \
             JOIN information_schema.referential_constraints rc \
               ON rc.constraint_name = tc.constraint_name AND rc.constraint_schema = tc.constraint_schema \
             WHERE tc.table_schema = current_schema() \
               AND tc.table_name = $1 \
               AND kcu.column_name = $2 \
               AND tc.constraint_type = 'FOREIGN KEY'",
        )
        .bind(table)
        .bind(column)
        .fetch_optional(*pool)
        .await
        .map_err(sql_error)?,
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_as::<_, (String, String, String)>(
                "SELECT ccu.table_name, ccu.column_name, rc.delete_rule \
                 FROM information_schema.table_constraints tc \
                 JOIN information_schema.key_column_usage kcu \
                   ON tc.constraint_name = kcu.constraint_name AND tc.constraint_schema = kcu.constraint_schema \
                 JOIN information_schema.constraint_column_usage ccu \
                   ON ccu.constraint_name = tc.constraint_name AND ccu.constraint_schema = tc.constraint_schema \
                 JOIN information_schema.referential_constraints rc \
                   ON rc.constraint_name = tc.constraint_name AND rc.constraint_schema = tc.constraint_schema \
                 WHERE tc.table_schema = current_schema() \
                   AND tc.table_name = $1 \
                   AND kcu.column_name = $2 \
                   AND tc.constraint_type = 'FOREIGN KEY'",
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
