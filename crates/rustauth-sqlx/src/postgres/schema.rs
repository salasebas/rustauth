use std::collections::{HashMap, HashSet};

use rustauth_core::db::{
    plan_schema_migration, DbSchema, ForeignKey, IdGeneration, OnDelete, SqlColumnSnapshot,
    SqlDialect, SqlSchemaSnapshot,
};
use rustauth_core::error::RustAuthError;
use sqlx::postgres::PgRow;

use super::errors::{inactive_transaction, sql_error};
use super::state::PostgresExecutor;
use super::support::sanitize_identifier;
use rustauth_core::db::SchemaMigrationPlan;

pub(super) async fn plan_migrations(
    mut executor: PostgresExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, RustAuthError> {
    build_migration_plan(&mut executor, schema).await
}

pub(super) async fn create_schema(
    mut executor: PostgresExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<(), RustAuthError> {
    let plan = build_migration_plan(&mut executor, schema).await?;
    crate::migration::ensure_executable(&plan)?;
    match executor {
        PostgresExecutor::Pool(pool) => execute_migration_plan_on_pool(pool, &plan).await,
        PostgresExecutor::Transaction(guard) => {
            execute_migration_plan(&mut PostgresExecutor::Transaction(guard), &plan).await
        }
    }
}

async fn build_migration_plan(
    executor: &mut PostgresExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, RustAuthError> {
    let snapshot = load_schema_snapshot(executor, schema).await?;
    plan_schema_migration(SqlDialect::Postgres, schema, &snapshot)
}

/// Loads the current database state with a fixed number of set-based catalog
/// queries per schema qualifier, instead of several round trips per column.
/// Per-column introspection through `information_schema` views (notably
/// `constraint_column_usage`) costs ~100ms per query on Postgres, which made
/// migration planning take tens of seconds for the full auth schema.
async fn load_schema_snapshot(
    executor: &mut PostgresExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<SqlSchemaSnapshot, RustAuthError> {
    let mut tables = schema.tables().collect::<Vec<_>>();
    tables.sort_by_key(|(_, table)| table.order.unwrap_or(u16::MAX));

    let mut groups: Vec<(Option<&str>, Vec<String>)> = Vec::new();
    for (_, table) in &tables {
        let table_ref = PgTableRef::new(&table.name);
        match groups
            .iter_mut()
            .find(|(schema, _)| *schema == table_ref.schema)
        {
            Some((_, names)) => names.push(table_ref.name.to_owned()),
            None => groups.push((table_ref.schema, vec![table_ref.name.to_owned()])),
        }
    }

    let mut catalogs: HashMap<Option<&str>, SchemaCatalog> = HashMap::new();
    for (schema_name, names) in &groups {
        let catalog = SchemaCatalog::load(executor, *schema_name, names).await?;
        catalogs.insert(*schema_name, catalog);
    }

    let mut snapshot = SqlSchemaSnapshot::default();
    for (_, table) in &tables {
        let table_ref = PgTableRef::new(&table.name);
        let Some(catalog) = catalogs.get(&table_ref.schema) else {
            continue;
        };

        if catalog.tables.contains(table_ref.name) {
            snapshot = snapshot.with_table(&table.name);
            for (_, field) in &table.fields {
                if let Some(column) = catalog.column_snapshot(table_ref, &field.name) {
                    snapshot = snapshot.with_column(&table.name, column);
                }
                if field.unique
                    && catalog
                        .unique_columns
                        .contains(&(table_ref.name.to_owned(), field.name.clone()))
                {
                    snapshot = snapshot.with_unique_column(&table.name, &field.name);
                }
            }
        }

        for (logical_name, field) in &table.fields {
            if field.index || field.unique {
                let prefix = if field.unique { "uidx" } else { "idx" };
                let index_name = format!("{prefix}_{}_{}", table.name, logical_name);
                let index_name = sanitize_identifier(&index_name)?;
                if catalog.indexes.contains(&index_name) {
                    snapshot = snapshot.with_index(&table.name, index_name);
                }
            }
        }
    }

    Ok(snapshot)
}

#[derive(Debug, Clone)]
struct ColumnInfo {
    data_type: String,
    nullable: bool,
    column_default: Option<String>,
    is_identity: bool,
}

#[derive(Debug, Default)]
struct SchemaCatalog {
    tables: HashSet<String>,
    /// Keyed by `(table, column)`.
    columns: HashMap<(String, String), ColumnInfo>,
    primary_key_columns: HashSet<(String, String)>,
    unique_columns: HashSet<(String, String)>,
    /// First foreign key seen per `(table, column)`, as `(ref_schema, ref_table, ref_column, delete_rule)`.
    foreign_keys: HashMap<(String, String), (String, String, String, OnDelete)>,
    indexes: HashSet<String>,
}

impl SchemaCatalog {
    async fn load(
        executor: &mut PostgresExecutor<'_, '_>,
        schema_name: Option<&str>,
        table_names: &[String],
    ) -> Result<Self, RustAuthError> {
        let mut catalog = Self::default();

        let table_rows: Vec<(String,)> = fetch_catalog_rows(
            executor,
            "SELECT table_name::text FROM information_schema.tables \
             WHERE table_schema = COALESCE($1, current_schema()) \
               AND table_type = 'BASE TABLE' AND table_name = ANY($2)",
            schema_name,
            table_names,
        )
        .await?;
        catalog.tables = table_rows.into_iter().map(|(name,)| name).collect();

        let column_rows: Vec<(String, String, String, bool, Option<String>, bool)> =
            fetch_catalog_rows(
                executor,
                "SELECT table_name::text, column_name::text, \
                        CASE WHEN data_type = 'ARRAY' THEN udt_name::text ELSE data_type::text END, \
                        is_nullable = 'YES', \
                        column_default::text, \
                        is_identity = 'YES' \
                 FROM information_schema.columns \
                 WHERE table_schema = COALESCE($1, current_schema()) AND table_name = ANY($2)",
                schema_name,
                table_names,
            )
            .await?;
        for (table, column, data_type, nullable, column_default, is_identity) in column_rows {
            catalog.columns.insert(
                (table, column),
                ColumnInfo {
                    data_type,
                    nullable,
                    column_default,
                    is_identity,
                },
            );
        }

        let index_column_rows: Vec<(String, String, bool, bool)> = fetch_catalog_rows(
            executor,
            "SELECT tbl.relname::text, attr.attname::text, \
                    bool_or(i.indisprimary), bool_or(i.indisunique) \
             FROM pg_index i \
             JOIN pg_class tbl ON tbl.oid = i.indrelid \
             JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
             JOIN pg_attribute attr ON attr.attrelid = tbl.oid AND attr.attnum = ANY(i.indkey) \
             WHERE ns.nspname = COALESCE($1, current_schema()) \
               AND tbl.relname = ANY($2) \
               AND NOT attr.attisdropped \
             GROUP BY tbl.relname, attr.attname",
            schema_name,
            table_names,
        )
        .await?;
        for (table, column, is_primary, is_unique) in index_column_rows {
            if is_primary {
                catalog
                    .primary_key_columns
                    .insert((table.clone(), column.clone()));
            }
            if is_unique {
                catalog.unique_columns.insert((table.clone(), column));
            }
        }

        let foreign_key_rows: Vec<(String, String, String, String, String, String)> =
            fetch_catalog_rows(
                executor,
                "SELECT src.relname::text, src_attr.attname::text, \
                        ref_ns.nspname::text, ref.relname::text, ref_attr.attname::text, \
                        con.confdeltype::text \
                 FROM pg_constraint con \
                 JOIN pg_class src ON src.oid = con.conrelid \
                 JOIN pg_namespace src_ns ON src_ns.oid = src.relnamespace \
                 JOIN pg_class ref ON ref.oid = con.confrelid \
                 JOIN pg_namespace ref_ns ON ref_ns.oid = ref.relnamespace \
                 CROSS JOIN LATERAL unnest(con.conkey, con.confkey) AS cols(src_attnum, ref_attnum) \
                 JOIN pg_attribute src_attr \
                   ON src_attr.attrelid = src.oid AND src_attr.attnum = cols.src_attnum \
                 JOIN pg_attribute ref_attr \
                   ON ref_attr.attrelid = ref.oid AND ref_attr.attnum = cols.ref_attnum \
                 WHERE con.contype = 'f' \
                   AND src_ns.nspname = COALESCE($1, current_schema()) \
                   AND src.relname = ANY($2)",
                schema_name,
                table_names,
            )
            .await?;
        for (table, column, ref_schema, ref_table, ref_column, delete_rule) in foreign_key_rows {
            catalog.foreign_keys.entry((table, column)).or_insert((
                ref_schema,
                ref_table,
                ref_column,
                parse_on_delete(&delete_rule),
            ));
        }

        let index_rows: Vec<(String,)> = fetch_catalog_rows(
            executor,
            "SELECT indexname::text FROM pg_indexes \
             WHERE schemaname = COALESCE($1, current_schema()) AND tablename = ANY($2)",
            schema_name,
            table_names,
        )
        .await?;
        catalog.indexes = index_rows.into_iter().map(|(name,)| name).collect();

        Ok(catalog)
    }

    fn column_snapshot(
        &self,
        table_ref: PgTableRef<'_>,
        column: &str,
    ) -> Option<SqlColumnSnapshot> {
        let key = (table_ref.name.to_owned(), column.to_owned());
        let info = self.columns.get(&key)?;
        let generated_id = if info.is_identity {
            Some(IdGeneration::Serial)
        } else if info
            .column_default
            .as_deref()
            .is_some_and(|default| default.contains("gen_random_uuid"))
        {
            Some(IdGeneration::Uuid)
        } else {
            None
        };
        let mut snapshot = SqlColumnSnapshot::new(column, &info.data_type)
            .nullable(info.nullable)
            .primary_key(self.primary_key_columns.contains(&key))
            .generated_id(generated_id);
        if let Some((ref_schema, ref_table, ref_column, on_delete)) = self.foreign_keys.get(&key) {
            let target_table = match table_ref.schema {
                Some(_) => format!("{ref_schema}.{ref_table}"),
                None => ref_table.clone(),
            };
            snapshot = snapshot.references(ForeignKey::new(target_table, ref_column, *on_delete));
        }
        Some(snapshot)
    }
}

async fn fetch_catalog_rows<T>(
    executor: &mut PostgresExecutor<'_, '_>,
    sql: &str,
    schema_name: Option<&str>,
    table_names: &[String],
) -> Result<Vec<T>, RustAuthError>
where
    T: for<'r> sqlx::FromRow<'r, PgRow> + Send + Unpin,
{
    match executor {
        PostgresExecutor::Pool(pool) => sqlx::query_as::<_, T>(sql)
            .bind(schema_name)
            .bind(table_names)
            .fetch_all(*pool)
            .await
            .map_err(sql_error),
        PostgresExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query_as::<_, T>(sql)
                .bind(schema_name)
                .bind(table_names)
                .fetch_all(&mut **tx)
                .await
                .map_err(sql_error)
        }
    }
}

pub(super) async fn execute_migration_plan(
    executor: &mut PostgresExecutor<'_, '_>,
    plan: &SchemaMigrationPlan,
) -> Result<(), RustAuthError> {
    for statement in &plan.statements {
        execute_schema_sql(executor, &statement.sql).await?;
    }
    Ok(())
}

pub(super) async fn execute_migration_plan_on_pool(
    pool: &sqlx::PgPool,
    plan: &SchemaMigrationPlan,
) -> Result<(), RustAuthError> {
    let mut tx = pool.begin().await.map_err(sql_error)?;
    for statement in &plan.statements {
        sqlx::query(&statement.sql)
            .execute(&mut *tx)
            .await
            .map_err(sql_error)?;
    }
    tx.commit().await.map_err(sql_error)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct PgTableRef<'a> {
    schema: Option<&'a str>,
    name: &'a str,
}

impl<'a> PgTableRef<'a> {
    fn new(table: &'a str) -> Self {
        match table.split_once('.') {
            Some((schema, name)) => Self {
                schema: Some(schema),
                name,
            },
            None => Self {
                schema: None,
                name: table,
            },
        }
    }
}

/// Maps `pg_constraint.confdeltype` action codes to [`OnDelete`].
fn parse_on_delete(value: &str) -> OnDelete {
    match value {
        "r" => OnDelete::Restrict,
        "c" => OnDelete::Cascade,
        "n" => OnDelete::SetNull,
        "d" => OnDelete::SetDefault,
        _ => OnDelete::NoAction,
    }
}

pub(super) async fn execute_schema_sql(
    executor: &mut PostgresExecutor<'_, '_>,
    sql: &str,
) -> Result<(), RustAuthError> {
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
