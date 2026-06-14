use std::collections::{HashMap, HashSet};

use rustauth_core::db::{
    ensure_executable_migration_plan, execute_schema_migration_plan, plan_schema_migration,
    AdapterFuture, DbSchema, ForeignKey, OnDelete, SqlColumnSnapshot, SqlDialect, SqlExecutor,
    SqlSchemaSnapshot, SqlStatement,
};
use rustauth_core::error::RustAuthError;
use tokio_postgres::{Client, Row};

use super::errors::postgres_error;
use rustauth_core::db::SchemaMigrationPlan;

pub async fn plan_migrations(
    client: &Client,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, RustAuthError> {
    let snapshot = load_schema_snapshot(client, schema).await?;
    plan_schema_migration(SqlDialect::Postgres, schema, &snapshot)
}

pub async fn create_schema(client: &Client, schema: &DbSchema) -> Result<(), RustAuthError> {
    let plan = plan_migrations(client, schema).await?;
    ensure_executable_migration_plan(&plan)?;
    execute_statements(client, &plan).await
}

pub async fn execute_migration_plan(
    client: &Client,
    schema: &DbSchema,
) -> Result<(), RustAuthError> {
    let plan = plan_migrations(client, schema).await?;
    ensure_executable_migration_plan(&plan)?;
    execute_statements(client, &plan).await
}

async fn execute_statements(
    client: &Client,
    plan: &SchemaMigrationPlan,
) -> Result<(), RustAuthError> {
    client
        .batch_execute("BEGIN")
        .await
        .map_err(postgres_error)?;
    let result = execute_schema_migration_plan(&mut PostgresSchemaExecutor { client }, plan).await;
    match result {
        Ok(()) => {
            if let Err(error) = client.batch_execute("COMMIT").await {
                let _rollback_result = client.batch_execute("ROLLBACK").await;
                return Err(postgres_error(error));
            }
            Ok(())
        }
        Err(error) => {
            let _rollback_result = client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}

/// Applies a prepared migration plan inside one Postgres transaction.
///
/// Exposed for integration tests that verify rollback behavior on failure.
#[doc(hidden)]
pub async fn apply_migration_plan(
    client: &Client,
    plan: &SchemaMigrationPlan,
) -> Result<(), RustAuthError> {
    execute_statements(client, plan).await
}

/// Loads the current database state with a fixed number of set-based catalog
/// queries per schema qualifier, instead of several round trips per column.
/// Per-column introspection through `information_schema` views (notably
/// `constraint_column_usage`) costs ~100ms per query on Postgres, which made
/// migration planning take tens of seconds for the full auth schema.
async fn load_schema_snapshot(
    client: &Client,
    schema: &DbSchema,
) -> Result<SqlSchemaSnapshot, RustAuthError> {
    let mut tables = schema.tables().collect::<Vec<_>>();
    tables.sort_by_key(|(_, table)| table.order.unwrap_or(u16::MAX));

    let mut groups: Vec<(Option<&str>, Vec<String>)> = Vec::new();
    for (_, table) in &tables {
        let table_name = PostgresTableName::parse(&table.name)?;
        match groups
            .iter_mut()
            .find(|(schema, _)| *schema == table_name.schema)
        {
            Some((_, names)) => names.push(table_name.name.to_owned()),
            None => groups.push((table_name.schema, vec![table_name.name.to_owned()])),
        }
    }

    let mut catalogs: HashMap<Option<&str>, SchemaCatalog> = HashMap::new();
    for (schema_name, names) in &groups {
        let catalog = SchemaCatalog::load(client, *schema_name, names).await?;
        catalogs.insert(*schema_name, catalog);
    }

    let mut snapshot = SqlSchemaSnapshot::default();
    for (_, table) in &tables {
        let table_name = PostgresTableName::parse(&table.name)?;
        let Some(catalog) = catalogs.get(&table_name.schema) else {
            continue;
        };

        if catalog.tables.contains(table_name.name) {
            snapshot = snapshot.with_table(&table.name);
            for (_, field) in &table.fields {
                let key = (table_name.name.to_owned(), field.name.clone());
                if let Some(actual_type) = catalog.column_types.get(&key) {
                    let mut column = SqlColumnSnapshot::new(&field.name, actual_type);
                    if let Some(foreign_key) = catalog.foreign_key(&table_name, &key) {
                        column = column.references(foreign_key);
                    }
                    snapshot = snapshot.with_column(&table.name, column);
                    if catalog.unique_columns.contains(&key) {
                        snapshot = snapshot.with_unique_column(&table.name, &field.name);
                    }
                }
            }
        }

        for (logical_name, field) in &table.fields {
            if field.index && !field.unique {
                let index_name = SqlDialect::Postgres
                    .sanitize_identifier(&format!("idx_{}_{}", table.name, logical_name))?;
                if catalog.indexes.contains(&index_name) {
                    snapshot = snapshot.with_index(&table.name, index_name);
                }
            }
        }
    }

    Ok(snapshot)
}

#[derive(Debug, Default)]
struct SchemaCatalog {
    current_schema: String,
    tables: HashSet<String>,
    /// Keyed by `(table, column)`.
    column_types: HashMap<(String, String), String>,
    unique_columns: HashSet<(String, String)>,
    /// First foreign key seen per `(table, column)`, as `(ref_schema, ref_table, ref_column, delete_rule)`.
    foreign_keys: HashMap<(String, String), (String, String, String, OnDelete)>,
    indexes: HashSet<String>,
}

impl SchemaCatalog {
    async fn load(
        client: &Client,
        schema_name: Option<&str>,
        table_names: &[String],
    ) -> Result<Self, RustAuthError> {
        let mut catalog = Self::default();
        let table_names = table_names.to_vec();

        catalog.current_schema = client
            .query_one("SELECT current_schema()", &[])
            .await
            .map_err(postgres_error)?
            .get::<_, String>(0);

        let table_rows = client
            .query(
                "SELECT table_name::text FROM information_schema.tables \
                 WHERE table_schema = COALESCE($1, current_schema()) AND table_name = ANY($2)",
                &[&schema_name, &table_names],
            )
            .await
            .map_err(postgres_error)?;
        catalog.tables = table_rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect();

        let column_rows = client
            .query(
                "SELECT table_name::text, column_name::text, \
                        CASE WHEN data_type = 'ARRAY' THEN udt_name::text ELSE data_type::text END \
                 FROM information_schema.columns \
                 WHERE table_schema = COALESCE($1, current_schema()) AND table_name = ANY($2)",
                &[&schema_name, &table_names],
            )
            .await
            .map_err(postgres_error)?;
        for row in column_rows {
            catalog
                .column_types
                .insert((row.get(0), row.get(1)), row.get(2));
        }

        let unique_rows = client
            .query(
                "SELECT tbl.relname::text, attr.attname::text \
                 FROM pg_constraint con \
                 JOIN pg_class tbl ON tbl.oid = con.conrelid \
                 JOIN pg_namespace ns ON ns.oid = tbl.relnamespace \
                 JOIN pg_attribute attr \
                   ON attr.attrelid = tbl.oid AND attr.attnum = ANY(con.conkey) \
                 WHERE con.contype IN ('u', 'p') \
                   AND ns.nspname = COALESCE($1, current_schema()) \
                   AND tbl.relname = ANY($2)",
                &[&schema_name, &table_names],
            )
            .await
            .map_err(postgres_error)?;
        catalog.unique_columns = unique_rows
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();

        let foreign_key_rows = client
            .query(
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
                &[&schema_name, &table_names],
            )
            .await
            .map_err(postgres_error)?;
        for row in foreign_key_rows {
            let delete_rule = parse_on_delete(&row.get::<_, String>(5));
            catalog
                .foreign_keys
                .entry((row.get(0), row.get(1)))
                .or_insert((row.get(2), row.get(3), row.get(4), delete_rule));
        }

        let index_rows = client
            .query(
                "SELECT indexname::text FROM pg_indexes \
                 WHERE schemaname = COALESCE($1, current_schema()) AND tablename = ANY($2)",
                &[&schema_name, &table_names],
            )
            .await
            .map_err(postgres_error)?;
        catalog.indexes = index_rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect();

        Ok(catalog)
    }

    fn foreign_key(
        &self,
        table_name: &PostgresTableName<'_>,
        key: &(String, String),
    ) -> Option<ForeignKey> {
        let (ref_schema, ref_table, ref_column, on_delete) = self.foreign_keys.get(key)?;
        let target_table = if table_name.schema.is_none() && *ref_schema == self.current_schema {
            ref_table.clone()
        } else {
            format!("{ref_schema}.{ref_table}")
        };
        Some(ForeignKey::new(target_table, ref_column, *on_delete))
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

struct PostgresTableName<'a> {
    schema: Option<&'a str>,
    name: &'a str,
}

impl<'a> PostgresTableName<'a> {
    fn parse(value: &'a str) -> Result<Self, RustAuthError> {
        let mut parts = value.split('.');
        let first = parts.next().unwrap_or_default();
        let second = parts.next();
        if parts.next().is_some() || first.is_empty() || second == Some("") {
            return Err(RustAuthError::Adapter(format!(
                "invalid PostgreSQL table name `{value}`"
            )));
        }
        Ok(match second {
            Some(name) => Self {
                schema: Some(first),
                name,
            },
            None => Self {
                schema: None,
                name: first,
            },
        })
    }
}

pub struct PostgresSchemaExecutor<'a> {
    pub client: &'a Client,
}

impl SqlExecutor for PostgresSchemaExecutor<'_> {
    type Row = Row;

    fn execute<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.client
                .execute(&statement.sql, &[])
                .await
                .map_err(postgres_error)
        })
    }

    fn fetch_all<'a>(&'a mut self, _statement: SqlStatement) -> AdapterFuture<'a, Vec<Self::Row>> {
        Box::pin(async {
            Err(RustAuthError::Adapter(
                "schema executor does not fetch rows".to_owned(),
            ))
        })
    }

    fn fetch_optional<'a>(
        &'a mut self,
        _statement: SqlStatement,
    ) -> AdapterFuture<'a, Option<Self::Row>> {
        Box::pin(async {
            Err(RustAuthError::Adapter(
                "schema executor does not fetch rows".to_owned(),
            ))
        })
    }

    fn fetch_scalar_i64<'a>(&'a mut self, _statement: SqlStatement) -> AdapterFuture<'a, i64> {
        Box::pin(async {
            Err(RustAuthError::Adapter(
                "schema executor does not fetch scalar values".to_owned(),
            ))
        })
    }
}
