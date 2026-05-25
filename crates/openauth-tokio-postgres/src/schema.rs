use openauth_core::db::{
    execute_schema_migration_plan, plan_schema_migration, AdapterFuture, DbSchema, ForeignKey,
    OnDelete, SqlColumnSnapshot, SqlDialect, SqlExecutor, SqlSchemaSnapshot, SqlStatement,
};
use openauth_core::error::OpenAuthError;
use tokio_postgres::{Client, Row};

use super::errors::postgres_error;
use crate::migration::SchemaMigrationPlan;

pub async fn plan_migrations(
    client: &Client,
    schema: &DbSchema,
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    let snapshot = load_schema_snapshot(client, schema).await?;
    plan_schema_migration(SqlDialect::Postgres, schema, &snapshot)
}

pub async fn create_schema(client: &Client, schema: &DbSchema) -> Result<(), OpenAuthError> {
    let plan = plan_migrations(client, schema).await?;
    execute_statements(client, &plan).await
}

pub async fn execute_migration_plan(
    client: &Client,
    schema: &DbSchema,
) -> Result<(), OpenAuthError> {
    let plan = plan_migrations(client, schema).await?;
    execute_statements(client, &plan).await
}

async fn execute_statements(
    client: &Client,
    plan: &SchemaMigrationPlan,
) -> Result<(), OpenAuthError> {
    execute_schema_migration_plan(&mut PostgresSchemaExecutor { client }, plan).await
}

async fn load_schema_snapshot(
    client: &Client,
    schema: &DbSchema,
) -> Result<SqlSchemaSnapshot, OpenAuthError> {
    let mut snapshot = SqlSchemaSnapshot::default();
    let mut tables = schema.tables().collect::<Vec<_>>();
    tables.sort_by_key(|(_, table)| table.order.unwrap_or(u16::MAX));

    for (_, table) in &tables {
        if table_exists(client, &table.name).await? {
            snapshot = snapshot.with_table(&table.name);
            for (_, field) in &table.fields {
                if let Some(actual_type) = column_type(client, &table.name, &field.name).await? {
                    let mut column = SqlColumnSnapshot::new(&field.name, actual_type);
                    if let Some(foreign_key) = foreign_key(client, &table.name, &field.name).await?
                    {
                        column = column.references(foreign_key);
                    }
                    snapshot = snapshot.with_column(&table.name, column);
                    if unique_column_exists(client, &table.name, &field.name).await? {
                        snapshot = snapshot.with_unique_column(&table.name, &field.name);
                    }
                }
            }
        }

        for (logical_name, field) in &table.fields {
            if field.index && !field.unique {
                let index_name = SqlDialect::Postgres
                    .sanitize_identifier(&format!("idx_{}_{}", table.name, logical_name))?;
                if index_exists(client, &table.name, &index_name).await? {
                    snapshot = snapshot.with_index(&table.name, index_name);
                }
            }
        }
    }

    Ok(snapshot)
}

async fn table_exists(client: &Client, table: &str) -> Result<bool, OpenAuthError> {
    let table = PostgresTableName::parse(table)?;
    let count = match table.schema {
        Some(schema) => {
            client
                .query_one(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2",
                    &[&schema, &table.name],
                )
                .await
        }
        None => {
            client
                .query_one(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1",
                    &[&table.name],
                )
                .await
        }
    }
    .map_err(postgres_error)?
    .get::<_, i64>(0);
    Ok(count > 0)
}

async fn column_type(
    client: &Client,
    table: &str,
    column: &str,
) -> Result<Option<String>, OpenAuthError> {
    let table = PostgresTableName::parse(table)?;
    let row = match table.schema {
        Some(schema) => {
            client
                .query_opt(
                    "SELECT CASE WHEN data_type = 'ARRAY' THEN udt_name ELSE data_type END \
                     FROM information_schema.columns \
                     WHERE table_schema = $1 AND table_name = $2 AND column_name = $3",
                    &[&schema, &table.name, &column],
                )
                .await
        }
        None => {
            client
                .query_opt(
                    "SELECT CASE WHEN data_type = 'ARRAY' THEN udt_name ELSE data_type END \
                     FROM information_schema.columns \
                     WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
                    &[&table.name, &column],
                )
                .await
        }
    }
    .map_err(postgres_error)?;
    Ok(row.map(|row| row.get::<_, String>(0)))
}

async fn index_exists(client: &Client, table: &str, index: &str) -> Result<bool, OpenAuthError> {
    let table = PostgresTableName::parse(table)?;
    let count = match table.schema {
        Some(schema) => {
            client
                .query_one(
                    "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = $1 AND indexname = $2",
                    &[&schema, &index],
                )
                .await
        }
        None => {
            client
                .query_one(
                    "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1",
                    &[&index],
                )
                .await
        }
    }
    .map_err(postgres_error)?
    .get::<_, i64>(0);
    Ok(count > 0)
}

async fn unique_column_exists(
    client: &Client,
    table: &str,
    column: &str,
) -> Result<bool, OpenAuthError> {
    let table = PostgresTableName::parse(table)?;
    let count = match table.schema {
        Some(schema) => {
            client
                .query_one(
                    "SELECT COUNT(*) \
                     FROM information_schema.table_constraints tc \
                     JOIN information_schema.key_column_usage kcu \
                       ON tc.constraint_schema = kcu.constraint_schema \
                      AND tc.constraint_name = kcu.constraint_name \
                      AND tc.table_name = kcu.table_name \
                     WHERE tc.constraint_schema = $1 \
                       AND tc.table_name = $2 \
                       AND kcu.column_name = $3 \
                       AND tc.constraint_type IN ('UNIQUE', 'PRIMARY KEY')",
                    &[&schema, &table.name, &column],
                )
                .await
        }
        None => {
            client
                .query_one(
                    "SELECT COUNT(*) \
                     FROM information_schema.table_constraints tc \
                     JOIN information_schema.key_column_usage kcu \
                       ON tc.constraint_schema = kcu.constraint_schema \
                      AND tc.constraint_name = kcu.constraint_name \
                      AND tc.table_name = kcu.table_name \
                     WHERE tc.constraint_schema = current_schema() \
                       AND tc.table_name = $1 \
                       AND kcu.column_name = $2 \
                       AND tc.constraint_type IN ('UNIQUE', 'PRIMARY KEY')",
                    &[&table.name, &column],
                )
                .await
        }
    }
    .map_err(postgres_error)?
    .get::<_, i64>(0);
    Ok(count > 0)
}

async fn foreign_key(
    client: &Client,
    table: &str,
    column: &str,
) -> Result<Option<ForeignKey>, OpenAuthError> {
    let table = PostgresTableName::parse(table)?;
    let table_is_schema_qualified = table.schema.is_some();
    let row = match table.schema {
        Some(schema) => {
            client
                .query_opt(
                    "SELECT current_schema(), ccu.table_schema, ccu.table_name, ccu.column_name, rc.delete_rule \
                     FROM information_schema.table_constraints tc \
                     JOIN information_schema.key_column_usage kcu \
                       ON tc.constraint_schema = kcu.constraint_schema \
                      AND tc.constraint_name = kcu.constraint_name \
                      AND tc.table_name = kcu.table_name \
                     JOIN information_schema.referential_constraints rc \
                       ON tc.constraint_schema = rc.constraint_schema \
                      AND tc.constraint_name = rc.constraint_name \
                     JOIN information_schema.constraint_column_usage ccu \
                       ON rc.unique_constraint_schema = ccu.constraint_schema \
                      AND rc.unique_constraint_name = ccu.constraint_name \
                     WHERE tc.constraint_schema = $1 \
                       AND tc.table_name = $2 \
                       AND kcu.column_name = $3 \
                       AND tc.constraint_type = 'FOREIGN KEY'",
                    &[&schema, &table.name, &column],
                )
                .await
        }
        None => {
            client
                .query_opt(
                    "SELECT current_schema(), ccu.table_schema, ccu.table_name, ccu.column_name, rc.delete_rule \
                     FROM information_schema.table_constraints tc \
                     JOIN information_schema.key_column_usage kcu \
                       ON tc.constraint_schema = kcu.constraint_schema \
                      AND tc.constraint_name = kcu.constraint_name \
                      AND tc.table_name = kcu.table_name \
                     JOIN information_schema.referential_constraints rc \
                       ON tc.constraint_schema = rc.constraint_schema \
                      AND tc.constraint_name = rc.constraint_name \
                     JOIN information_schema.constraint_column_usage ccu \
                       ON rc.unique_constraint_schema = ccu.constraint_schema \
                      AND rc.unique_constraint_name = ccu.constraint_name \
                     WHERE tc.constraint_schema = current_schema() \
                       AND tc.table_name = $1 \
                       AND kcu.column_name = $2 \
                       AND tc.constraint_type = 'FOREIGN KEY'",
                    &[&table.name, &column],
                )
                .await
        }
    }
    .map_err(postgres_error)?;

    let Some(row) = row else {
        return Ok(None);
    };
    let current_schema = row.get::<_, String>(0);
    let foreign_schema = row.get::<_, String>(1);
    let foreign_table = row.get::<_, String>(2);
    let field = row.get::<_, String>(3);
    let delete_rule = row.get::<_, String>(4);
    let table = if !table_is_schema_qualified && foreign_schema == current_schema {
        foreign_table
    } else {
        format!("{foreign_schema}.{foreign_table}")
    };
    Ok(Some(ForeignKey::new(
        table,
        field,
        match delete_rule.as_str() {
            "CASCADE" => OnDelete::Cascade,
            "SET NULL" => OnDelete::SetNull,
            "SET DEFAULT" => OnDelete::SetDefault,
            "RESTRICT" => OnDelete::Restrict,
            _ => OnDelete::NoAction,
        },
    )))
}

struct PostgresTableName<'a> {
    schema: Option<&'a str>,
    name: &'a str,
}

impl<'a> PostgresTableName<'a> {
    fn parse(value: &'a str) -> Result<Self, OpenAuthError> {
        let mut parts = value.split('.');
        let first = parts.next().unwrap_or_default();
        let second = parts.next();
        if parts.next().is_some() || first.is_empty() || second == Some("") {
            return Err(OpenAuthError::Adapter(format!(
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
            Err(OpenAuthError::Adapter(
                "schema executor does not fetch rows".to_owned(),
            ))
        })
    }

    fn fetch_optional<'a>(
        &'a mut self,
        _statement: SqlStatement,
    ) -> AdapterFuture<'a, Option<Self::Row>> {
        Box::pin(async {
            Err(OpenAuthError::Adapter(
                "schema executor does not fetch rows".to_owned(),
            ))
        })
    }

    fn fetch_scalar_i64<'a>(&'a mut self, _statement: SqlStatement) -> AdapterFuture<'a, i64> {
        Box::pin(async {
            Err(OpenAuthError::Adapter(
                "schema executor does not fetch scalar values".to_owned(),
            ))
        })
    }
}
