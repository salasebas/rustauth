use openauth_core::db::{
    execute_schema_migration_plan, plan_schema_migration, AdapterFuture, DbSchema,
    SqlColumnSnapshot, SqlDialect, SqlExecutor, SqlSchemaSnapshot, SqlStatement,
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
                    snapshot = snapshot.with_column(
                        &table.name,
                        SqlColumnSnapshot::new(&field.name, actual_type),
                    );
                }
            }
        }

        for (logical_name, field) in &table.fields {
            if field.index && !field.unique {
                let index_name = SqlDialect::Postgres
                    .sanitize_identifier(&format!("idx_{}_{}", table.name, logical_name))?;
                if index_exists(client, &index_name).await? {
                    snapshot = snapshot.with_index(&table.name, index_name);
                }
            }
        }
    }

    Ok(snapshot)
}

async fn table_exists(client: &Client, table: &str) -> Result<bool, OpenAuthError> {
    let count = client
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1",
            &[&table],
        )
        .await
        .map_err(postgres_error)?
        .get::<_, i64>(0);
    Ok(count > 0)
}

async fn column_type(
    client: &Client,
    table: &str,
    column: &str,
) -> Result<Option<String>, OpenAuthError> {
    let row = client
        .query_opt(
            "SELECT CASE WHEN data_type = 'ARRAY' THEN udt_name ELSE data_type END \
             FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
            &[&table, &column],
        )
        .await
        .map_err(postgres_error)?;
    Ok(row.map(|row| row.get::<_, String>(0)))
}

async fn index_exists(client: &Client, index: &str) -> Result<bool, OpenAuthError> {
    let count = client
        .query_one(
            "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1",
            &[&index],
        )
        .await
        .map_err(postgres_error)?
        .get::<_, i64>(0);
    Ok(count > 0)
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
