use rustauth_core::db::DbSchema;
use rustauth_core::db::{
    ensure_executable_migration_plan, MigrationStatement, MigrationStatementKind,
};
use rustauth_core::error::RustAuthError;
use rustauth_tokio_postgres::driver::{apply_migration_plan, plan_migrations, postgres_error};
use tokio_postgres::Client;

/// Asserts that a multi-statement Postgres migration plan rolls back when a later
/// statement fails, leaving no tables from the plan committed.
pub async fn assert_migration_plan_rolls_back_on_statement_failure(
    client: &Client,
    schema: &DbSchema,
) -> Result<(), RustAuthError> {
    let plan = plan_migrations(client, schema).await?;
    ensure_executable_migration_plan(&plan)?;

    let first_table = plan
        .to_be_created
        .first()
        .ok_or_else(|| {
            RustAuthError::Adapter(
                "expected multi-table migration plan for rollback test".to_owned(),
            )
        })?
        .table_name
        .clone();
    assert!(
        plan.statements.len() >= 2,
        "expected at least two migration statements, got {}",
        plan.statements.len()
    );

    let mut broken_plan = plan;
    broken_plan.statements.insert(
        1,
        MigrationStatement {
            kind: MigrationStatementKind::CreateTable,
            sql: "RUSTAUTH_MIGRATION_ROLLBACK_TEST_INVALID SQL".to_owned(),
        },
    );

    let result = apply_migration_plan(client, &broken_plan).await;
    assert!(
        result.is_err(),
        "expected migration failure, got {result:?}"
    );

    assert!(
        !table_exists(client, &first_table).await?,
        "table `{first_table}` should not exist after rolled-back migration"
    );
    Ok(())
}

async fn table_exists(client: &Client, table: &str) -> Result<bool, RustAuthError> {
    let count = client
        .query_one(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = $1",
            &[&table],
        )
        .await
        .map_err(postgres_error)?
        .get::<_, i64>(0);
    Ok(count > 0)
}
