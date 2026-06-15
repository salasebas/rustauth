//! MySQL migration rollback assertions for Diesel adapter integration tests.

use rustauth_core::db::DbSchema;
use rustauth_core::db::{
    ensure_executable_migration_plan, MigrationStatement, MigrationStatementKind,
};
use rustauth_core::error::RustAuthError;

pub async fn assert_diesel_mysql_migration_plan_rolls_back(
    adapter: &rustauth_diesel::DieselMysqlAdapter,
    pool: &sqlx::MySqlPool,
    schema: &DbSchema,
) -> Result<(), RustAuthError> {
    let plan = adapter.plan_migrations(schema).await?;
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

    let result = adapter.apply_migration_plan(&broken_plan).await;
    assert!(
        result.is_err(),
        "expected migration failure, got {result:?}"
    );

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = ?
        )",
    )
    .bind(&first_table)
    .fetch_one(pool)
    .await
    .map_err(|error| RustAuthError::Adapter(error.to_string()))?;
    assert!(
        !exists,
        "table `{first_table}` should not exist after rolled-back migration"
    );
    Ok(())
}
