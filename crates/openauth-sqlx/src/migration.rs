//! Compatibility re-exports for SQL migration planning types.

use openauth_core::error::OpenAuthError;

pub use openauth_core::db::{
    ColumnToAdd, IndexToCreate, MigrationStatement, MigrationStatementKind, SchemaMigrationPlan,
    SchemaMigrationWarning, TableToCreate,
};

pub(crate) fn ensure_executable(plan: &SchemaMigrationPlan) -> Result<(), OpenAuthError> {
    if !plan.has_warnings() {
        return Ok(());
    }

    Err(OpenAuthError::Adapter(format!(
        "migration contains {} non-executable migration warnings; inspect plan_migrations or compile_migrations before applying",
        plan.warnings.len()
    )))
}
