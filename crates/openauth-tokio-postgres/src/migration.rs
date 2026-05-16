//! Migration compatibility re-exports for tokio-postgres adapters.

pub use openauth_core::db::{
    ColumnToAdd, IndexToCreate, MigrationStatement, MigrationStatementKind, SchemaMigrationPlan,
    SchemaMigrationWarning, TableToCreate,
};
