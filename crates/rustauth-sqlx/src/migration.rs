//! Internal migration helpers for SQLx adapters.

use std::path::Path;

use rustauth_core::db::{SchemaCreation, SchemaMigrationPlan};
use rustauth_core::error::RustAuthError;

pub(crate) fn ensure_executable(plan: &SchemaMigrationPlan) -> Result<(), RustAuthError> {
    rustauth_core::db::ensure_executable_migration_plan(plan)
}

pub(crate) async fn write_schema_file(
    path: &str,
    code: String,
) -> Result<SchemaCreation, RustAuthError> {
    let schema_path = Path::new(path);
    if let Some(parent) = schema_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            RustAuthError::Adapter(format!(
                "failed to create schema file directory `{}`: {error}",
                parent.display()
            ))
        })?;
    }
    tokio::fs::write(schema_path, code.as_bytes())
        .await
        .map_err(|error| {
            RustAuthError::Adapter(format!("failed to write schema file `{path}`: {error}"))
        })?;
    Ok(SchemaCreation::new(path, code).overwrite())
}
