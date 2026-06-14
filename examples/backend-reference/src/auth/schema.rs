//! Database schema resolution: plugins contribute tables/fields before the
//! Postgres adapter connects.

use std::sync::Arc;

use rustauth::db::DbSchema;
use rustauth_core::context::create_auth_context_with_adapter;

use crate::auth::options::schema_seed_options;
use crate::error::AppResult;

/// Build the effective schema for all enabled plugins.
pub fn resolve_schema() -> AppResult<DbSchema> {
    let options = schema_seed_options()?;
    let context =
        create_auth_context_with_adapter(options, Arc::new(rustauth::db::MemoryAdapter::new()))?;
    Ok(context.db_schema)
}
