//! Plugin schema contributions.

use crate::db::{DbField, DbSchema, DbTable};
use crate::error::OpenAuthError;

/// Database schema contribution made by a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginSchemaContribution {
    Table {
        logical_name: String,
        table: DbTable,
    },
    Field {
        table: String,
        logical_name: String,
        field: DbField,
    },
}

impl PluginSchemaContribution {
    pub fn table(logical_name: impl Into<String>, table: DbTable) -> Self {
        Self::Table {
            logical_name: logical_name.into(),
            table,
        }
    }

    pub fn field(
        table: impl Into<String>,
        logical_name: impl Into<String>,
        field: DbField,
    ) -> Self {
        Self::Field {
            table: table.into(),
            logical_name: logical_name.into(),
            field,
        }
    }

    pub fn apply(&self, schema: &mut DbSchema) -> Result<(), OpenAuthError> {
        match self {
            Self::Table {
                logical_name,
                table,
            } => schema.insert_plugin_table(logical_name.clone(), table.clone()),
            Self::Field {
                table,
                logical_name,
                field,
            } => schema.insert_plugin_field(table, logical_name.clone(), field.clone()),
        }
    }
}
