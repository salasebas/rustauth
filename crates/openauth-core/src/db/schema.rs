use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::{IdGeneration, IdPolicy};
use crate::error::OpenAuthError;

mod builder;
pub use builder::auth_schema;

/// Storage backend selected for rate limit counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitStorage {
    #[default]
    Memory,
    Database,
    SecondaryStorage,
}

/// Per-table schema overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableOptions {
    pub name: Option<String>,
    pub field_names: IndexMap<String, String>,
    pub additional_fields: IndexMap<String, DbField>,
}

impl TableOptions {
    /// Return a copy of these options with a custom database table name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Return a copy of these options with a custom database column name.
    pub fn with_field_name(
        mut self,
        logical_name: impl Into<String>,
        db_name: impl Into<String>,
    ) -> Self {
        self.field_names.insert(logical_name.into(), db_name.into());
        self
    }

    /// Return a copy of these options with an additional logical field.
    pub fn with_field(mut self, logical_name: impl Into<String>, field: DbField) -> Self {
        self.additional_fields.insert(logical_name.into(), field);
        self
    }

    fn field_name(&self, logical_name: &str) -> String {
        self.field_names
            .get(logical_name)
            .cloned()
            .unwrap_or_else(|| logical_name.to_owned())
    }
}

/// Options used to build OpenAuth's core database schema metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSchemaOptions {
    pub id_policy: IdPolicy,
    pub user: TableOptions,
    pub account: TableOptions,
    pub session: TableOptions,
    pub verification: TableOptions,
    pub rate_limit: TableOptions,
    pub has_secondary_storage: bool,
    pub store_session_in_database: bool,
    pub store_verification_in_database: bool,
    pub rate_limit_storage: RateLimitStorage,
}

/// Supported database field kinds for core schema metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbFieldType {
    String,
    Number,
    Boolean,
    Timestamp,
    Json,
    StringArray,
    NumberArray,
}

/// Foreign key delete behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnDelete {
    NoAction,
    Restrict,
    Cascade,
    SetNull,
    SetDefault,
}

/// Foreign key metadata for adapter and migration implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKey {
    pub table: String,
    pub field: String,
    pub on_delete: OnDelete,
}

impl ForeignKey {
    pub fn new(table: impl Into<String>, field: impl Into<String>, on_delete: OnDelete) -> Self {
        Self {
            table: table.into(),
            field: field.into(),
            on_delete,
        }
    }
}

/// Field metadata used by adapters and migrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbField {
    pub name: String,
    pub field_type: DbFieldType,
    pub required: bool,
    pub unique: bool,
    pub index: bool,
    pub returned: bool,
    pub input: bool,
    pub foreign_key: Option<ForeignKey>,
    #[serde(default)]
    pub generated_id: Option<IdGeneration>,
}

impl DbField {
    /// Create a required, returned, input-accepted field.
    pub fn new(name: impl Into<String>, field_type: DbFieldType) -> Self {
        Self {
            name: name.into(),
            field_type,
            required: true,
            unique: false,
            index: false,
            returned: true,
            input: true,
            foreign_key: None,
            generated_id: None,
        }
    }

    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }

    pub fn indexed(mut self) -> Self {
        self.index = true;
        self
    }

    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }

    pub fn generated(mut self) -> Self {
        self.input = false;
        self
    }

    pub fn generated_id(mut self, generation: IdGeneration) -> Self {
        self.generated_id = Some(generation);
        self.generated()
    }

    pub fn references(mut self, foreign_key: ForeignKey) -> Self {
        self.foreign_key = Some(foreign_key);
        self
    }
}

/// Table metadata keyed by logical field name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbTable {
    pub name: String,
    pub fields: IndexMap<String, DbField>,
    pub order: Option<u16>,
}

impl DbTable {
    pub fn field(&self, logical_name: &str) -> Option<&DbField> {
        self.fields.get(logical_name)
    }
}

/// Schema metadata keyed by logical table name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbSchema {
    tables: IndexMap<String, DbTable>,
}

impl DbSchema {
    pub fn table(&self, logical_name: &str) -> Option<&DbTable> {
        self.tables.get(logical_name)
    }

    /// Resolve a logical or physical table name to its physical database name.
    pub fn table_name(&self, table: &str) -> Result<&str, OpenAuthError> {
        self.resolve_table(table)
            .map(|(_, table)| table.name.as_str())
            .ok_or_else(|| OpenAuthError::TableNotFound {
                table: table.to_owned(),
            })
    }

    /// Resolve a logical or physical field name to its physical database column name.
    pub fn field_name(&self, table: &str, field: &str) -> Result<&str, OpenAuthError> {
        self.field(table, field)
            .map(|field| field.name.as_str())
            .map_err(|_| OpenAuthError::FieldNotFound {
                table: table.to_owned(),
                field: field.to_owned(),
            })
    }

    /// Resolve field metadata from logical or physical table and field names.
    pub fn field(&self, table: &str, field: &str) -> Result<&DbField, OpenAuthError> {
        let (_, table_metadata) =
            self.resolve_table(table)
                .ok_or_else(|| OpenAuthError::TableNotFound {
                    table: table.to_owned(),
                })?;

        table_metadata
            .resolve_field(field)
            .ok_or_else(|| OpenAuthError::FieldNotFound {
                table: table.to_owned(),
                field: field.to_owned(),
            })
    }

    pub fn tables(&self) -> impl Iterator<Item = (&str, &DbTable)> {
        self.tables
            .iter()
            .map(|(logical_name, table)| (logical_name.as_str(), table))
    }

    pub fn insert_plugin_table(
        &mut self,
        logical_name: String,
        table: DbTable,
    ) -> Result<(), OpenAuthError> {
        if let Some(existing) = self.tables.get(&logical_name) {
            if existing == &table {
                return Ok(());
            }
            return Err(OpenAuthError::InvalidConfig(format!(
                "plugin schema table `{logical_name}` conflicts with an existing table"
            )));
        }
        if self
            .tables
            .values()
            .any(|existing| existing.name == table.name)
        {
            return Err(OpenAuthError::InvalidConfig(format!(
                "plugin schema table `{logical_name}` uses existing database table `{}`",
                table.name
            )));
        }
        self.tables.insert(logical_name, table);
        Ok(())
    }

    pub fn insert_plugin_field(
        &mut self,
        table: &str,
        logical_name: String,
        field: DbField,
    ) -> Result<(), OpenAuthError> {
        let (_, table_metadata) =
            self.resolve_table_mut(table)
                .ok_or_else(|| OpenAuthError::TableNotFound {
                    table: table.to_owned(),
                })?;

        if let Some(existing) = table_metadata.fields.get(&logical_name) {
            if existing == &field {
                return Ok(());
            }
            return Err(OpenAuthError::InvalidConfig(format!(
                "plugin schema field `{logical_name}` conflicts with table `{table}`"
            )));
        }
        if table_metadata
            .fields
            .values()
            .any(|existing| existing.name == field.name)
        {
            return Err(OpenAuthError::InvalidConfig(format!(
                "plugin schema field `{logical_name}` uses existing database field `{}` on table `{table}`",
                field.name
            )));
        }
        table_metadata.fields.insert(logical_name, field);
        Ok(())
    }

    fn resolve_table(&self, table: &str) -> Option<(&str, &DbTable)> {
        self.tables
            .get_key_value(table)
            .map(|(logical_name, table)| (logical_name.as_str(), table))
            .or_else(|| {
                self.tables
                    .iter()
                    .find(|(_, table_metadata)| table_metadata.name == table)
                    .map(|(logical_name, table)| (logical_name.as_str(), table))
            })
    }

    fn resolve_table_mut(&mut self, table: &str) -> Option<(&str, &mut DbTable)> {
        if self.tables.contains_key(table) {
            let (logical_name, table_metadata) = self.tables.get_key_value_mut(table)?;
            return Some((logical_name.as_str(), table_metadata));
        }
        self.tables
            .iter_mut()
            .find(|(_, table_metadata)| table_metadata.name == table)
            .map(|(logical_name, table)| (logical_name.as_str(), table))
    }

    fn insert(&mut self, logical_name: impl Into<String>, table: DbTable) {
        self.tables.insert(logical_name.into(), table);
    }
}

impl DbTable {
    fn resolve_field(&self, field: &str) -> Option<&DbField> {
        self.fields
            .get(field)
            .or_else(|| self.fields.values().find(|metadata| metadata.name == field))
    }
}
