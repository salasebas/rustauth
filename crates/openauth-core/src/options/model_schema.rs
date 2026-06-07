//! Per-model schema alias options (parity with Better Auth `modelName` / `fields`).

use std::collections::BTreeMap;

/// Table and column alias overrides for a core auth model.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModelSchemaOptions {
    /// Physical database table name override.
    pub model_name: Option<String>,
    /// Logical field name to physical column name aliases.
    pub field_names: BTreeMap<String, String>,
}

impl ModelSchemaOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn model_name(mut self, name: impl Into<String>) -> Self {
        self.model_name = Some(name.into());
        self
    }

    #[must_use]
    pub fn field_name(
        mut self,
        logical_name: impl Into<String>,
        db_name: impl Into<String>,
    ) -> Self {
        self.field_names.insert(logical_name.into(), db_name.into());
        self
    }
}
