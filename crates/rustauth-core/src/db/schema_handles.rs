use crate::error::RustAuthError;

use super::adapter::{Create, Sort, SortDirection, Update, Where, WhereOperator};
use super::schema::DbSchema;
use super::{DbRecord, DbValue};

/// Schema view for validated table and field names.
#[derive(Debug, Clone, Copy)]
pub struct AuthSchema<'a> {
    inner: &'a DbSchema,
}

/// Validated logical table bound to the merged auth schema.
///
/// Use this handle to validate field names and map adapter records back to
/// logical keys. Execute queries with the normal adapter types
/// ([`FindOne`](super::FindOne), [`Create`](super::Create), …) using
/// [`SchemaTable::model`].
#[derive(Debug, Clone)]
pub struct SchemaTable<'a> {
    schema: &'a DbSchema,
    logical: String,
}

impl<'a> AuthSchema<'a> {
    pub fn new(schema: &'a DbSchema) -> Self {
        Self { inner: schema }
    }

    /// Resolve a logical table name and return a handle for validation/mapping.
    pub fn table(&self, logical_name: &str) -> Result<SchemaTable<'a>, RustAuthError> {
        SchemaTable::new(self.inner, logical_name)
    }

    /// Resolve a logical table when it exists in the merged schema.
    pub fn try_table(&self, logical_name: &str) -> Option<SchemaTable<'a>> {
        SchemaTable::new(self.inner, logical_name).ok()
    }
}

impl<'a> SchemaTable<'a> {
    pub fn new(schema: &'a DbSchema, logical_name: &str) -> Result<Self, RustAuthError> {
        schema
            .table(logical_name)
            .ok_or_else(|| RustAuthError::TableNotFound {
                table: logical_name.to_owned(),
            })?;
        Ok(Self {
            schema,
            logical: logical_name.to_owned(),
        })
    }

    /// Logical model name used in adapter queries (`"user"`, `"session"`, …).
    pub fn model(&self) -> &str {
        &self.logical
    }

    pub fn logical_name(&self) -> &str {
        &self.logical
    }

    pub fn physical_name(&self) -> Result<&str, RustAuthError> {
        self.schema.table_name(&self.logical)
    }

    pub fn create(&self) -> Create {
        Create::new(&self.logical)
    }

    /// Build a predicate on a logical field name (defaults to equality).
    pub fn where_eq(&self, field: &str, value: DbValue) -> Result<Where, RustAuthError> {
        self.where_op(field, WhereOperator::Eq, value)
    }

    /// Build a predicate on a logical field name with an explicit operator.
    pub fn where_op(
        &self,
        field: &str,
        operator: WhereOperator,
        value: DbValue,
    ) -> Result<Where, RustAuthError> {
        self.schema.field(&self.logical, field)?;
        Ok(Where::new(field, value).operator(operator))
    }

    pub fn sort_by(&self, field: &str, direction: SortDirection) -> Result<Sort, RustAuthError> {
        self.schema.field(&self.logical, field)?;
        Ok(Sort::new(field, direction))
    }

    /// Validate logical field names exist in the schema.
    pub fn ensure_field(&self, logical_field: &str) -> Result<(), RustAuthError> {
        self.schema.field(&self.logical, logical_field)?;
        Ok(())
    }

    pub fn ensure_fields<const N: usize>(&self, fields: [&str; N]) -> Result<(), RustAuthError> {
        for field in fields {
            self.ensure_field(field)?;
        }
        Ok(())
    }

    /// Attach a column value to a create builder using a logical field name.
    pub fn with_data(
        &self,
        create: Create,
        field: &str,
        value: DbValue,
    ) -> Result<Create, RustAuthError> {
        self.ensure_field(field)?;
        Ok(create.data(field, value))
    }

    /// Attach a column value to an update builder using a logical field name.
    pub fn with_update_data(
        &self,
        update: Update,
        field: &str,
        value: DbValue,
    ) -> Result<Update, RustAuthError> {
        self.ensure_field(field)?;
        Ok(update.data(field, value))
    }

    /// Map a database record's physical column keys to logical field names.
    pub fn map_record(&self, record: DbRecord) -> Result<DbRecord, RustAuthError> {
        self.schema.map_record_to_logical(&self.logical, record)
    }
}
