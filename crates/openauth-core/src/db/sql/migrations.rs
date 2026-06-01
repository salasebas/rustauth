use super::*;

/// Executes a pure migration plan through any SQL executor.
///
/// Introspection and transaction ownership stay in the adapter crate; this
/// helper only runs the already-planned SQL statements in order.
pub async fn execute_schema_migration_plan<E>(
    executor: &mut E,
    plan: &SchemaMigrationPlan,
) -> Result<(), OpenAuthError>
where
    E: SqlExecutor,
{
    for statement in &plan.statements {
        executor
            .execute(SqlStatement::new(statement.sql.clone()))
            .await?;
    }
    Ok(())
}

/// Rejects migration plans that carry non-executable warnings before any
/// schema mutation runs.
///
/// Shared preflight so every SQL adapter refuses warning/error plans
/// identically instead of silently mutating the database.
pub fn ensure_executable_migration_plan(plan: &SchemaMigrationPlan) -> Result<(), OpenAuthError> {
    if !plan.has_warnings() {
        return Ok(());
    }

    Err(OpenAuthError::Adapter(format!(
        "migration contains {} non-executable migration warnings; inspect plan_migrations or compile_migrations before applying",
        plan.warnings.len()
    )))
}

/// Additive schema changes planned for a live database.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaMigrationPlan {
    pub to_be_created: Vec<TableToCreate>,
    pub to_be_added: Vec<ColumnToAdd>,
    pub indexes_to_be_created: Vec<IndexToCreate>,
    pub warnings: Vec<SchemaMigrationWarning>,
    pub statements: Vec<MigrationStatement>,
}

impl SchemaMigrationPlan {
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    pub fn compile(&self) -> String {
        if self.statements.is_empty() {
            return ";".to_owned();
        }

        format!(
            "{};",
            self.statements
                .iter()
                .map(|statement| statement.sql.as_str())
                .collect::<Vec<_>>()
                .join(";\n\n")
        )
    }
}

/// A table missing from the database and planned for creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableToCreate {
    pub logical_name: String,
    pub table_name: String,
}

/// A column missing from an existing table and planned for additive creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColumnToAdd {
    pub table_logical_name: String,
    pub table_name: String,
    pub field_logical_name: String,
    pub column_name: String,
}

/// A standalone index missing from the database and planned for creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexToCreate {
    pub table_logical_name: String,
    pub table_name: String,
    pub field_logical_name: String,
    pub column_name: String,
    pub index_name: String,
    pub unique: bool,
}

/// Non-executable findings discovered while planning migrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum SchemaMigrationWarning {
    ColumnTypeMismatch {
        table_name: String,
        column_name: String,
        expected: String,
        actual: String,
    },
    ColumnNullabilityMismatch {
        table_name: String,
        column_name: String,
        expected_nullable: bool,
        actual_nullable: bool,
    },
    PrimaryKeyMismatch {
        table_name: String,
        column_name: String,
    },
    GeneratedIdMismatch {
        table_name: String,
        column_name: String,
        expected: IdGeneration,
        actual: Option<IdGeneration>,
    },
    ForeignKeyMismatch {
        table_name: String,
        column_name: String,
        expected: ForeignKey,
        actual: Option<ForeignKey>,
    },
}

/// A SQL statement emitted by a migration plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationStatement {
    pub kind: MigrationStatementKind,
    pub sql: String,
}

/// The additive operation represented by a migration statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatementKind {
    CreateTable,
    AddColumn,
    CreateIndex,
}

/// Introspected database schema used by the pure migration planner.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlSchemaSnapshot {
    tables: IndexMap<String, SqlTableSnapshot>,
}

impl SqlSchemaSnapshot {
    pub fn with_table(mut self, table: impl Into<String>) -> Self {
        self.tables.entry(table.into()).or_default();
        self
    }

    pub fn with_column(mut self, table: impl Into<String>, column: SqlColumnSnapshot) -> Self {
        self.tables
            .entry(table.into())
            .or_default()
            .columns
            .insert(column.name.clone(), column);
        self
    }

    pub fn with_index(mut self, table: impl Into<String>, index: impl Into<String>) -> Self {
        self.tables
            .entry(table.into())
            .or_default()
            .indexes
            .insert(index.into());
        self
    }

    pub fn with_unique_column(
        mut self,
        table: impl Into<String>,
        column: impl Into<String>,
    ) -> Self {
        self.tables
            .entry(table.into())
            .or_default()
            .unique_columns
            .insert(column.into());
        self
    }

    pub fn table_exists(&self, table: &str) -> bool {
        self.tables.contains_key(table)
    }

    pub fn column_type(&self, table: &str, column: &str) -> Option<&str> {
        self.column(table, column)
            .map(|column| column.data_type.as_str())
    }

    pub fn column(&self, table: &str, column: &str) -> Option<&SqlColumnSnapshot> {
        self.tables
            .get(table)
            .and_then(|table| table.columns.get(column))
    }

    pub fn index_exists(&self, table: &str, index: &str) -> bool {
        self.tables
            .get(table)
            .is_some_and(|table| table.indexes.contains(index))
            || self
                .tables
                .values()
                .any(|table| table.indexes.contains(index))
    }

    pub fn unique_column_exists(&self, table: &str, column: &str) -> bool {
        self.tables
            .get(table)
            .is_some_and(|table| table.unique_columns.contains(column))
    }
}

/// Introspected table metadata used by the pure migration planner.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlTableSnapshot {
    columns: IndexMap<String, SqlColumnSnapshot>,
    indexes: IndexSet<String>,
    unique_columns: IndexSet<String>,
}

/// Introspected column metadata used by the pure migration planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlColumnSnapshot {
    pub name: String,
    pub data_type: String,
    pub nullable: Option<bool>,
    pub primary_key: Option<bool>,
    pub generated_id: Option<IdGeneration>,
    pub foreign_key: Option<ForeignKey>,
}

impl SqlColumnSnapshot {
    pub fn new(name: impl Into<String>, data_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
            nullable: None,
            primary_key: None,
            generated_id: None,
            foreign_key: None,
        }
    }

    pub fn nullable(mut self, nullable: bool) -> Self {
        self.nullable = Some(nullable);
        self
    }

    pub fn primary_key(mut self, primary_key: bool) -> Self {
        self.primary_key = Some(primary_key);
        self
    }

    pub fn generated_id(mut self, generated_id: Option<IdGeneration>) -> Self {
        self.generated_id = generated_id;
        self
    }

    pub fn references(mut self, foreign_key: ForeignKey) -> Self {
        self.foreign_key = Some(foreign_key);
        self
    }
}

/// Compares a target OpenAuth schema with a SQL schema snapshot and emits an additive plan.
pub fn plan_schema_migration(
    dialect: SqlDialect,
    schema: &DbSchema,
    snapshot: &SqlSchemaSnapshot,
) -> Result<SchemaMigrationPlan, OpenAuthError> {
    let mut plan = SchemaMigrationPlan::default();
    let mut tables = schema.tables().collect::<Vec<_>>();
    tables.sort_by_key(|(_, table)| table.order.unwrap_or(u16::MAX));

    for (table_logical_name, table) in &tables {
        if snapshot.table_exists(&table.name) {
            for (logical_name, field) in &table.fields {
                if let Some(column) = snapshot.column(&table.name, &field.name) {
                    if !dialect.type_matches(&column.data_type, field) {
                        plan.warnings
                            .push(SchemaMigrationWarning::ColumnTypeMismatch {
                                table_name: table.name.clone(),
                                column_name: field.name.clone(),
                                expected: dialect.sql_type(logical_name, field),
                                actual: column.data_type.clone(),
                            });
                    }
                    push_constraint_warnings(&mut plan, table, logical_name, field, column);
                } else {
                    plan.to_be_added.push(ColumnToAdd {
                        table_logical_name: (*table_logical_name).to_owned(),
                        table_name: table.name.clone(),
                        field_logical_name: logical_name.clone(),
                        column_name: field.name.clone(),
                    });
                    plan.statements.push(MigrationStatement {
                        kind: MigrationStatementKind::AddColumn,
                        sql: dialect.add_column_statement(&table.name, logical_name, field)?,
                    });
                }
            }
        } else {
            plan.to_be_created.push(TableToCreate {
                logical_name: (*table_logical_name).to_owned(),
                table_name: table.name.clone(),
            });
            plan.statements.push(MigrationStatement {
                kind: MigrationStatementKind::CreateTable,
                sql: dialect.create_table_statement(table)?,
            });
        }
    }

    for (table_logical_name, table) in tables {
        let table_exists = snapshot.table_exists(&table.name);
        for (logical_name, field) in &table.fields {
            if field.index || field.unique {
                if field.unique
                    && (!table_exists || snapshot.unique_column_exists(&table.name, &field.name))
                {
                    continue;
                }
                let prefix = if field.unique { "uidx" } else { "idx" };
                let index_name = dialect
                    .sanitize_identifier(&format!("{prefix}_{}_{}", table.name, logical_name))?;
                if !snapshot.index_exists(&table.name, &index_name) {
                    plan.indexes_to_be_created.push(IndexToCreate {
                        table_logical_name: table_logical_name.to_owned(),
                        table_name: table.name.clone(),
                        field_logical_name: logical_name.clone(),
                        column_name: field.name.clone(),
                        index_name: index_name.clone(),
                        unique: field.unique,
                    });
                    plan.statements.push(MigrationStatement {
                        kind: MigrationStatementKind::CreateIndex,
                        sql: dialect.create_index_statement(
                            &table.name,
                            &field.name,
                            &index_name,
                            field.unique,
                        )?,
                    });
                }
            }
        }
    }

    Ok(plan)
}

fn push_constraint_warnings(
    plan: &mut SchemaMigrationPlan,
    table: &DbTable,
    logical_name: &str,
    field: &DbField,
    column: &SqlColumnSnapshot,
) {
    if logical_name == "id" || field.name == "id" {
        if column.primary_key == Some(false) {
            plan.warnings
                .push(SchemaMigrationWarning::PrimaryKeyMismatch {
                    table_name: table.name.clone(),
                    column_name: field.name.clone(),
                });
        }
    } else if let Some(actual_nullable) = column.nullable {
        let expected_nullable = !field.required;
        if expected_nullable != actual_nullable {
            plan.warnings
                .push(SchemaMigrationWarning::ColumnNullabilityMismatch {
                    table_name: table.name.clone(),
                    column_name: field.name.clone(),
                    expected_nullable,
                    actual_nullable,
                });
        }
    }

    if logical_name == "id" || field.name == "id" {
        if let Some(expected) = field.generated_id {
            if column.generated_id != Some(expected) {
                plan.warnings
                    .push(SchemaMigrationWarning::GeneratedIdMismatch {
                        table_name: table.name.clone(),
                        column_name: field.name.clone(),
                        expected,
                        actual: column.generated_id,
                    });
            }
        }
    }

    if let Some(expected) = &field.foreign_key {
        if column.foreign_key.as_ref() != Some(expected) {
            plan.warnings
                .push(SchemaMigrationWarning::ForeignKeyMismatch {
                    table_name: table.name.clone(),
                    column_name: field.name.clone(),
                    expected: expected.clone(),
                    actual: column.foreign_key.clone(),
                });
        }
    }
}
