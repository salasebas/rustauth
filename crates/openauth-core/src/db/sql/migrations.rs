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
}

/// Non-executable findings discovered while planning migrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaMigrationWarning {
    ColumnTypeMismatch {
        table_name: String,
        column_name: String,
        expected: String,
        actual: String,
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

    pub fn table_exists(&self, table: &str) -> bool {
        self.tables.contains_key(table)
    }

    pub fn column_type(&self, table: &str, column: &str) -> Option<&str> {
        self.tables
            .get(table)
            .and_then(|table| table.columns.get(column))
            .map(|column| column.data_type.as_str())
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
}

/// Introspected table metadata used by the pure migration planner.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlTableSnapshot {
    columns: IndexMap<String, SqlColumnSnapshot>,
    indexes: IndexSet<String>,
}

/// Introspected column metadata used by the pure migration planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlColumnSnapshot {
    pub name: String,
    pub data_type: String,
}

impl SqlColumnSnapshot {
    pub fn new(name: impl Into<String>, data_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            data_type: data_type.into(),
        }
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
                if let Some(actual_type) = snapshot.column_type(&table.name, &field.name) {
                    if !dialect.type_matches(actual_type, field) {
                        plan.warnings
                            .push(SchemaMigrationWarning::ColumnTypeMismatch {
                                table_name: table.name.clone(),
                                column_name: field.name.clone(),
                                expected: dialect.sql_type(logical_name, field),
                                actual: actual_type.to_owned(),
                            });
                    }
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
        for (logical_name, field) in &table.fields {
            if field.index && !field.unique {
                let index_name =
                    dialect.sanitize_identifier(&format!("idx_{}_{}", table.name, logical_name))?;
                if !snapshot.index_exists(&table.name, &index_name) {
                    plan.indexes_to_be_created.push(IndexToCreate {
                        table_logical_name: table_logical_name.to_owned(),
                        table_name: table.name.clone(),
                        field_logical_name: logical_name.clone(),
                        column_name: field.name.clone(),
                        index_name: index_name.clone(),
                    });
                    plan.statements.push(MigrationStatement {
                        kind: MigrationStatementKind::CreateIndex,
                        sql: dialect.create_index_statement(
                            &table.name,
                            &field.name,
                            &index_name,
                        )?,
                    });
                }
            }
        }
    }

    Ok(plan)
}
