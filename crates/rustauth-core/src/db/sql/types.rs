use super::*;

/// SQL dialect supported by RustAuth's shared SQL planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SqlDialect {
    Postgres,
    MySql,
    Sqlite,
}

/// A SQL fragment plus its ordered parameters.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SqlFragment {
    pub sql: String,
    pub params: Vec<SqlParam>,
}

impl SqlFragment {
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            params: Vec::new(),
        }
    }
}

/// A complete SQL statement plus its ordered parameters.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SqlStatement {
    pub sql: String,
    pub params: Vec<SqlParam>,
}

impl SqlStatement {
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            params: Vec::new(),
        }
    }
}

impl From<SqlFragment> for SqlStatement {
    fn from(fragment: SqlFragment) -> Self {
        Self {
            sql: fragment.sql,
            params: fragment.params,
        }
    }
}

/// A database value paired with the field type needed to bind NULLs correctly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlParam {
    pub field_type: DbFieldType,
    pub generated_id: Option<IdGeneration>,
    pub value: DbValue,
}

impl SqlParam {
    pub fn new(field: &DbField, value: DbValue) -> Self {
        Self {
            field_type: field.field_type.clone(),
            generated_id: field.generated_id,
            value,
        }
    }
}

/// Field selected by a SQL read statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlSelectedField {
    pub logical_name: String,
    pub field: DbField,
    pub alias: String,
}

/// A read statement and the metadata needed to decode its result rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlReadStatement {
    pub statement: SqlStatement,
    pub selection: Vec<SqlSelectedField>,
}

/// A native join read statement and borrowed metadata needed for row grouping.
#[derive(Debug, Clone)]
pub struct SqlJoinReadStatement<'a> {
    pub statement: SqlStatement,
    pub base_selection: Vec<(&'a str, &'a DbField)>,
    pub joins: Vec<NativeJoin<'a>>,
}

/// Shared single-row update strategy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SqlUpdateOnePlan {
    Returning(SqlReadStatement),
    PreselectThenUpdate {
        select: SqlReadStatement,
        update: SqlStatement,
        data: DbRecord,
    },
}

/// Shared single-row delete statement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlDeleteOnePlan {
    pub statement: SqlStatement,
    pub strategy: DeleteOneStrategy,
}

/// Dialect strategy used to delete only one matching row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeleteOneStrategy {
    NestedId,
    Limit,
}

/// SQL statements used by database-backed rate limit stores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SqlRateLimitPlan {
    pub insert_ignore: SqlStatement,
    pub select: SqlStatement,
    pub update: SqlStatement,
}

/// Physical database names used by SQL-backed rate limit stores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlRateLimitNames {
    pub table: String,
    pub key: String,
    pub count: String,
    pub last_request: String,
}

impl SqlRateLimitNames {
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            key: "key".to_owned(),
            count: "count".to_owned(),
            last_request: "last_request".to_owned(),
        }
    }

    pub fn from_schema(schema: &DbSchema) -> Self {
        let Some(table) = schema.table("rate_limit") else {
            return Self::new("rate_limits");
        };
        Self {
            table: table.name.clone(),
            key: table
                .field("key")
                .map(|field| field.name.clone())
                .unwrap_or_else(|| "key".to_owned()),
            count: table
                .field("count")
                .map(|field| field.name.clone())
                .unwrap_or_else(|| "count".to_owned()),
            last_request: table
                .field("last_request")
                .map(|field| field.name.clone())
                .unwrap_or_else(|| "last_request".to_owned()),
        }
    }
}
