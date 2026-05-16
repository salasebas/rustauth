use super::*;

impl SqlDialect {
    pub fn quote_identifier(self, identifier: &str) -> Result<String, OpenAuthError> {
        validate_identifier(self, identifier)?;
        let quote = match self {
            Self::MySql => '`',
            Self::Postgres | Self::Sqlite => '"',
        };
        Ok(format!("{quote}{identifier}{quote}"))
    }

    pub fn sanitize_identifier(self, identifier: &str) -> Result<String, OpenAuthError> {
        let sanitized = identifier
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '_' {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        validate_identifier(self, &sanitized)?;
        Ok(sanitized)
    }

    pub fn placeholder(self, index: usize) -> String {
        match self {
            Self::Postgres => format!("${index}"),
            Self::MySql | Self::Sqlite => "?".to_owned(),
        }
    }

    pub fn where_clause(
        self,
        table: &DbTable,
        clauses: &[Where],
    ) -> Result<SqlFragment, OpenAuthError> {
        self.where_clause_starting_at(table, clauses, 1)
    }

    pub fn where_clause_starting_at(
        self,
        table: &DbTable,
        clauses: &[Where],
        first_placeholder: usize,
    ) -> Result<SqlFragment, OpenAuthError> {
        if clauses.is_empty() {
            return Ok(SqlFragment::default());
        }

        let mut sql = String::from(" WHERE ");
        let mut params = Vec::new();
        for (index, clause) in clauses.iter().enumerate() {
            if index > 0 {
                sql.push(' ');
                sql.push_str(match clause.connector {
                    Connector::And => "AND",
                    Connector::Or => "OR",
                });
                sql.push(' ');
            }
            sql.push_str(&self.clause_sql(table, clause, &mut params, first_placeholder)?);
        }
        Ok(SqlFragment { sql, params })
    }

    fn clause_sql(
        self,
        table: &DbTable,
        clause: &Where,
        params: &mut Vec<SqlParam>,
        first_placeholder: usize,
    ) -> Result<String, OpenAuthError> {
        let (_, field) = resolve_field(table, &clause.field)?;
        let column = self.quote_identifier(&field.name)?;
        if clause.value == DbValue::Null {
            return Ok(match clause.operator {
                WhereOperator::Eq => format!("{column} IS NULL"),
                WhereOperator::Ne => format!("{column} IS NOT NULL"),
                _ => {
                    return Err(OpenAuthError::Adapter(
                        "null only supports Eq and Ne operators".to_owned(),
                    ))
                }
            });
        }

        match clause.operator {
            WhereOperator::Eq
            | WhereOperator::Ne
            | WhereOperator::Lt
            | WhereOperator::Lte
            | WhereOperator::Gt
            | WhereOperator::Gte => {
                let operator = match clause.operator {
                    WhereOperator::Eq => "=",
                    WhereOperator::Ne => "!=",
                    WhereOperator::Lt => "<",
                    WhereOperator::Lte => "<=",
                    WhereOperator::Gt => ">",
                    WhereOperator::Gte => ">=",
                    _ => unreachable!("operator matched by outer arm"),
                };
                let placeholder =
                    self.push_param(params, field, clause.value.clone(), first_placeholder);
                Ok(format!("{column} {operator} {placeholder}"))
            }
            WhereOperator::In | WhereOperator::NotIn => {
                let placeholders =
                    self.push_array_params(params, field, &clause.value, first_placeholder)?;
                let operator = if clause.operator == WhereOperator::In {
                    "IN"
                } else {
                    "NOT IN"
                };
                Ok(format!("{column} {operator} ({})", placeholders.join(", ")))
            }
            WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
                let DbValue::String(value) = &clause.value else {
                    return Err(OpenAuthError::Adapter(
                        "string pattern operators require string values".to_owned(),
                    ));
                };
                let pattern = match clause.operator {
                    WhereOperator::Contains => format!("%{value}%"),
                    WhereOperator::StartsWith => format!("{value}%"),
                    WhereOperator::EndsWith => format!("%{value}"),
                    _ => unreachable!("operator matched by outer arm"),
                };
                let placeholder =
                    self.push_param(params, field, DbValue::String(pattern), first_placeholder);
                if clause.mode == WhereMode::Insensitive {
                    Ok(format!("LOWER({column}) LIKE LOWER({placeholder})"))
                } else {
                    Ok(format!("{column} LIKE {placeholder}"))
                }
            }
        }
    }

    fn push_param(
        &self,
        params: &mut Vec<SqlParam>,
        field: &DbField,
        value: DbValue,
        first_placeholder: usize,
    ) -> String {
        params.push(SqlParam::new(field, value));
        self.placeholder(first_placeholder + params.len() - 1)
    }

    fn push_array_params(
        self,
        params: &mut Vec<SqlParam>,
        field: &DbField,
        value: &DbValue,
        first_placeholder: usize,
    ) -> Result<Vec<String>, OpenAuthError> {
        match value {
            DbValue::StringArray(values) => Ok(values
                .iter()
                .map(|value| {
                    self.push_param(
                        params,
                        field,
                        DbValue::String(value.clone()),
                        first_placeholder,
                    )
                })
                .collect()),
            DbValue::NumberArray(values) => Ok(values
                .iter()
                .map(|value| {
                    self.push_param(params, field, DbValue::Number(*value), first_placeholder)
                })
                .collect()),
            _ => Err(OpenAuthError::Adapter(
                "IN and NOT IN require array values".to_owned(),
            )),
        }
    }

    pub fn order_limit_offset(
        self,
        table: &DbTable,
        sort_by: Option<&Sort>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<String, OpenAuthError> {
        let mut sql = String::new();
        if let Some(sort) = sort_by {
            let (_, field) = resolve_field(table, &sort.field)?;
            let direction = match sort.direction {
                SortDirection::Asc => "ASC",
                SortDirection::Desc => "DESC",
            };
            sql.push_str(" ORDER BY ");
            sql.push_str(&self.quote_identifier(&field.name)?);
            sql.push(' ');
            sql.push_str(direction);
        }
        if let Some(limit) = limit {
            sql.push_str(" LIMIT ");
            sql.push_str(&limit.to_string());
        }
        if let Some(offset) = offset {
            sql.push_str(" OFFSET ");
            sql.push_str(&offset.to_string());
        }
        Ok(sql)
    }

    pub fn column_definition(
        self,
        logical_name: &str,
        field: &DbField,
    ) -> Result<String, OpenAuthError> {
        let mut parts = vec![
            self.quote_identifier(&field.name)?,
            self.sql_type(logical_name, field),
        ];
        if logical_name == "id" || field.name == "id" {
            parts.push("PRIMARY KEY".to_owned());
        } else {
            if field.required {
                parts.push("NOT NULL".to_owned());
            }
            if field.unique {
                parts.push("UNIQUE".to_owned());
            }
        }
        if let Some(foreign_key) = &field.foreign_key {
            parts.push(format!(
                "REFERENCES {} ({})",
                self.quote_identifier(&foreign_key.table)?,
                self.quote_identifier(&foreign_key.field)?
            ));
            parts.push(on_delete_sql(foreign_key.on_delete).to_owned());
        }
        Ok(parts.join(" "))
    }

    pub fn create_table_statement(self, table: &DbTable) -> Result<String, OpenAuthError> {
        let columns = table
            .fields
            .iter()
            .map(|(logical_name, field)| self.column_definition(logical_name, field))
            .collect::<Result<Vec<_>, _>>()?;
        let suffix = match self {
            Self::MySql => " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
            Self::Postgres | Self::Sqlite => "",
        };
        Ok(format!(
            "CREATE TABLE IF NOT EXISTS {} ({}){}",
            self.quote_identifier(&table.name)?,
            columns.join(", "),
            suffix
        ))
    }

    pub fn add_column_statement(
        self,
        table: &str,
        logical_name: &str,
        field: &DbField,
    ) -> Result<String, OpenAuthError> {
        Ok(format!(
            "ALTER TABLE {} ADD COLUMN {}",
            self.quote_identifier(table)?,
            self.column_definition(logical_name, field)?,
        ))
    }

    pub fn create_index_statement(
        self,
        table: &str,
        column: &str,
        index: &str,
    ) -> Result<String, OpenAuthError> {
        let if_not_exists = match self {
            Self::Postgres | Self::Sqlite => " IF NOT EXISTS",
            Self::MySql => "",
        };
        Ok(format!(
            "CREATE INDEX{} {} ON {} ({})",
            if_not_exists,
            self.quote_identifier(index)?,
            self.quote_identifier(table)?,
            self.quote_identifier(column)?,
        ))
    }

    pub fn sql_type(self, logical_name: &str, field: &DbField) -> String {
        match self {
            Self::Postgres => match field.field_type {
                DbFieldType::String => "TEXT",
                DbFieldType::Number => "BIGINT",
                DbFieldType::Boolean => "BOOLEAN",
                DbFieldType::Timestamp => "TIMESTAMPTZ",
                DbFieldType::Json | DbFieldType::StringArray | DbFieldType::NumberArray => "JSONB",
            }
            .to_owned(),
            Self::Sqlite => match field.field_type {
                DbFieldType::String
                | DbFieldType::Timestamp
                | DbFieldType::Json
                | DbFieldType::StringArray
                | DbFieldType::NumberArray => "TEXT",
                DbFieldType::Number | DbFieldType::Boolean => "INTEGER",
            }
            .to_owned(),
            Self::MySql => match field.field_type {
                DbFieldType::String if logical_name == "id" || field.unique || field.index => {
                    "VARCHAR(255)"
                }
                DbFieldType::String => "TEXT",
                DbFieldType::Number => "BIGINT",
                DbFieldType::Boolean => "BOOLEAN",
                DbFieldType::Timestamp => "DATETIME(6)",
                DbFieldType::Json | DbFieldType::StringArray | DbFieldType::NumberArray => "JSON",
            }
            .to_owned(),
        }
    }

    pub fn type_matches(self, actual: &str, field: &DbField) -> bool {
        let actual = normalized_type(actual);
        match self {
            Self::Postgres => match field.field_type {
                DbFieldType::String => {
                    matches!(
                        actual.as_str(),
                        "text" | "character varying" | "varchar" | "uuid"
                    )
                }
                DbFieldType::Number => matches!(
                    actual.as_str(),
                    "bigint"
                        | "integer"
                        | "smallint"
                        | "numeric"
                        | "real"
                        | "double precision"
                        | "int8"
                        | "int4"
                        | "int2"
                ),
                DbFieldType::Boolean => matches!(actual.as_str(), "boolean" | "bool"),
                DbFieldType::Timestamp => matches!(
                    actual.as_str(),
                    "timestamp with time zone"
                        | "timestamp without time zone"
                        | "timestamp"
                        | "timestamptz"
                        | "date"
                ),
                DbFieldType::Json | DbFieldType::StringArray | DbFieldType::NumberArray => {
                    matches!(actual.as_str(), "jsonb" | "json")
                }
            },
            Self::MySql => match field.field_type {
                DbFieldType::String => matches!(actual.as_str(), "varchar" | "text" | "uuid"),
                DbFieldType::Number => matches!(
                    actual.as_str(),
                    "integer" | "int" | "bigint" | "smallint" | "decimal" | "float" | "double"
                ),
                DbFieldType::Boolean => matches!(actual.as_str(), "boolean" | "tinyint"),
                DbFieldType::Timestamp => {
                    matches!(actual.as_str(), "timestamp" | "datetime" | "date")
                }
                DbFieldType::Json | DbFieldType::StringArray | DbFieldType::NumberArray => {
                    actual.as_str() == "json"
                }
            },
            Self::Sqlite => match field.field_type {
                DbFieldType::String
                | DbFieldType::Timestamp
                | DbFieldType::Json
                | DbFieldType::StringArray
                | DbFieldType::NumberArray => matches!(
                    actual.as_str(),
                    "text" | "varchar" | "character varying" | "nvarchar" | "clob"
                ),
                DbFieldType::Number => matches!(
                    actual.as_str(),
                    "integer"
                        | "int"
                        | "bigint"
                        | "smallint"
                        | "tinyint"
                        | "numeric"
                        | "real"
                        | "double"
                ),
                DbFieldType::Boolean => matches!(
                    actual.as_str(),
                    "integer" | "int" | "bigint" | "smallint" | "tinyint" | "boolean" | "bool"
                ),
            },
        }
    }
}

fn validate_identifier(dialect: SqlDialect, identifier: &str) -> Result<(), OpenAuthError> {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return Err(OpenAuthError::Adapter(format!(
            "{} identifier cannot be empty",
            dialect.name()
        )));
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(invalid_identifier(dialect, identifier));
    }
    if chars.any(|character| !(character.is_ascii_alphanumeric() || character == '_')) {
        return Err(invalid_identifier(dialect, identifier));
    }
    Ok(())
}

fn invalid_identifier(dialect: SqlDialect, identifier: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!(
        "invalid {} identifier `{identifier}`",
        dialect.name()
    ))
}

impl SqlDialect {
    fn name(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::MySql => "mysql",
            Self::Sqlite => "sqlite",
        }
    }
}

fn normalized_type(value: &str) -> String {
    value
        .trim()
        .split_once('(')
        .map(|(prefix, _)| prefix)
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

fn on_delete_sql(on_delete: OnDelete) -> &'static str {
    match on_delete {
        OnDelete::NoAction => "ON DELETE NO ACTION",
        OnDelete::Restrict => "ON DELETE RESTRICT",
        OnDelete::Cascade => "ON DELETE CASCADE",
        OnDelete::SetNull => "ON DELETE SET NULL",
        OnDelete::SetDefault => "ON DELETE SET DEFAULT",
    }
}
