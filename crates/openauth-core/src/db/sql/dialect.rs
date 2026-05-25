use super::*;

impl SqlDialect {
    pub fn quote_identifier(self, identifier: &str) -> Result<String, OpenAuthError> {
        let quote = match self {
            Self::MySql => '`',
            Self::Postgres | Self::Sqlite => '"',
        };
        identifier
            .split('.')
            .map(|part| {
                validate_identifier(self, part)?;
                Ok(format!("{quote}{part}{quote}"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|parts| parts.join("."))
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

        let mut and_clauses = Vec::new();
        let mut or_clauses = Vec::new();
        for clause in clauses {
            match clause.connector {
                Connector::And => and_clauses.push(clause),
                Connector::Or => or_clauses.push(clause),
            }
        }

        let mut sql = String::from(" WHERE ");
        let mut parts = Vec::new();
        let mut params = Vec::new();

        for clause in and_clauses {
            parts.push(self.clause_sql(table, clause, &mut params, first_placeholder)?);
        }

        if !or_clauses.is_empty() {
            let mut or_parts = Vec::new();
            for clause in or_clauses {
                or_parts.push(self.clause_sql(table, clause, &mut params, first_placeholder)?);
            }
            let or_sql = or_parts.join(" OR ");
            if parts.is_empty() && or_parts.len() == 1 {
                parts.push(or_sql);
            } else {
                parts.push(format!("({or_sql})"));
            }
        }

        sql.push_str(&parts.join(" AND "));
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
                    _ => {
                        return Err(OpenAuthError::Adapter(
                            "unsupported scalar where operator".to_owned(),
                        ));
                    }
                };
                let placeholder =
                    self.push_param(params, field, clause.value.clone(), first_placeholder);
                if clause.mode == WhereMode::Insensitive
                    && field.field_type == DbFieldType::String
                    && matches!(&clause.value, DbValue::String(_))
                    && matches!(clause.operator, WhereOperator::Eq | WhereOperator::Ne)
                {
                    Ok(format!("LOWER({column}) {operator} LOWER({placeholder})"))
                } else {
                    Ok(format!("{column} {operator} {placeholder}"))
                }
            }
            WhereOperator::In | WhereOperator::NotIn => {
                let placeholders =
                    self.push_array_params(params, field, &clause.value, first_placeholder)?;
                if placeholders.is_empty() {
                    return Ok(if clause.operator == WhereOperator::In {
                        "1 = 0".to_owned()
                    } else {
                        "1 = 1".to_owned()
                    });
                }
                let operator = if clause.operator == WhereOperator::In {
                    "IN"
                } else {
                    "NOT IN"
                };
                let placeholders = if clause.mode == WhereMode::Insensitive
                    && field.field_type == DbFieldType::String
                    && matches!(&clause.value, DbValue::StringArray(_))
                {
                    placeholders
                        .into_iter()
                        .map(|placeholder| format!("LOWER({placeholder})"))
                        .collect::<Vec<_>>()
                } else {
                    placeholders
                };
                let column = if clause.mode == WhereMode::Insensitive
                    && field.field_type == DbFieldType::String
                    && matches!(&clause.value, DbValue::StringArray(_))
                {
                    format!("LOWER({column})")
                } else {
                    column
                };
                Ok(format!("{column} {operator} ({})", placeholders.join(", ")))
            }
            WhereOperator::Contains | WhereOperator::StartsWith | WhereOperator::EndsWith => {
                let DbValue::String(value) = &clause.value else {
                    return Err(OpenAuthError::Adapter(
                        "string pattern operators require string values".to_owned(),
                    ));
                };
                let value = escape_like_pattern(value);
                let pattern = match clause.operator {
                    WhereOperator::Contains => format!("%{value}%"),
                    WhereOperator::StartsWith => format!("{value}%"),
                    WhereOperator::EndsWith => format!("%{value}"),
                    _ => {
                        return Err(OpenAuthError::Adapter(
                            "unsupported string pattern where operator".to_owned(),
                        ));
                    }
                };
                let placeholder =
                    self.push_param(params, field, DbValue::String(pattern), first_placeholder);
                if clause.mode == WhereMode::Insensitive {
                    if self == Self::Postgres {
                        Ok(format!(
                            "{column} ILIKE {placeholder} {}",
                            self.like_escape_clause()
                        ))
                    } else {
                        Ok(format!(
                            "LOWER({column}) LIKE LOWER({placeholder}) {}",
                            self.like_escape_clause()
                        ))
                    }
                } else {
                    Ok(format!(
                        "{column} LIKE {placeholder} {}",
                        self.like_escape_clause()
                    ))
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
            match (self, field.generated_id) {
                (Self::Postgres, Some(IdGeneration::Serial)) => {
                    parts.push("GENERATED BY DEFAULT AS IDENTITY".to_owned());
                }
                (Self::Postgres, Some(IdGeneration::Uuid)) => {
                    parts.push("DEFAULT pg_catalog.gen_random_uuid()".to_owned());
                }
                (Self::MySql, Some(IdGeneration::Serial)) => {
                    parts.push("AUTO_INCREMENT".to_owned());
                }
                _ => {}
            }
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
        unique: bool,
    ) -> Result<String, OpenAuthError> {
        let if_not_exists = match self {
            Self::Postgres | Self::Sqlite => " IF NOT EXISTS",
            Self::MySql => "",
        };
        let unique = if unique { "UNIQUE " } else { "" };
        Ok(format!(
            "CREATE {unique}INDEX{} {} ON {} ({})",
            if_not_exists,
            self.quote_identifier(index)?,
            self.quote_identifier(table)?,
            self.quote_identifier(column)?,
        ))
    }

    pub fn sql_type(self, logical_name: &str, field: &DbField) -> String {
        match self {
            Self::Postgres => match field.field_type {
                DbFieldType::String if field.generated_id == Some(IdGeneration::Uuid) => "UUID",
                DbFieldType::String => "TEXT",
                DbFieldType::Number => "BIGINT",
                DbFieldType::Boolean => "BOOLEAN",
                DbFieldType::Timestamp => "TIMESTAMPTZ",
                DbFieldType::Json => "JSONB",
                DbFieldType::StringArray => "TEXT[]",
                DbFieldType::NumberArray => "BIGINT[]",
            }
            .to_owned(),
            Self::Sqlite => match field.field_type {
                DbFieldType::Number if field.generated_id == Some(IdGeneration::Serial) => {
                    "INTEGER"
                }
                DbFieldType::String
                | DbFieldType::Timestamp
                | DbFieldType::Json
                | DbFieldType::StringArray
                | DbFieldType::NumberArray => "TEXT",
                DbFieldType::Number | DbFieldType::Boolean => "INTEGER",
            }
            .to_owned(),
            Self::MySql => match field.field_type {
                DbFieldType::Number if field.generated_id == Some(IdGeneration::Serial) => "BIGINT",
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
                DbFieldType::Json => matches!(actual.as_str(), "jsonb" | "json"),
                DbFieldType::StringArray => {
                    matches!(actual.as_str(), "text[]" | "_text" | "_varchar" | "_bpchar")
                }
                DbFieldType::NumberArray => matches!(
                    actual.as_str(),
                    "bigint[]" | "integer[]" | "_int8" | "_int4" | "_int2"
                ),
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

fn escape_like_pattern(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
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

    fn like_escape_clause(self) -> &'static str {
        match self {
            Self::MySql => "ESCAPE '\\\\'",
            Self::Postgres | Self::Sqlite => "ESCAPE '\\'",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn user_table() -> DbTable {
        let mut fields = IndexMap::new();
        fields.insert(
            "email".to_owned(),
            DbField::new("email", DbFieldType::String),
        );
        fields.insert("name".to_owned(), DbField::new("name", DbFieldType::String));
        DbTable {
            name: "users".to_owned(),
            fields,
            order: None,
        }
    }

    #[test]
    fn where_clause_applies_insensitive_mode_to_eq() -> Result<(), OpenAuthError> {
        let clause =
            Where::new("email", DbValue::String("ADA@EXAMPLE.COM".to_owned())).insensitive();

        let fragment = SqlDialect::Postgres.where_clause(&user_table(), &[clause])?;

        assert_eq!(fragment.sql, r#" WHERE LOWER("email") = LOWER($1)"#);
        Ok(())
    }

    #[test]
    fn where_clause_applies_insensitive_mode_to_ne() -> Result<(), OpenAuthError> {
        let clause = Where::new("email", DbValue::String("ADA@EXAMPLE.COM".to_owned()))
            .operator(WhereOperator::Ne)
            .insensitive();

        let fragment = SqlDialect::Postgres.where_clause(&user_table(), &[clause])?;

        assert_eq!(fragment.sql, r#" WHERE LOWER("email") != LOWER($1)"#);
        Ok(())
    }

    #[test]
    fn where_clause_applies_insensitive_mode_to_in() -> Result<(), OpenAuthError> {
        let clause = Where::new(
            "email",
            DbValue::StringArray(vec![
                "ADA@EXAMPLE.COM".to_owned(),
                "GRACE@EXAMPLE.COM".to_owned(),
            ]),
        )
        .operator(WhereOperator::In)
        .insensitive();

        let fragment = SqlDialect::Postgres.where_clause(&user_table(), &[clause])?;

        assert_eq!(
            fragment.sql,
            r#" WHERE LOWER("email") IN (LOWER($1), LOWER($2))"#
        );
        Ok(())
    }

    #[test]
    fn where_clause_applies_insensitive_mode_to_not_in() -> Result<(), OpenAuthError> {
        let clause = Where::new(
            "email",
            DbValue::StringArray(vec!["ADA@EXAMPLE.COM".to_owned()]),
        )
        .operator(WhereOperator::NotIn)
        .insensitive();

        let fragment = SqlDialect::Postgres.where_clause(&user_table(), &[clause])?;

        assert_eq!(fragment.sql, r#" WHERE LOWER("email") NOT IN (LOWER($1))"#);
        Ok(())
    }
}
