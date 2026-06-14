use super::*;

pub fn create_statement(
    dialect: SqlDialect,
    schema: &DbSchema,
    query: &Create,
) -> Result<SqlStatement, RustAuthError> {
    let table = resolve_table(schema, &query.model)?;
    let selection = selected_fields(table, &query.select)?;
    let mut columns = Vec::new();
    let mut placeholders = Vec::new();
    let mut params = Vec::new();

    for (field, value) in &query.data {
        let (_, metadata) = resolve_field(table, field)?;
        columns.push(dialect.quote_identifier(&metadata.name)?);
        params.push(SqlParam::new(metadata, value.clone()));
        placeholders.push(dialect.placeholder(params.len()));
    }

    let mut sql = if columns.is_empty() {
        match dialect {
            SqlDialect::Postgres | SqlDialect::Sqlite => format!(
                "INSERT INTO {} DEFAULT VALUES",
                dialect.quote_identifier(&table.name)?
            ),
            SqlDialect::MySql => format!(
                "INSERT INTO {} () VALUES ()",
                dialect.quote_identifier(&table.name)?
            ),
        }
    } else {
        format!(
            "INSERT INTO {} ({}) VALUES ({})",
            dialect.quote_identifier(&table.name)?,
            columns.join(", "),
            placeholders.join(", ")
        )
    };
    if dialect.supports_insert_returning() && table_has_database_generated_id(table) {
        sql.push_str(" RETURNING ");
        sql.push_str(
            &selection
                .iter()
                .map(|selected| dialect.quote_identifier(&selected.field.name))
                .collect::<Result<Vec<_>, _>>()?
                .join(", "),
        );
    }

    Ok(SqlStatement { sql, params })
}

pub fn create_returning_selection(
    schema: &DbSchema,
    query: &Create,
) -> Result<Vec<SqlSelectedField>, RustAuthError> {
    selected_fields(resolve_table(schema, &query.model)?, &query.select)
}

pub fn find_one_statement(
    dialect: SqlDialect,
    schema: &DbSchema,
    query: &FindOne,
) -> Result<SqlReadStatement, RustAuthError> {
    let mut find_many = FindMany::new(query.model.clone());
    find_many.where_clauses = query.where_clauses.clone();
    find_many.limit = Some(1);
    find_many.select = query.select.clone();
    find_many.joins = query.joins.clone();
    find_many_statement(dialect, schema, &find_many)
}

pub fn find_many_statement(
    dialect: SqlDialect,
    schema: &DbSchema,
    query: &FindMany,
) -> Result<SqlReadStatement, RustAuthError> {
    let table = resolve_table(schema, &query.model)?;
    let selection = selected_fields(table, &query.select)?;
    let where_sql = dialect.where_clause(table, &query.where_clauses)?;
    let sql = format!(
        "SELECT {} FROM {}{}{}",
        selection
            .iter()
            .map(|selected| dialect.quote_identifier(&selected.field.name))
            .collect::<Result<Vec<_>, _>>()?
            .join(", "),
        dialect.quote_identifier(&table.name)?,
        where_sql.sql,
        dialect.order_limit_offset(table, query.sort_by.as_ref(), query.limit, query.offset)?
    );

    Ok(SqlReadStatement {
        statement: SqlStatement {
            sql,
            params: where_sql.params,
        },
        selection,
    })
}

pub fn find_many_with_joins_statement<'a>(
    dialect: SqlDialect,
    schema: &'a DbSchema,
    query: &FindMany,
) -> Result<SqlJoinReadStatement<'a>, RustAuthError> {
    let (base_logical, table) = resolve_table_with_logical(schema, &query.model)?;
    let joins = resolve_native_joins(schema, base_logical, table, &query.joins, 100)?;
    let base_selection = internal_base_selection(table, &query.select, &joins)?;
    let where_sql = dialect.where_clause(table, &query.where_clauses)?;
    let base_columns = base_selection
        .iter()
        .map(|(_, field)| dialect.quote_identifier(&field.name))
        .collect::<Result<Vec<_>, _>>()?;
    let base_sql = format!(
        "SELECT {} FROM {}{}{}",
        base_columns.join(", "),
        dialect.quote_identifier(&table.name)?,
        where_sql.sql,
        dialect.order_limit_offset(table, query.sort_by.as_ref(), query.limit, query.offset)?
    );

    let mut selects = vec![format!(
        "{}.{} AS {}",
        dialect.quote_identifier("base")?,
        dialect.quote_identifier(&resolve_field_from_selection(&base_selection, "id")?.name)?,
        dialect.quote_identifier("__base_id")?
    )];
    for (index, (_, field)) in base_selection.iter().enumerate() {
        selects.push(format!(
            "{}.{} AS {}",
            dialect.quote_identifier("base")?,
            dialect.quote_identifier(&field.name)?,
            dialect.quote_identifier(&base_alias(index))?
        ));
    }
    for (join_index, join) in joins.iter().enumerate() {
        for (field_index, (_, field)) in join.selection.iter().enumerate() {
            selects.push(format!(
                "{}.{} AS {}",
                dialect.quote_identifier(&join_alias(join_index))?,
                dialect.quote_identifier(&field.name)?,
                dialect.quote_identifier(&join_field_alias(join_index, field_index))?
            ));
        }
    }

    let mut sql = format!(
        "SELECT {} FROM ({}) AS {}",
        selects.join(", "),
        base_sql,
        dialect.quote_identifier("base")?
    );
    for (index, join) in joins.iter().enumerate() {
        sql.push_str(" LEFT JOIN ");
        sql.push_str(&dialect.quote_identifier(&join.table.name)?);
        sql.push_str(" AS ");
        sql.push_str(&dialect.quote_identifier(&join_alias(index))?);
        sql.push_str(" ON ");
        sql.push_str(&dialect.quote_identifier(&join_alias(index))?);
        sql.push('.');
        sql.push_str(&dialect.quote_identifier(&join.to)?);
        sql.push_str(" = ");
        sql.push_str(&dialect.quote_identifier("base")?);
        sql.push('.');
        sql.push_str(&dialect.quote_identifier(&join.from)?);
    }

    Ok(SqlJoinReadStatement {
        statement: SqlStatement {
            sql,
            params: where_sql.params,
        },
        base_selection,
        joins,
    })
}

pub fn count_statement(
    dialect: SqlDialect,
    schema: &DbSchema,
    query: &Count,
) -> Result<SqlStatement, RustAuthError> {
    let table = resolve_table(schema, &query.model)?;
    let where_sql = dialect.where_clause(table, &query.where_clauses)?;
    Ok(SqlStatement {
        sql: format!(
            "SELECT COUNT(*) FROM {}{}",
            dialect.quote_identifier(&table.name)?,
            where_sql.sql
        ),
        params: where_sql.params,
    })
}

pub fn update_one_plan(
    dialect: SqlDialect,
    schema: &DbSchema,
    query: &Update,
) -> Result<SqlUpdateOnePlan, RustAuthError> {
    let table = resolve_table(schema, &query.model)?;
    let selection = selected_fields(table, &[])?;

    match dialect {
        SqlDialect::Postgres | SqlDialect::Sqlite => {
            let assignment = update_assignment(dialect, table, &query.data, 1)?;
            let where_sql =
                dialect.where_clause_starting_at(table, &query.where_clauses, assignment.next)?;
            let row_id = match dialect {
                SqlDialect::Postgres => "ctid",
                SqlDialect::Sqlite => "rowid",
                SqlDialect::MySql => {
                    return Err(RustAuthError::Adapter(
                        "mysql update-one uses a preselect plan".to_owned(),
                    ));
                }
            };
            let mut params = assignment.params;
            params.extend(where_sql.params);
            Ok(SqlUpdateOnePlan::Returning(SqlReadStatement {
                statement: SqlStatement {
                    sql: format!(
                        "UPDATE {} SET {} WHERE {row_id} IN (SELECT {row_id} FROM {}{} LIMIT 1) RETURNING {}",
                        dialect.quote_identifier(&table.name)?,
                        assignment.sql.join(", "),
                        dialect.quote_identifier(&table.name)?,
                        where_sql.sql,
                        selection
                            .iter()
                            .map(|selected| dialect.quote_identifier(&selected.field.name))
                            .collect::<Result<Vec<_>, _>>()?
                            .join(", ")
                    ),
                    params,
                },
                selection,
            }))
        }
        SqlDialect::MySql => {
            let mut select_query = FindMany::new(query.model.clone());
            select_query.where_clauses = query.where_clauses.clone();
            select_query.limit = Some(1);
            let select = find_many_statement(dialect, schema, &select_query)?;
            let assignment = update_assignment(dialect, table, &query.data, 1)?;
            let where_sql =
                dialect.where_clause_starting_at(table, &query.where_clauses, assignment.next)?;
            let mut params = assignment.params;
            params.extend(where_sql.params);
            Ok(SqlUpdateOnePlan::PreselectThenUpdate {
                select,
                update: SqlStatement {
                    sql: format!(
                        "UPDATE {} SET {}{} LIMIT 1",
                        dialect.quote_identifier(&table.name)?,
                        assignment.sql.join(", "),
                        where_sql.sql
                    ),
                    params,
                },
                data: query.data.clone(),
            })
        }
    }
}

pub fn update_many_statement(
    dialect: SqlDialect,
    schema: &DbSchema,
    query: &UpdateMany,
) -> Result<SqlStatement, RustAuthError> {
    let table = resolve_table(schema, &query.model)?;
    let assignment = update_assignment(dialect, table, &query.data, 1)?;
    let where_sql =
        dialect.where_clause_starting_at(table, &query.where_clauses, assignment.next)?;
    let mut params = assignment.params;
    params.extend(where_sql.params);
    Ok(SqlStatement {
        sql: format!(
            "UPDATE {} SET {}{}",
            dialect.quote_identifier(&table.name)?,
            assignment.sql.join(", "),
            where_sql.sql
        ),
        params,
    })
}

pub fn delete_one_statement(
    dialect: SqlDialect,
    schema: &DbSchema,
    query: &Delete,
) -> Result<SqlDeleteOnePlan, RustAuthError> {
    let table = resolve_table(schema, &query.model)?;
    let where_sql = dialect.where_clause(table, &query.where_clauses)?;
    let statement = match dialect {
        SqlDialect::Postgres => SqlStatement {
            sql: format!(
                "DELETE FROM {} WHERE ctid IN (SELECT ctid FROM {}{} LIMIT 1)",
                dialect.quote_identifier(&table.name)?,
                dialect.quote_identifier(&table.name)?,
                where_sql.sql
            ),
            params: where_sql.params,
        },
        SqlDialect::Sqlite => SqlStatement {
            sql: format!(
                "DELETE FROM {} WHERE rowid IN (SELECT rowid FROM {}{} LIMIT 1)",
                dialect.quote_identifier(&table.name)?,
                dialect.quote_identifier(&table.name)?,
                where_sql.sql
            ),
            params: where_sql.params,
        },
        SqlDialect::MySql => SqlStatement {
            sql: format!(
                "DELETE FROM {}{} LIMIT 1",
                dialect.quote_identifier(&table.name)?,
                where_sql.sql
            ),
            params: where_sql.params,
        },
    };
    let strategy = match dialect {
        SqlDialect::Postgres | SqlDialect::Sqlite => DeleteOneStrategy::NestedId,
        SqlDialect::MySql => DeleteOneStrategy::Limit,
    };
    Ok(SqlDeleteOnePlan {
        statement,
        strategy,
    })
}

pub fn delete_many_statement(
    dialect: SqlDialect,
    schema: &DbSchema,
    query: &DeleteMany,
) -> Result<SqlStatement, RustAuthError> {
    let table = resolve_table(schema, &query.model)?;
    let where_sql = dialect.where_clause(table, &query.where_clauses)?;
    Ok(SqlStatement {
        sql: format!(
            "DELETE FROM {}{}",
            dialect.quote_identifier(&table.name)?,
            where_sql.sql
        ),
        params: where_sql.params,
    })
}

struct UpdateAssignment {
    sql: Vec<String>,
    params: Vec<SqlParam>,
    next: usize,
}

fn update_assignment(
    dialect: SqlDialect,
    table: &DbTable,
    data: &DbRecord,
    first_placeholder: usize,
) -> Result<UpdateAssignment, RustAuthError> {
    let mut sql = Vec::new();
    let mut params = Vec::new();
    for (field, value) in data {
        let (_, metadata) = resolve_field(table, field)?;
        params.push(SqlParam::new(metadata, value.clone()));
        sql.push(format!(
            "{} = {}",
            dialect.quote_identifier(&metadata.name)?,
            dialect.placeholder(first_placeholder + params.len() - 1)
        ));
    }
    Ok(UpdateAssignment {
        sql,
        next: first_placeholder + params.len(),
        params,
    })
}

pub fn table_has_database_generated_id(table: &DbTable) -> bool {
    table
        .field("id")
        .and_then(|field| field.generated_id)
        .is_some()
}

impl SqlDialect {
    pub fn supports_insert_returning(self) -> bool {
        matches!(self, Self::Postgres | Self::Sqlite)
    }
}
