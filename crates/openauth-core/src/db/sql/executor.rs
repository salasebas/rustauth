use super::*;

/// Minimal async execution boundary required by the shared SQL runner.
///
/// Adapter crates implement this trait for their driver/pool/transaction
/// context. The shared layer owns SQL planning, while this trait owns only
/// driver execution and returning raw driver rows.
pub trait SqlExecutor {
    /// Driver-specific row type returned by fetch operations.
    type Row;

    /// Executes a statement that does not need decoded rows and returns affected rows.
    fn execute<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, u64>;

    /// Fetches all rows produced by a read statement.
    fn fetch_all<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, Vec<Self::Row>>;

    /// Fetches at most one row produced by a read statement.
    fn fetch_optional<'a>(
        &'a mut self,
        statement: SqlStatement,
    ) -> AdapterFuture<'a, Option<Self::Row>>;

    /// Fetches a single signed integer scalar, used by count queries.
    fn fetch_scalar_i64<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, i64>;
}

/// Driver row decoding boundary for converting raw driver rows into OpenAuth values.
pub trait SqlRowReader<Row> {
    /// Reads a single projected field by SQL alias.
    fn value_at(&self, row: &Row, field: &DbField, alias: &str) -> Result<DbValue, OpenAuthError>;

    /// Reads a complete record from the selected fields tracked by a read statement.
    fn record(&self, row: &Row, selection: &[SqlSelectedField]) -> Result<DbRecord, OpenAuthError> {
        selection
            .iter()
            .map(|selected| {
                self.value_at(row, &selected.field, &selected.alias)
                    .map(|value| (selected.logical_name.clone(), value))
            })
            .collect()
    }
}

/// Shared CRUD runner for SQL adapters that can execute raw SQL.
pub struct SqlAdapterRunner<'a, E, R> {
    dialect: SqlDialect,
    schema: &'a DbSchema,
    executor: E,
    row_reader: R,
}

impl<'a, E, R> SqlAdapterRunner<'a, E, R> {
    /// Creates a runner for one adapter operation.
    pub fn new(dialect: SqlDialect, schema: &'a DbSchema, executor: E, row_reader: R) -> Self {
        Self {
            dialect,
            schema,
            executor,
            row_reader,
        }
    }
}

impl<E, R> SqlAdapterRunner<'_, E, R>
where
    E: SqlExecutor,
    R: SqlRowReader<E::Row>,
{
    pub async fn create(mut self, query: Create) -> Result<DbRecord, OpenAuthError> {
        let table = resolve_table(self.schema, &query.model)?;
        let statement = create_statement(self.dialect, self.schema, &query)?;
        if self.dialect.supports_insert_returning() && table_has_database_generated_id(table) {
            let selection = create_returning_selection(self.schema, &query)?;
            let row = self.executor.fetch_optional(statement).await?;
            return row
                .as_ref()
                .map(|row| self.row_reader.record(row, &selection))
                .transpose()?
                .ok_or_else(|| {
                    OpenAuthError::Adapter(
                        "sql adapter did not return inserted database-generated id".to_owned(),
                    )
                });
        }
        self.executor.execute(statement).await?;
        if self.dialect == SqlDialect::MySql
            && table
                .field("id")
                .is_some_and(|field| field.generated_id == Some(IdGeneration::Serial))
        {
            let id = self
                .executor
                .fetch_scalar_i64(SqlStatement::new("SELECT CAST(LAST_INSERT_ID() AS SIGNED)"))
                .await?;
            let mut record = query.data;
            record.insert("id".to_owned(), DbValue::Number(id));
            return Ok(select_record(record, &query.select));
        }
        Ok(select_record(query.data, &query.select))
    }

    pub async fn find_one(mut self, query: FindOne) -> Result<Option<DbRecord>, OpenAuthError> {
        if !query.joins.is_empty() {
            let mut find_many = FindMany::new(query.model);
            find_many.where_clauses = query.where_clauses;
            find_many.limit = Some(1);
            find_many.select = query.select;
            find_many.joins = query.joins;
            return self
                .find_many(find_many)
                .await
                .map(|records| records.into_iter().next());
        }
        let read = find_one_statement(self.dialect, self.schema, &query)?;
        let row = self.executor.fetch_optional(read.statement).await?;
        row.as_ref()
            .map(|row| self.row_reader.record(row, &read.selection))
            .transpose()
    }

    pub async fn find_many(mut self, query: FindMany) -> Result<Vec<DbRecord>, OpenAuthError> {
        if !query.joins.is_empty() {
            return self.find_many_with_joins(query).await;
        }
        let read = find_many_statement(self.dialect, self.schema, &query)?;
        let rows = self.executor.fetch_all(read.statement).await?;
        rows.iter()
            .map(|row| self.row_reader.record(row, &read.selection))
            .collect()
    }

    async fn find_many_with_joins(
        mut self,
        query: FindMany,
    ) -> Result<Vec<DbRecord>, OpenAuthError> {
        let read = find_many_with_joins_statement(self.dialect, self.schema, &query)?;
        let rows = self.executor.fetch_all(read.statement).await?;
        joined_rows(
            &rows,
            &read.base_selection,
            &query.select,
            &read.joins,
            |row, field, alias| self.row_reader.value_at(row, field, alias),
        )
    }

    pub async fn count(mut self, query: Count) -> Result<u64, OpenAuthError> {
        let statement = count_statement(self.dialect, self.schema, &query)?;
        let count = self.executor.fetch_scalar_i64(statement).await?;
        u64::try_from(count).map_err(|_| OpenAuthError::NumericOutOfRange {
            context: "SQL count result",
        })
    }

    pub async fn update(mut self, query: Update) -> Result<Option<DbRecord>, OpenAuthError> {
        if query.data.is_empty() {
            return Ok(None);
        }
        match update_one_plan(self.dialect, self.schema, &query)? {
            SqlUpdateOnePlan::Returning(read) => {
                let row = self.executor.fetch_optional(read.statement).await?;
                row.as_ref()
                    .map(|row| self.row_reader.record(row, &read.selection))
                    .transpose()
            }
            SqlUpdateOnePlan::PreselectThenUpdate {
                select,
                update,
                data,
            } => {
                let Some(row) = self.executor.fetch_optional(select.statement).await? else {
                    return Ok(None);
                };
                let mut record = self.row_reader.record(&row, &select.selection)?;
                self.executor.execute(update).await?;
                record.extend(data);
                Ok(Some(record))
            }
        }
    }

    pub async fn update_many(mut self, query: UpdateMany) -> Result<u64, OpenAuthError> {
        if query.data.is_empty() {
            return Ok(0);
        }
        let statement = update_many_statement(self.dialect, self.schema, &query)?;
        self.executor.execute(statement).await
    }

    pub async fn delete(mut self, query: Delete) -> Result<(), OpenAuthError> {
        let plan = delete_one_statement(self.dialect, self.schema, &query)?;
        self.executor.execute(plan.statement).await?;
        Ok(())
    }

    pub async fn delete_many(mut self, query: DeleteMany) -> Result<u64, OpenAuthError> {
        let statement = delete_many_statement(self.dialect, self.schema, &query)?;
        self.executor.execute(statement).await
    }
}
