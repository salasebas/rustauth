use std::sync::Arc;

use indexmap::IndexMap;
use openauth_core::db::{
    auth_schema, AdapterCapabilities, AdapterFuture, AuthSchemaOptions, Connector, Count, Create,
    DbAdapter, DbField, DbFieldType, DbRecord, DbSchema, DbTable, DbValue, Delete, DeleteMany,
    FindMany, FindOne, JoinAdapter, OnDelete, SchemaCreation, SortDirection, TransactionCallback,
    Update, UpdateMany, Where, WhereMode, WhereOperator,
};
use openauth_core::error::OpenAuthError;
use sqlx::sqlite::{SqliteArguments, SqlitePoolOptions, SqliteRow};
use sqlx::{Arguments, Executor, Row, Sqlite, SqlitePool, Transaction};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct SqliteAdapter {
    pool: SqlitePool,
    schema: Arc<DbSchema>,
}

impl SqliteAdapter {
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_schema(pool, auth_schema(AuthSchemaOptions::default()))
    }

    pub fn with_schema(pool: SqlitePool, schema: DbSchema) -> Self {
        Self {
            pool,
            schema: Arc::new(schema),
        }
    }

    pub async fn connect(database_url: &str) -> Result<Self, OpenAuthError> {
        Self::connect_with_schema(database_url, auth_schema(AuthSchemaOptions::default())).await
    }

    pub async fn connect_with_schema(
        database_url: &str,
        schema: DbSchema,
    ) -> Result<Self, OpenAuthError> {
        let pool = SqlitePoolOptions::new()
            .connect(database_url)
            .await
            .map_err(sql_error)?;
        Ok(Self::with_schema(pool, schema))
    }

    fn state(&self) -> SqliteState<'_, '_> {
        SqliteState {
            schema: &self.schema,
            executor: SqliteExecutor::Pool(&self.pool),
        }
    }
}

impl DbAdapter for SqliteAdapter {
    fn id(&self) -> &str {
        "sqlx-sqlite"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("SQLx SQLite")
            .with_json()
            .with_arrays()
            .with_joins()
            .with_transactions()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move { self.state().create(query).await })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            if query.joins.is_empty() {
                self.state().find_one(query).await
            } else {
                let adapter =
                    JoinAdapter::new(self.schema.as_ref().clone(), Arc::new(self.clone()), false);
                adapter.find_one(query).await
            }
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            if query.joins.is_empty() {
                self.state().find_many(query).await
            } else {
                let adapter =
                    JoinAdapter::new(self.schema.as_ref().clone(), Arc::new(self.clone()), false);
                adapter.find_many(query).await
            }
        })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().count(query).await })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move { self.state().update(query).await })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().update_many(query).await })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move { self.state().delete(query).await })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().delete_many(query).await })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let tx = self.pool.begin().await.map_err(sql_error)?;
            let adapter = SqliteTxAdapter {
                schema: Arc::clone(&self.schema),
                tx: Mutex::new(Some(tx)),
            };
            let result = callback(&adapter).await;
            let mut guard = adapter.tx.lock().await;
            let Some(tx) = guard.take() else {
                return Err(OpenAuthError::Adapter(
                    "sqlite transaction was already completed".to_owned(),
                ));
            };
            drop(guard);
            match result {
                Ok(()) => tx.commit().await.map_err(sql_error),
                Err(error) => {
                    let _rollback_result = tx.rollback().await;
                    Err(error)
                }
            }
        })
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        _file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        Box::pin(async move {
            self.pool
                .execute("PRAGMA foreign_keys = ON")
                .await
                .map_err(sql_error)?;
            create_schema(SqliteExecutor::Pool(&self.pool), schema).await?;
            Ok(None)
        })
    }
}

struct SqliteTxAdapter<'tx> {
    schema: Arc<DbSchema>,
    tx: Mutex<Option<Transaction<'tx, Sqlite>>>,
}

impl DbAdapter for SqliteTxAdapter<'_> {
    fn id(&self) -> &str {
        "sqlx-sqlite"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("SQLx SQLite")
            .with_json()
            .with_arrays()
            .with_transactions()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move { self.state().await?.create(query).await })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move { self.state().await?.find_one(query).await })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move { self.state().await?.find_many(query).await })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().await?.count(query).await })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move { self.state().await?.update(query).await })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().await?.update_many(query).await })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move { self.state().await?.delete(query).await })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move { self.state().await?.delete_many(query).await })
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        callback(self)
    }
}

impl<'tx> SqliteTxAdapter<'tx> {
    async fn state<'a>(&'a self) -> Result<SqliteState<'a, 'tx>, OpenAuthError> {
        let guard = self.tx.lock().await;
        if guard.is_none() {
            return Err(OpenAuthError::Adapter(
                "sqlite transaction is no longer active".to_owned(),
            ));
        }
        Ok(SqliteState {
            schema: &self.schema,
            executor: SqliteExecutor::Transaction(guard),
        })
    }
}

struct SqliteState<'a, 'tx> {
    schema: &'a DbSchema,
    executor: SqliteExecutor<'a, 'tx>,
}

enum SqliteExecutor<'a, 'tx> {
    Pool(&'a SqlitePool),
    Transaction(tokio::sync::MutexGuard<'a, Option<Transaction<'tx, Sqlite>>>),
}

impl SqliteState<'_, '_> {
    async fn create(mut self, query: Create) -> Result<DbRecord, OpenAuthError> {
        let table = resolve_table(self.schema, &query.model)?;
        let mut columns = Vec::new();
        let mut values = Vec::new();
        let mut args = SqliteArguments::default();

        for (field, value) in &query.data {
            let (_, metadata) = resolve_field(table, field)?;
            columns.push(quote_identifier(&metadata.name)?);
            values.push("?".to_owned());
            bind_value(&mut args, metadata, value)?;
        }

        let sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_identifier(&table.name)?,
            columns.join(", "),
            values.join(", ")
        );
        self.execute(sql, args).await?;
        Ok(select_record(query.data, &query.select))
    }

    async fn find_one(self, mut query: FindOne) -> Result<Option<DbRecord>, OpenAuthError> {
        reject_joins(&query.joins)?;
        let mut find_many = FindMany::new(query.model);
        find_many.where_clauses = std::mem::take(&mut query.where_clauses);
        find_many.limit = Some(1);
        find_many.select = query.select;
        Ok(self.find_many(find_many).await?.into_iter().next())
    }

    async fn find_many(mut self, query: FindMany) -> Result<Vec<DbRecord>, OpenAuthError> {
        reject_joins(&query.joins)?;
        let table = resolve_table(self.schema, &query.model)?;
        let selection = select_fields(table, &query.select)?;
        let mut args = SqliteArguments::default();
        let where_sql = where_sql(table, &query.where_clauses, &mut args)?;
        let mut sql = format!(
            "SELECT {} FROM {}{}",
            selection
                .iter()
                .map(|(_, field)| quote_identifier(&field.name))
                .collect::<Result<Vec<_>, _>>()?
                .join(", "),
            quote_identifier(&table.name)?,
            where_sql
        );

        if let Some(sort) = query.sort_by {
            let (_, field) = resolve_field(table, &sort.field)?;
            let direction = match sort.direction {
                SortDirection::Asc => "ASC",
                SortDirection::Desc => "DESC",
            };
            sql.push_str(" ORDER BY ");
            sql.push_str(&quote_identifier(&field.name)?);
            sql.push(' ');
            sql.push_str(direction);
        }
        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ");
            sql.push_str(&limit.to_string());
        }
        if let Some(offset) = query.offset {
            sql.push_str(" OFFSET ");
            sql.push_str(&offset.to_string());
        }

        let rows = self.fetch_all(sql, args).await?;
        rows.iter()
            .map(|row| row_record(row, &selection))
            .collect::<Result<Vec<_>, _>>()
    }

    async fn count(mut self, query: Count) -> Result<u64, OpenAuthError> {
        let table = resolve_table(self.schema, &query.model)?;
        let mut args = SqliteArguments::default();
        let where_sql = where_sql(table, &query.where_clauses, &mut args)?;
        let sql = format!(
            "SELECT COUNT(*) FROM {}{}",
            quote_identifier(&table.name)?,
            where_sql
        );
        let count: i64 = self.fetch_scalar(sql, args).await?;
        u64::try_from(count)
            .map_err(|_| OpenAuthError::Adapter("sqlite returned a negative count".to_owned()))
    }

    async fn update(mut self, query: Update) -> Result<Option<DbRecord>, OpenAuthError> {
        let table = resolve_table(self.schema, &query.model)?;
        if query.data.is_empty() {
            return Ok(None);
        }
        let selection = select_fields(table, &[])?;
        let mut args = SqliteArguments::default();
        let mut assignments = Vec::new();
        for (field, value) in &query.data {
            let (_, metadata) = resolve_field(table, field)?;
            assignments.push(format!("{} = ?", quote_identifier(&metadata.name)?));
            bind_value(&mut args, metadata, value)?;
        }
        let where_sql = where_sql(table, &query.where_clauses, &mut args)?;
        let sql = format!(
            "UPDATE {} SET {} WHERE rowid IN (SELECT rowid FROM {}{} LIMIT 1) RETURNING {}",
            quote_identifier(&table.name)?,
            assignments.join(", "),
            quote_identifier(&table.name)?,
            where_sql,
            selection
                .iter()
                .map(|(_, field)| quote_identifier(&field.name))
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        );
        let row = self.fetch_optional(sql, args).await?;
        row.as_ref()
            .map(|row| row_record(row, &selection))
            .transpose()
    }

    async fn update_many(mut self, query: UpdateMany) -> Result<u64, OpenAuthError> {
        let table = resolve_table(self.schema, &query.model)?;
        if query.data.is_empty() {
            return Ok(0);
        }
        let mut args = SqliteArguments::default();
        let mut assignments = Vec::new();
        for (field, value) in &query.data {
            let (_, metadata) = resolve_field(table, field)?;
            assignments.push(format!("{} = ?", quote_identifier(&metadata.name)?));
            bind_value(&mut args, metadata, value)?;
        }
        let where_sql = where_sql(table, &query.where_clauses, &mut args)?;
        let sql = format!(
            "UPDATE {} SET {}{}",
            quote_identifier(&table.name)?,
            assignments.join(", "),
            where_sql
        );
        self.execute(sql, args).await
    }

    async fn delete(mut self, query: Delete) -> Result<(), OpenAuthError> {
        let table = resolve_table(self.schema, &query.model)?;
        let mut args = SqliteArguments::default();
        let where_sql = where_sql(table, &query.where_clauses, &mut args)?;
        let sql = format!(
            "DELETE FROM {} WHERE rowid IN (SELECT rowid FROM {}{} LIMIT 1)",
            quote_identifier(&table.name)?,
            quote_identifier(&table.name)?,
            where_sql
        );
        self.execute(sql, args).await?;
        Ok(())
    }

    async fn delete_many(mut self, query: DeleteMany) -> Result<u64, OpenAuthError> {
        let table = resolve_table(self.schema, &query.model)?;
        let mut args = SqliteArguments::default();
        let where_sql = where_sql(table, &query.where_clauses, &mut args)?;
        let sql = format!(
            "DELETE FROM {}{}",
            quote_identifier(&table.name)?,
            where_sql
        );
        self.execute(sql, args).await
    }

    async fn execute(
        &mut self,
        sql: String,
        args: SqliteArguments<'_>,
    ) -> Result<u64, OpenAuthError> {
        match &mut self.executor {
            SqliteExecutor::Pool(pool) => sqlx::query_with(&sql, args)
                .execute(*pool)
                .await
                .map(|result| result.rows_affected())
                .map_err(sql_error),
            SqliteExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_with(&sql, args)
                    .execute(&mut **tx)
                    .await
                    .map(|result| result.rows_affected())
                    .map_err(sql_error)
            }
        }
    }

    async fn fetch_all(
        &mut self,
        sql: String,
        args: SqliteArguments<'_>,
    ) -> Result<Vec<SqliteRow>, OpenAuthError> {
        match &mut self.executor {
            SqliteExecutor::Pool(pool) => sqlx::query_with(&sql, args)
                .fetch_all(*pool)
                .await
                .map_err(sql_error),
            SqliteExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_with(&sql, args)
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(sql_error)
            }
        }
    }

    async fn fetch_optional(
        &mut self,
        sql: String,
        args: SqliteArguments<'_>,
    ) -> Result<Option<SqliteRow>, OpenAuthError> {
        match &mut self.executor {
            SqliteExecutor::Pool(pool) => sqlx::query_with(&sql, args)
                .fetch_optional(*pool)
                .await
                .map_err(sql_error),
            SqliteExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_with(&sql, args)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(sql_error)
            }
        }
    }

    async fn fetch_scalar(
        &mut self,
        sql: String,
        args: SqliteArguments<'_>,
    ) -> Result<i64, OpenAuthError> {
        match &mut self.executor {
            SqliteExecutor::Pool(pool) => sqlx::query_scalar_with(&sql, args)
                .fetch_one(*pool)
                .await
                .map_err(sql_error),
            SqliteExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_scalar_with(&sql, args)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(sql_error)
            }
        }
    }
}

async fn create_schema(
    mut executor: SqliteExecutor<'_, '_>,
    schema: &DbSchema,
) -> Result<(), OpenAuthError> {
    let mut tables = schema.tables().collect::<Vec<_>>();
    tables.sort_by_key(|(_, table)| table.order.unwrap_or(u16::MAX));

    for (_, table) in &tables {
        let mut columns = Vec::new();
        for (logical_name, field) in &table.fields {
            columns.push(column_definition(logical_name, field)?);
        }
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} ({})",
            quote_identifier(&table.name)?,
            columns.join(", ")
        );
        execute_schema_sql(&mut executor, &sql).await?;
    }

    for (_, table) in tables {
        for (logical_name, field) in &table.fields {
            if field.index && !field.unique {
                let index_name = format!("idx_{}_{}", table.name, logical_name);
                let sql = format!(
                    "CREATE INDEX IF NOT EXISTS {} ON {} ({})",
                    quote_identifier(&sanitize_identifier(&index_name)?)?,
                    quote_identifier(&table.name)?,
                    quote_identifier(&field.name)?,
                );
                execute_schema_sql(&mut executor, &sql).await?;
            }
        }
    }

    Ok(())
}

async fn execute_schema_sql(
    executor: &mut SqliteExecutor<'_, '_>,
    sql: &str,
) -> Result<(), OpenAuthError> {
    match executor {
        SqliteExecutor::Pool(pool) => {
            sqlx::query(sql).execute(*pool).await.map_err(sql_error)?;
        }
        SqliteExecutor::Transaction(tx) => {
            let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
            sqlx::query(sql)
                .execute(&mut **tx)
                .await
                .map_err(sql_error)?;
        }
    }
    Ok(())
}

fn column_definition(logical_name: &str, field: &DbField) -> Result<String, OpenAuthError> {
    let mut parts = vec![quote_identifier(&field.name)?, sqlite_type(field)];
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
            quote_identifier(&foreign_key.table)?,
            quote_identifier(&foreign_key.field)?
        ));
        parts.push(on_delete_sql(foreign_key.on_delete).to_owned());
    }
    Ok(parts.join(" "))
}

fn sqlite_type(field: &DbField) -> String {
    match field.field_type {
        DbFieldType::String
        | DbFieldType::Timestamp
        | DbFieldType::Json
        | DbFieldType::StringArray
        | DbFieldType::NumberArray => "TEXT".to_owned(),
        DbFieldType::Number | DbFieldType::Boolean => "INTEGER".to_owned(),
    }
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

fn where_sql(
    table: &DbTable,
    clauses: &[Where],
    args: &mut SqliteArguments<'_>,
) -> Result<String, OpenAuthError> {
    if clauses.is_empty() {
        return Ok(String::new());
    }

    let mut sql = String::from(" WHERE ");
    for (index, clause) in clauses.iter().enumerate() {
        if index > 0 {
            sql.push(' ');
            sql.push_str(match clause.connector {
                Connector::And => "AND",
                Connector::Or => "OR",
            });
            sql.push(' ');
        }
        sql.push_str(&clause_sql(table, clause, args)?);
    }
    Ok(sql)
}

fn clause_sql(
    table: &DbTable,
    clause: &Where,
    args: &mut SqliteArguments<'_>,
) -> Result<String, OpenAuthError> {
    let (_, field) = resolve_field(table, &clause.field)?;
    let column = quote_identifier(&field.name)?;
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
            bind_value(args, field, &clause.value)?;
            Ok(format!("{column} {operator} ?"))
        }
        WhereOperator::In | WhereOperator::NotIn => {
            let placeholders = bind_array_values(args, field, &clause.value)?;
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
            args.add(pattern).map_err(argument_error)?;
            if clause.mode == WhereMode::Insensitive {
                Ok(format!("LOWER({column}) LIKE LOWER(?)"))
            } else {
                Ok(format!("{column} LIKE ?"))
            }
        }
    }
}

fn bind_array_values(
    args: &mut SqliteArguments<'_>,
    field: &DbField,
    value: &DbValue,
) -> Result<Vec<String>, OpenAuthError> {
    match value {
        DbValue::StringArray(values) => {
            for value in values {
                bind_value(args, field, &DbValue::String(value.clone()))?;
            }
            Ok(vec!["?".to_owned(); values.len()])
        }
        DbValue::NumberArray(values) => {
            for value in values {
                bind_value(args, field, &DbValue::Number(*value))?;
            }
            Ok(vec!["?".to_owned(); values.len()])
        }
        _ => Err(OpenAuthError::Adapter(
            "IN and NOT IN require array values".to_owned(),
        )),
    }
}

fn bind_value(
    args: &mut SqliteArguments<'_>,
    field: &DbField,
    value: &DbValue,
) -> Result<(), OpenAuthError> {
    match value {
        DbValue::String(value) => args.add(value.clone()).map_err(argument_error),
        DbValue::Number(value) => args.add(*value).map_err(argument_error),
        DbValue::Boolean(value) => args.add(i64::from(*value)).map_err(argument_error),
        DbValue::Timestamp(value) => args
            .add(value.format(&Rfc3339).map_err(time_error)?)
            .map_err(argument_error),
        DbValue::Json(value) => args.add(value.to_string()).map_err(argument_error),
        DbValue::StringArray(value) => args
            .add(serde_json::to_string(value).map_err(json_error)?)
            .map_err(argument_error),
        DbValue::NumberArray(value) => args
            .add(serde_json::to_string(value).map_err(json_error)?)
            .map_err(argument_error),
        DbValue::Record(_) | DbValue::RecordArray(_) => Err(OpenAuthError::Adapter(
            "joined records cannot be bound as SQL values".to_owned(),
        )),
        DbValue::Null => match field.field_type {
            DbFieldType::String
            | DbFieldType::Timestamp
            | DbFieldType::Json
            | DbFieldType::StringArray
            | DbFieldType::NumberArray => args.add(Option::<String>::None).map_err(argument_error),
            DbFieldType::Number | DbFieldType::Boolean => {
                args.add(Option::<i64>::None).map_err(argument_error)
            }
        },
    }
}

fn row_record(row: &SqliteRow, selection: &[(&str, &DbField)]) -> Result<DbRecord, OpenAuthError> {
    selection
        .iter()
        .map(|(logical_name, field)| {
            row_value(row, field).map(|value| ((*logical_name).to_owned(), value))
        })
        .collect::<Result<IndexMap<_, _>, _>>()
}

fn row_value(row: &SqliteRow, field: &DbField) -> Result<DbValue, OpenAuthError> {
    match field.field_type {
        DbFieldType::String => row
            .try_get::<Option<String>, _>(field.name.as_str())
            .map(|value| value.map(DbValue::String).unwrap_or(DbValue::Null))
            .map_err(sql_error),
        DbFieldType::Number => row
            .try_get::<Option<i64>, _>(field.name.as_str())
            .map(|value| value.map(DbValue::Number).unwrap_or(DbValue::Null))
            .map_err(sql_error),
        DbFieldType::Boolean => row
            .try_get::<Option<i64>, _>(field.name.as_str())
            .map(|value| {
                value
                    .map(|value| DbValue::Boolean(value != 0))
                    .unwrap_or(DbValue::Null)
            })
            .map_err(sql_error),
        DbFieldType::Timestamp => {
            let value = row
                .try_get::<Option<String>, _>(field.name.as_str())
                .map_err(sql_error)?;
            value
                .map(|value| {
                    OffsetDateTime::parse(&value, &Rfc3339)
                        .map(DbValue::Timestamp)
                        .map_err(time_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
        DbFieldType::Json => {
            let value = row
                .try_get::<Option<String>, _>(field.name.as_str())
                .map_err(sql_error)?;
            value
                .map(|value| {
                    serde_json::from_str(&value)
                        .map(DbValue::Json)
                        .map_err(json_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
        DbFieldType::StringArray => {
            let value = row
                .try_get::<Option<String>, _>(field.name.as_str())
                .map_err(sql_error)?;
            value
                .map(|value| {
                    serde_json::from_str::<Vec<String>>(&value)
                        .map(DbValue::StringArray)
                        .map_err(json_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
        DbFieldType::NumberArray => {
            let value = row
                .try_get::<Option<String>, _>(field.name.as_str())
                .map_err(sql_error)?;
            value
                .map(|value| {
                    serde_json::from_str::<Vec<i64>>(&value)
                        .map(DbValue::NumberArray)
                        .map_err(json_error)
                })
                .transpose()
                .map(|value| value.unwrap_or(DbValue::Null))
        }
    }
}

fn select_fields<'a>(
    table: &'a DbTable,
    select: &'a [String],
) -> Result<Vec<(&'a str, &'a DbField)>, OpenAuthError> {
    if select.is_empty() {
        return Ok(table
            .fields
            .iter()
            .map(|(logical_name, field)| (logical_name.as_str(), field))
            .collect());
    }

    select
        .iter()
        .map(|field| resolve_field(table, field))
        .collect::<Result<Vec<_>, _>>()
}

fn select_record(record: DbRecord, select: &[String]) -> DbRecord {
    if select.is_empty() {
        return record;
    }
    select
        .iter()
        .filter_map(|field| {
            record
                .get(field)
                .cloned()
                .map(|value| (field.clone(), value))
        })
        .collect()
}

fn resolve_table<'a>(schema: &'a DbSchema, model: &str) -> Result<&'a DbTable, OpenAuthError> {
    schema
        .tables()
        .find_map(|(logical_name, table)| {
            (logical_name == model || table.name == model).then_some(table)
        })
        .ok_or_else(|| OpenAuthError::TableNotFound {
            table: model.to_owned(),
        })
}

fn resolve_field<'a>(
    table: &'a DbTable,
    field: &str,
) -> Result<(&'a str, &'a DbField), OpenAuthError> {
    table
        .fields
        .iter()
        .find_map(|(logical_name, metadata)| {
            (logical_name == field || metadata.name == field)
                .then_some((logical_name.as_str(), metadata))
        })
        .ok_or_else(|| OpenAuthError::FieldNotFound {
            table: table.name.clone(),
            field: field.to_owned(),
        })
}

fn reject_joins<T>(joins: &IndexMap<String, T>) -> Result<(), OpenAuthError> {
    if joins.is_empty() {
        Ok(())
    } else {
        Err(OpenAuthError::Adapter(
            "sqlx joins are not implemented".to_owned(),
        ))
    }
}

fn quote_identifier(identifier: &str) -> Result<String, OpenAuthError> {
    validate_identifier(identifier)?;
    Ok(format!("\"{identifier}\""))
}

fn sanitize_identifier(identifier: &str) -> Result<String, OpenAuthError> {
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
    validate_identifier(&sanitized)?;
    Ok(sanitized)
}

fn validate_identifier(identifier: &str) -> Result<(), OpenAuthError> {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return Err(OpenAuthError::Adapter(
            "sqlite identifier cannot be empty".to_owned(),
        ));
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(invalid_identifier(identifier));
    }
    if chars.any(|character| !(character.is_ascii_alphanumeric() || character == '_')) {
        return Err(invalid_identifier(identifier));
    }
    Ok(())
}

fn invalid_identifier(identifier: &str) -> OpenAuthError {
    OpenAuthError::Adapter(format!("invalid sqlite identifier `{identifier}`"))
}

fn inactive_transaction() -> OpenAuthError {
    OpenAuthError::Adapter("sqlite transaction is no longer active".to_owned())
}

fn sql_error(error: sqlx::Error) -> OpenAuthError {
    OpenAuthError::Adapter(error.to_string())
}

fn argument_error(error: Box<dyn std::error::Error + Send + Sync>) -> OpenAuthError {
    OpenAuthError::Adapter(error.to_string())
}

fn time_error(error: impl std::fmt::Display) -> OpenAuthError {
    OpenAuthError::Adapter(error.to_string())
}

fn json_error(error: serde_json::Error) -> OpenAuthError {
    OpenAuthError::Adapter(error.to_string())
}
