use openauth_core::db::{
    AdapterFuture, Count, Create, DbField, DbRecord, DbSchema, DbValue, Delete, DeleteMany,
    FindMany, FindOne, SqlAdapterRunner, SqlDialect, SqlExecutor, SqlParam, SqlRowReader,
    SqlStatement, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use sqlx::sqlite::{SqliteArguments, SqliteRow};
use sqlx::{Sqlite, SqlitePool, Transaction};

use super::errors::{inactive_transaction, sql_error_with_context};
use super::foreign_keys;
use super::query::bind_param;
use super::row::row_value_at;

pub(super) struct SqliteState<'a, 'tx> {
    pub(super) schema: &'a DbSchema,
    pub(super) executor: SqliteExecutor<'a, 'tx>,
}

pub(super) enum SqliteExecutor<'a, 'tx> {
    Pool(&'a SqlitePool),
    Transaction(tokio::sync::MutexGuard<'a, Option<Transaction<'tx, Sqlite>>>),
}

impl SqliteState<'_, '_> {
    pub(super) async fn create(self, query: Create) -> Result<DbRecord, OpenAuthError> {
        runner(self).create(query).await
    }

    pub(super) async fn find_one(self, query: FindOne) -> Result<Option<DbRecord>, OpenAuthError> {
        runner(self).find_one(query).await
    }

    pub(super) async fn find_many(self, query: FindMany) -> Result<Vec<DbRecord>, OpenAuthError> {
        runner(self).find_many(query).await
    }

    pub(super) async fn count(self, query: Count) -> Result<u64, OpenAuthError> {
        runner(self).count(query).await
    }

    pub(super) async fn update(self, query: Update) -> Result<Option<DbRecord>, OpenAuthError> {
        runner(self).update(query).await
    }

    pub(super) async fn update_many(self, query: UpdateMany) -> Result<u64, OpenAuthError> {
        runner(self).update_many(query).await
    }

    pub(super) async fn delete(self, query: Delete) -> Result<(), OpenAuthError> {
        runner(self).delete(query).await
    }

    pub(super) async fn delete_many(self, query: DeleteMany) -> Result<u64, OpenAuthError> {
        runner(self).delete_many(query).await
    }

    async fn execute_sql(
        &mut self,
        sql: String,
        args: SqliteArguments<'_>,
        params: usize,
    ) -> Result<u64, OpenAuthError> {
        match &mut self.executor {
            SqliteExecutor::Pool(pool) => {
                let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                    .await
                    .map_err(|error| sql_error_with_context("execute", &sql, params, error))?;
                sqlx::query_with(&sql, args)
                    .execute(&mut *connection)
                    .await
                    .map(|result| result.rows_affected())
                    .map_err(|error| sql_error_with_context("execute", &sql, params, error))
            }
            SqliteExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_with(&sql, args)
                    .execute(&mut **tx)
                    .await
                    .map(|result| result.rows_affected())
                    .map_err(|error| sql_error_with_context("execute", &sql, params, error))
            }
        }
    }

    async fn fetch_all_sql(
        &mut self,
        sql: String,
        args: SqliteArguments<'_>,
        params: usize,
    ) -> Result<Vec<SqliteRow>, OpenAuthError> {
        match &mut self.executor {
            SqliteExecutor::Pool(pool) => {
                let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_all", &sql, params, error))?;
                sqlx::query_with(&sql, args)
                    .fetch_all(&mut *connection)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_all", &sql, params, error))
            }
            SqliteExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_with(&sql, args)
                    .fetch_all(&mut **tx)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_all", &sql, params, error))
            }
        }
    }

    async fn fetch_optional_sql(
        &mut self,
        sql: String,
        args: SqliteArguments<'_>,
        params: usize,
    ) -> Result<Option<SqliteRow>, OpenAuthError> {
        match &mut self.executor {
            SqliteExecutor::Pool(pool) => {
                let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                    .await
                    .map_err(|error| {
                        sql_error_with_context("fetch_optional", &sql, params, error)
                    })?;
                sqlx::query_with(&sql, args)
                    .fetch_optional(&mut *connection)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_optional", &sql, params, error))
            }
            SqliteExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_with(&sql, args)
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_optional", &sql, params, error))
            }
        }
    }

    async fn fetch_scalar_sql(
        &mut self,
        sql: String,
        args: SqliteArguments<'_>,
        params: usize,
    ) -> Result<i64, OpenAuthError> {
        match &mut self.executor {
            SqliteExecutor::Pool(pool) => {
                let mut connection = foreign_keys::acquire_with_foreign_keys(pool)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_scalar", &sql, params, error))?;
                sqlx::query_scalar_with(&sql, args)
                    .fetch_one(&mut *connection)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_scalar", &sql, params, error))
            }
            SqliteExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_scalar_with(&sql, args)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_scalar", &sql, params, error))
            }
        }
    }
}

impl SqlExecutor for SqliteState<'_, '_> {
    type Row = SqliteRow;

    fn execute<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let params = statement.params.len();
            let args = sqlite_args(&statement.params)?;
            self.execute_sql(statement.sql, args, params).await
        })
    }

    fn fetch_all<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, Vec<Self::Row>> {
        Box::pin(async move {
            let params = statement.params.len();
            let args = sqlite_args(&statement.params)?;
            self.fetch_all_sql(statement.sql, args, params).await
        })
    }

    fn fetch_optional<'a>(
        &'a mut self,
        statement: SqlStatement,
    ) -> AdapterFuture<'a, Option<Self::Row>> {
        Box::pin(async move {
            let params = statement.params.len();
            let args = sqlite_args(&statement.params)?;
            self.fetch_optional_sql(statement.sql, args, params).await
        })
    }

    fn fetch_scalar_i64<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, i64> {
        Box::pin(async move {
            let params = statement.params.len();
            let args = sqlite_args(&statement.params)?;
            self.fetch_scalar_sql(statement.sql, args, params).await
        })
    }
}

struct SqliteRowReader;

impl SqlRowReader<SqliteRow> for SqliteRowReader {
    fn value_at(
        &self,
        row: &SqliteRow,
        field: &DbField,
        alias: &str,
    ) -> Result<DbValue, OpenAuthError> {
        row_value_at(row, field, alias)
    }
}

fn runner<'a, 'tx>(
    state: SqliteState<'a, 'tx>,
) -> SqlAdapterRunner<'a, SqliteState<'a, 'tx>, SqliteRowReader> {
    SqlAdapterRunner::new(SqlDialect::Sqlite, state.schema, state, SqliteRowReader)
}

fn sqlite_args(params: &[SqlParam]) -> Result<SqliteArguments<'static>, OpenAuthError> {
    let mut args = SqliteArguments::default();
    for param in params {
        bind_param(&mut args, param)?;
    }
    Ok(args)
}
