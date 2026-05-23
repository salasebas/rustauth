use openauth_core::db::{
    AdapterFuture, Count, Create, DbField, DbRecord, DbSchema, DbValue, Delete, DeleteMany,
    FindMany, FindOne, SqlAdapterRunner, SqlDialect, SqlExecutor, SqlParam, SqlRowReader,
    SqlStatement, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use sqlx::mysql::{MySqlArguments, MySqlRow};
use sqlx::{MySql, MySqlPool, Transaction};

use super::errors::{inactive_transaction, sql_error_with_context};
use super::query::bind_param;
use super::row::row_value_at;

pub(super) struct MySqlState<'a, 'tx> {
    pub(super) schema: &'a DbSchema,
    pub(super) executor: MySqlExecutor<'a, 'tx>,
}

pub(super) enum MySqlExecutor<'a, 'tx> {
    Pool(&'a MySqlPool),
    Transaction(tokio::sync::MutexGuard<'a, Option<Transaction<'tx, MySql>>>),
}

impl MySqlState<'_, '_> {
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
        args: MySqlArguments,
        params: usize,
    ) -> Result<u64, OpenAuthError> {
        match &mut self.executor {
            MySqlExecutor::Pool(pool) => sqlx::query_with(&sql, args)
                .execute(*pool)
                .await
                .map(|result| result.rows_affected())
                .map_err(|error| sql_error_with_context("execute", &sql, params, error)),
            MySqlExecutor::Transaction(tx) => {
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
        args: MySqlArguments,
        params: usize,
    ) -> Result<Vec<MySqlRow>, OpenAuthError> {
        match &mut self.executor {
            MySqlExecutor::Pool(pool) => sqlx::query_with(&sql, args)
                .fetch_all(*pool)
                .await
                .map_err(|error| sql_error_with_context("fetch_all", &sql, params, error)),
            MySqlExecutor::Transaction(tx) => {
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
        args: MySqlArguments,
        params: usize,
    ) -> Result<Option<MySqlRow>, OpenAuthError> {
        match &mut self.executor {
            MySqlExecutor::Pool(pool) => sqlx::query_with(&sql, args)
                .fetch_optional(*pool)
                .await
                .map_err(|error| sql_error_with_context("fetch_optional", &sql, params, error)),
            MySqlExecutor::Transaction(tx) => {
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
        args: MySqlArguments,
        params: usize,
    ) -> Result<i64, OpenAuthError> {
        match &mut self.executor {
            MySqlExecutor::Pool(pool) => sqlx::query_scalar_with(&sql, args)
                .fetch_one(*pool)
                .await
                .map_err(|error| sql_error_with_context("fetch_scalar", &sql, params, error)),
            MySqlExecutor::Transaction(tx) => {
                let tx = tx.as_mut().ok_or_else(inactive_transaction)?;
                sqlx::query_scalar_with(&sql, args)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|error| sql_error_with_context("fetch_scalar", &sql, params, error))
            }
        }
    }
}

impl SqlExecutor for MySqlState<'_, '_> {
    type Row = MySqlRow;

    fn execute<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let params = statement.params.len();
            let args = mysql_args(&statement.params)?;
            self.execute_sql(statement.sql, args, params).await
        })
    }

    fn fetch_all<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, Vec<Self::Row>> {
        Box::pin(async move {
            let params = statement.params.len();
            let args = mysql_args(&statement.params)?;
            self.fetch_all_sql(statement.sql, args, params).await
        })
    }

    fn fetch_optional<'a>(
        &'a mut self,
        statement: SqlStatement,
    ) -> AdapterFuture<'a, Option<Self::Row>> {
        Box::pin(async move {
            let params = statement.params.len();
            let args = mysql_args(&statement.params)?;
            self.fetch_optional_sql(statement.sql, args, params).await
        })
    }

    fn fetch_scalar_i64<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, i64> {
        Box::pin(async move {
            let params = statement.params.len();
            let args = mysql_args(&statement.params)?;
            self.fetch_scalar_sql(statement.sql, args, params).await
        })
    }
}

struct MySqlRowReader;

impl SqlRowReader<MySqlRow> for MySqlRowReader {
    fn value_at(
        &self,
        row: &MySqlRow,
        field: &DbField,
        alias: &str,
    ) -> Result<DbValue, OpenAuthError> {
        row_value_at(row, field, alias)
    }
}

fn runner<'a, 'tx>(
    state: MySqlState<'a, 'tx>,
) -> SqlAdapterRunner<'a, MySqlState<'a, 'tx>, MySqlRowReader> {
    SqlAdapterRunner::new(SqlDialect::MySql, state.schema, state, MySqlRowReader)
}

fn mysql_args(params: &[SqlParam]) -> Result<MySqlArguments, OpenAuthError> {
    let mut args = MySqlArguments::default();
    for param in params {
        bind_param(&mut args, param)?;
    }
    Ok(args)
}
