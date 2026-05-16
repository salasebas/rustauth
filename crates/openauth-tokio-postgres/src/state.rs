use openauth_core::db::{
    AdapterFuture, Count, Create, DbField, DbRecord, DbSchema, DbValue, Delete, DeleteMany,
    FindMany, FindOne, SqlAdapterRunner, SqlDialect, SqlExecutor, SqlRowReader, SqlStatement,
    Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use tokio::sync::MutexGuard;
use tokio_postgres::{Client, Row};

use super::driver::{param_refs, postgres_params};
use super::errors::postgres_error;
use super::row::row_value_at;

pub(crate) struct TokioPostgresState<'a> {
    pub(crate) schema: &'a DbSchema,
    pub(crate) client: MutexGuard<'a, Client>,
}

impl TokioPostgresState<'_> {
    pub(crate) async fn create(self, query: Create) -> Result<DbRecord, OpenAuthError> {
        runner(self).create(query).await
    }

    pub(crate) async fn find_one(self, query: FindOne) -> Result<Option<DbRecord>, OpenAuthError> {
        runner(self).find_one(query).await
    }

    pub(crate) async fn find_many(self, query: FindMany) -> Result<Vec<DbRecord>, OpenAuthError> {
        runner(self).find_many(query).await
    }

    pub(crate) async fn count(self, query: Count) -> Result<u64, OpenAuthError> {
        runner(self).count(query).await
    }

    pub(crate) async fn update(self, query: Update) -> Result<Option<DbRecord>, OpenAuthError> {
        runner(self).update(query).await
    }

    pub(crate) async fn update_many(self, query: UpdateMany) -> Result<u64, OpenAuthError> {
        runner(self).update_many(query).await
    }

    pub(crate) async fn delete(self, query: Delete) -> Result<(), OpenAuthError> {
        runner(self).delete(query).await
    }

    pub(crate) async fn delete_many(self, query: DeleteMany) -> Result<u64, OpenAuthError> {
        runner(self).delete_many(query).await
    }
}

impl SqlExecutor for TokioPostgresState<'_> {
    type Row = Row;

    fn execute<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            let values = postgres_params(&statement.params)?;
            let params = param_refs(&values);
            self.client
                .execute(&statement.sql, &params)
                .await
                .map_err(postgres_error)
        })
    }

    fn fetch_all<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, Vec<Self::Row>> {
        Box::pin(async move {
            let values = postgres_params(&statement.params)?;
            let params = param_refs(&values);
            self.client
                .query(&statement.sql, &params)
                .await
                .map_err(postgres_error)
        })
    }

    fn fetch_optional<'a>(
        &'a mut self,
        statement: SqlStatement,
    ) -> AdapterFuture<'a, Option<Self::Row>> {
        Box::pin(async move {
            let values = postgres_params(&statement.params)?;
            let params = param_refs(&values);
            self.client
                .query_opt(&statement.sql, &params)
                .await
                .map_err(postgres_error)
        })
    }

    fn fetch_scalar_i64<'a>(&'a mut self, statement: SqlStatement) -> AdapterFuture<'a, i64> {
        Box::pin(async move {
            let values = postgres_params(&statement.params)?;
            let params = param_refs(&values);
            let row = self
                .client
                .query_one(&statement.sql, &params)
                .await
                .map_err(postgres_error)?;
            Ok(row.get::<_, i64>(0))
        })
    }
}

struct TokioPostgresRowReader;

impl SqlRowReader<Row> for TokioPostgresRowReader {
    fn value_at(&self, row: &Row, field: &DbField, alias: &str) -> Result<DbValue, OpenAuthError> {
        row_value_at(row, field, alias)
    }
}

fn runner<'a>(
    state: TokioPostgresState<'a>,
) -> SqlAdapterRunner<'a, TokioPostgresState<'a>, TokioPostgresRowReader> {
    SqlAdapterRunner::new(
        SqlDialect::Postgres,
        state.schema,
        state,
        TokioPostgresRowReader,
    )
}
