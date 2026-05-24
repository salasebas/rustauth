use std::sync::Arc;

use deadpool_postgres::Client as DeadpoolClient;
use openauth_core::db::{
    AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, Delete, DeleteMany,
    FindMany, FindOne, JoinAdapter, TransactionCallback, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use openauth_tokio_postgres::driver::PostgresSqlState;
use tokio::sync::Mutex;

use crate::config::pg_client;

pub(crate) struct DeadpoolPostgresTxAdapter {
    pub(crate) client: Arc<Mutex<DeadpoolClient>>,
    pub(crate) schema: Arc<openauth_core::db::DbSchema>,
}

impl DeadpoolPostgresTxAdapter {
    async fn run_with_state<T>(
        &self,
        f: impl for<'a> FnOnce(PostgresSqlState<'a>) -> AdapterFuture<'a, T> + Send,
    ) -> Result<T, OpenAuthError>
    where
        T: Send + 'static,
    {
        let client = self.client.lock().await;
        f(PostgresSqlState::new(
            self.schema.as_ref(),
            pg_client(&client),
        ))
        .await
    }
}

impl DbAdapter for DeadpoolPostgresTxAdapter {
    fn id(&self) -> &str {
        "deadpool-postgres-tx"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("deadpool-postgres transaction")
            .with_uuid_ids()
            .with_json()
            .with_arrays()
            .with_joins()
            .with_transactions()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.create(query)))
                .await
        })
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.find_one(query)))
                .await
        })
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        Box::pin(async move {
            if query.joins.len() <= 1 {
                self.run_with_state(|state| Box::pin(state.find_many(query)))
                    .await
            } else {
                let adapter = JoinAdapter::new(self.schema.as_ref().clone(), Arc::new(self), false);
                adapter.find_many(query).await
            }
        })
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.count(query)))
                .await
        })
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.update(query)))
                .await
        })
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.update_many(query)))
                .await
        })
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.delete(query)))
                .await
        })
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        Box::pin(async move {
            self.run_with_state(|state| Box::pin(state.delete_many(query)))
                .await
        })
    }

    fn transaction<'a>(&'a self, _callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        Box::pin(async {
            Err(OpenAuthError::Adapter(
                "nested deadpool-postgres transactions are not supported".to_owned(),
            ))
        })
    }
}
