use std::sync::Arc;

use openauth_core::db::{
    AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, DbSchema, Delete,
    DeleteMany, FindMany, FindOne, TransactionCallback, Update, UpdateMany,
};
use openauth_core::error::OpenAuthError;
use tokio::sync::Mutex;
use tokio_postgres::Client;

use crate::driver::PostgresSqlState;

pub(crate) struct TokioPostgresTxAdapter {
    client: Arc<Mutex<Client>>,
    schema: Arc<DbSchema>,
}

impl TokioPostgresTxAdapter {
    pub(crate) fn new(client: Arc<Mutex<Client>>, schema: Arc<DbSchema>) -> Self {
        Self { client, schema }
    }

    async fn run_with_state<T>(
        &self,
        f: impl for<'a> FnOnce(PostgresSqlState<'a>) -> AdapterFuture<'a, T> + Send,
    ) -> Result<T, OpenAuthError>
    where
        T: Send + 'static,
    {
        let client = self.client.lock().await;
        f(PostgresSqlState::new(self.schema.as_ref(), &client)).await
    }
}

impl DbAdapter for TokioPostgresTxAdapter {
    fn id(&self) -> &str {
        "tokio-postgres-tx"
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::new(self.id())
            .named("tokio-postgres transaction")
            .with_uuid_ids()
            .with_json()
            .with_arrays()
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
            self.run_with_state(|state| Box::pin(state.find_many(query)))
                .await
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
                "nested tokio-postgres transactions are not supported".to_owned(),
            ))
        })
    }
}
