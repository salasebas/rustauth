//! Database adapter wrapper that executes plugin hooks around mutations.

mod pipeline;

use std::sync::Arc;

use super::{
    AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, Delete, DeleteMany,
    FindMany, FindOne, SchemaCreation, TransactionCallback, Update, UpdateMany,
};
use crate::db::DbSchema;
use crate::env::logger::{create_logger, Logger, LoggerOptions};
use crate::plugin::PluginDatabaseHook;
use pipeline::{
    hooked_create, hooked_delete, hooked_delete_many, hooked_update, hooked_update_many,
    AfterHookQueue,
};

/// Adapter wrapper that runs plugin database hooks for mutating operations.
#[derive(Clone)]
pub struct HookedAdapter<A = Arc<dyn DbAdapter>> {
    inner: A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    logger: Logger,
    after_queue: Option<AfterHookQueue>,
}

impl<A> HookedAdapter<A> {
    pub fn new(inner: A, hooks: Vec<PluginDatabaseHook>) -> Self {
        Self::with_logger(inner, hooks, create_logger(LoggerOptions::default()))
    }

    pub fn with_logger(inner: A, hooks: Vec<PluginDatabaseHook>, logger: Logger) -> Self {
        Self {
            inner,
            hooks: Arc::new(hooks),
            logger,
            after_queue: None,
        }
    }

    pub fn hooks(&self) -> &[PluginDatabaseHook] {
        self.hooks.as_slice()
    }

    fn with_after_queue(
        inner: A,
        hooks: Arc<Vec<PluginDatabaseHook>>,
        logger: Logger,
        after_queue: AfterHookQueue,
    ) -> Self {
        Self {
            inner,
            hooks,
            logger,
            after_queue: Some(after_queue),
        }
    }
}

impl<A> DbAdapter for HookedAdapter<A>
where
    A: DbAdapter,
{
    fn id(&self) -> &str {
        self.inner.id()
    }

    fn capabilities(&self) -> AdapterCapabilities {
        self.inner.capabilities()
    }

    fn create<'a>(&'a self, query: Create) -> AdapterFuture<'a, DbRecord> {
        hooked_create(
            &self.inner,
            Arc::clone(&self.hooks),
            self.logger.clone(),
            self.after_queue.clone(),
            query,
        )
    }

    fn find_one<'a>(&'a self, query: FindOne) -> AdapterFuture<'a, Option<DbRecord>> {
        self.inner.find_one(query)
    }

    fn find_many<'a>(&'a self, query: FindMany) -> AdapterFuture<'a, Vec<DbRecord>> {
        self.inner.find_many(query)
    }

    fn count<'a>(&'a self, query: Count) -> AdapterFuture<'a, u64> {
        self.inner.count(query)
    }

    fn update<'a>(&'a self, query: Update) -> AdapterFuture<'a, Option<DbRecord>> {
        hooked_update(
            &self.inner,
            Arc::clone(&self.hooks),
            self.logger.clone(),
            self.after_queue.clone(),
            query,
        )
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        hooked_update_many(
            &self.inner,
            Arc::clone(&self.hooks),
            self.logger.clone(),
            self.after_queue.clone(),
            query,
        )
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        hooked_delete(
            &self.inner,
            Arc::clone(&self.hooks),
            self.logger.clone(),
            self.after_queue.clone(),
            query,
        )
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        hooked_delete_many(
            &self.inner,
            Arc::clone(&self.hooks),
            self.logger.clone(),
            self.after_queue.clone(),
            query,
        )
    }

    fn transaction<'a>(&'a self, callback: TransactionCallback<'a>) -> AdapterFuture<'a, ()> {
        Box::pin(async move {
            let should_run_after_hooks = self.after_queue.is_none();
            let after_queue = self.after_queue.clone().unwrap_or_default();
            let transaction_queue = after_queue.clone();
            let hooks = Arc::clone(&self.hooks);
            let logger = self.logger.clone();
            self.inner
                .transaction(Box::new(move |transaction| {
                    let adapter = HookedAdapter::with_after_queue(
                        transaction,
                        Arc::clone(&hooks),
                        logger.clone(),
                        transaction_queue,
                    );
                    callback(Box::new(adapter))
                }))
                .await?;
            if should_run_after_hooks {
                after_queue
                    .run(self.hooks.as_slice(), &self.logger, &self.inner)
                    .await?;
            }
            Ok(())
        })
    }

    fn create_schema<'a>(
        &'a self,
        schema: &'a DbSchema,
        file: Option<&'a str>,
    ) -> AdapterFuture<'a, Option<SchemaCreation>> {
        self.inner.create_schema(schema, file)
    }

    fn run_migrations<'a>(&'a self, schema: &'a DbSchema) -> AdapterFuture<'a, ()> {
        self.inner.run_migrations(schema)
    }
}
