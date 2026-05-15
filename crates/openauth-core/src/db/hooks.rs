//! Database adapter wrapper that executes plugin hooks around mutations.

use std::sync::{Arc, Mutex};

use super::{
    AdapterCapabilities, AdapterFuture, Count, Create, DbAdapter, DbRecord, Delete, DeleteMany,
    FindMany, FindOne, SchemaCreation, TransactionCallback, Update, UpdateMany,
};
use crate::context::request_state::current_request_path;
use crate::db::DbSchema;
use crate::error::OpenAuthError;
use crate::plugin::{
    PluginDatabaseAfterInput, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
    PluginDatabaseHook, PluginDatabaseHookContext, PluginDatabaseOperation,
};

/// Adapter wrapper that runs plugin database hooks for mutating operations.
#[derive(Clone)]
pub struct HookedAdapter<A = Arc<dyn DbAdapter>> {
    inner: A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    after_queue: Option<AfterHookQueue>,
}

impl<A> HookedAdapter<A> {
    pub fn new(inner: A, hooks: Vec<PluginDatabaseHook>) -> Self {
        Self {
            inner,
            hooks: Arc::new(hooks),
            after_queue: None,
        }
    }

    pub fn hooks(&self) -> &[PluginDatabaseHook] {
        self.hooks.as_slice()
    }

    fn with_after_queue(
        inner: A,
        hooks: Arc<Vec<PluginDatabaseHook>>,
        after_queue: AfterHookQueue,
    ) -> Self {
        Self {
            inner,
            hooks,
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
            self.after_queue.clone(),
            query,
        )
    }

    fn update_many<'a>(&'a self, query: UpdateMany) -> AdapterFuture<'a, u64> {
        hooked_update_many(
            &self.inner,
            Arc::clone(&self.hooks),
            self.after_queue.clone(),
            query,
        )
    }

    fn delete<'a>(&'a self, query: Delete) -> AdapterFuture<'a, ()> {
        hooked_delete(
            &self.inner,
            Arc::clone(&self.hooks),
            self.after_queue.clone(),
            query,
        )
    }

    fn delete_many<'a>(&'a self, query: DeleteMany) -> AdapterFuture<'a, u64> {
        hooked_delete_many(
            &self.inner,
            Arc::clone(&self.hooks),
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
            self.inner
                .transaction(Box::new(move |transaction| {
                    let adapter = HookedAdapter::with_after_queue(
                        transaction,
                        Arc::clone(&hooks),
                        transaction_queue,
                    );
                    callback(Box::new(adapter))
                }))
                .await?;
            if should_run_after_hooks {
                after_queue.run(self.hooks.as_slice(), &self.inner).await?;
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

#[derive(Clone, Default)]
struct AfterHookQueue {
    inputs: Arc<Mutex<Vec<PluginDatabaseAfterInput>>>,
}

impl AfterHookQueue {
    fn push(&self, input: PluginDatabaseAfterInput) -> Result<(), OpenAuthError> {
        self.inputs
            .lock()
            .map_err(|_| OpenAuthError::Adapter("after hook queue lock poisoned".to_owned()))?
            .push(input);
        Ok(())
    }

    async fn run<A>(&self, hooks: &[PluginDatabaseHook], adapter: &A) -> Result<(), OpenAuthError>
    where
        A: DbAdapter,
    {
        let inputs = {
            let mut guard = self
                .inputs
                .lock()
                .map_err(|_| OpenAuthError::Adapter("after hook queue lock poisoned".to_owned()))?;
            std::mem::take(&mut *guard)
        };
        for input in inputs {
            run_after_hooks(hooks, input, adapter).await?;
        }
        Ok(())
    }
}

fn hooked_create<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    after_queue: Option<AfterHookQueue>,
    query: Create,
) -> AdapterFuture<'a, DbRecord>
where
    A: DbAdapter,
{
    Box::pin(async move {
        let query = match run_before_hooks(
            hooks.as_slice(),
            PluginDatabaseBeforeInput::Create(query),
            inner,
        )
        .await?
        {
            PluginDatabaseBeforeInput::Create(query) => query,
            other => {
                return Err(mismatched_continue_input(
                    PluginDatabaseOperation::Create,
                    other,
                ))
            }
        };
        let result = inner.create(query.clone()).await?;
        run_or_queue_after_hooks(
            after_queue.as_ref(),
            hooks.as_slice(),
            PluginDatabaseAfterInput::Create {
                query,
                result: result.clone(),
            },
            inner,
        )
        .await?;
        Ok(result)
    })
}

fn hooked_update<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    after_queue: Option<AfterHookQueue>,
    query: Update,
) -> AdapterFuture<'a, Option<DbRecord>>
where
    A: DbAdapter,
{
    Box::pin(async move {
        let query = match run_before_hooks(
            hooks.as_slice(),
            PluginDatabaseBeforeInput::Update(query),
            inner,
        )
        .await?
        {
            PluginDatabaseBeforeInput::Update(query) => query,
            other => {
                return Err(mismatched_continue_input(
                    PluginDatabaseOperation::Update,
                    other,
                ))
            }
        };
        let result = inner.update(query.clone()).await?;
        run_or_queue_after_hooks(
            after_queue.as_ref(),
            hooks.as_slice(),
            PluginDatabaseAfterInput::Update {
                query,
                result: result.clone(),
            },
            inner,
        )
        .await?;
        Ok(result)
    })
}

fn hooked_update_many<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    after_queue: Option<AfterHookQueue>,
    query: UpdateMany,
) -> AdapterFuture<'a, u64>
where
    A: DbAdapter,
{
    Box::pin(async move {
        let query = match run_before_hooks(
            hooks.as_slice(),
            PluginDatabaseBeforeInput::UpdateMany(query),
            inner,
        )
        .await?
        {
            PluginDatabaseBeforeInput::UpdateMany(query) => query,
            other => {
                return Err(mismatched_continue_input(
                    PluginDatabaseOperation::UpdateMany,
                    other,
                ));
            }
        };
        let result = inner.update_many(query.clone()).await?;
        run_or_queue_after_hooks(
            after_queue.as_ref(),
            hooks.as_slice(),
            PluginDatabaseAfterInput::UpdateMany { query, result },
            inner,
        )
        .await?;
        Ok(result)
    })
}

fn hooked_delete<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    after_queue: Option<AfterHookQueue>,
    query: Delete,
) -> AdapterFuture<'a, ()>
where
    A: DbAdapter,
{
    Box::pin(async move {
        let snapshots = load_delete_snapshots(
            inner,
            query.model.clone(),
            query.where_clauses.clone(),
            Some(1),
        )
        .await;
        let (query, snapshots) = match run_before_hooks(
            hooks.as_slice(),
            PluginDatabaseBeforeInput::Delete { query, snapshots },
            inner,
        )
        .await?
        {
            PluginDatabaseBeforeInput::Delete { query, snapshots } => (query, snapshots),
            other => {
                return Err(mismatched_continue_input(
                    PluginDatabaseOperation::Delete,
                    other,
                ))
            }
        };
        inner.delete(query.clone()).await?;
        run_or_queue_after_hooks(
            after_queue.as_ref(),
            hooks.as_slice(),
            PluginDatabaseAfterInput::Delete { query, snapshots },
            inner,
        )
        .await?;
        Ok(())
    })
}

fn hooked_delete_many<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    after_queue: Option<AfterHookQueue>,
    query: DeleteMany,
) -> AdapterFuture<'a, u64>
where
    A: DbAdapter,
{
    Box::pin(async move {
        let snapshots = load_delete_snapshots(
            inner,
            query.model.clone(),
            query.where_clauses.clone(),
            None,
        )
        .await;
        let (query, snapshots) = match run_before_hooks(
            hooks.as_slice(),
            PluginDatabaseBeforeInput::DeleteMany { query, snapshots },
            inner,
        )
        .await?
        {
            PluginDatabaseBeforeInput::DeleteMany { query, snapshots } => (query, snapshots),
            other => {
                return Err(mismatched_continue_input(
                    PluginDatabaseOperation::DeleteMany,
                    other,
                ));
            }
        };
        let result = inner.delete_many(query.clone()).await?;
        run_or_queue_after_hooks(
            after_queue.as_ref(),
            hooks.as_slice(),
            PluginDatabaseAfterInput::DeleteMany {
                query,
                snapshots,
                result,
            },
            inner,
        )
        .await?;
        Ok(result)
    })
}

async fn load_delete_snapshots<A>(
    inner: &A,
    model: String,
    where_clauses: Vec<super::Where>,
    limit: Option<usize>,
) -> Vec<DbRecord>
where
    A: DbAdapter,
{
    let mut query = FindMany::new(model);
    query.where_clauses = where_clauses;
    query.limit = limit;
    inner.find_many(query).await.unwrap_or_default()
}

async fn run_before_hooks<A>(
    hooks: &[PluginDatabaseHook],
    mut input: PluginDatabaseBeforeInput,
    adapter: &A,
) -> Result<PluginDatabaseBeforeInput, OpenAuthError>
where
    A: DbAdapter,
{
    let operation = input.operation();
    for hook in hooks.iter().filter(|hook| hook.operation == operation) {
        let Some(handler) = &hook.before else {
            continue;
        };
        let model = input.model().to_owned();
        let context = hook_context(hook, operation, &model, adapter);
        input = match handler(context, input).await? {
            PluginDatabaseBeforeAction::Continue(next) => next,
            PluginDatabaseBeforeAction::Cancel(error) => return Err(error),
        };
        if input.operation() != operation {
            return Err(mismatched_continue_input(operation, input));
        }
    }
    Ok(input)
}

async fn run_after_hooks<A>(
    hooks: &[PluginDatabaseHook],
    input: PluginDatabaseAfterInput,
    adapter: &A,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter,
{
    let operation = input.operation();
    for hook in hooks.iter().filter(|hook| hook.operation == operation) {
        let Some(handler) = &hook.after else {
            continue;
        };
        let context = hook_context(hook, operation, input.model(), adapter);
        handler(context, input.clone()).await?;
    }
    Ok(())
}

async fn run_or_queue_after_hooks<A>(
    queue: Option<&AfterHookQueue>,
    hooks: &[PluginDatabaseHook],
    input: PluginDatabaseAfterInput,
    adapter: &A,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter,
{
    if let Some(queue) = queue {
        queue.push(input)
    } else {
        run_after_hooks(hooks, input, adapter).await
    }
}

fn hook_context<'a, A>(
    hook: &PluginDatabaseHook,
    operation: PluginDatabaseOperation,
    model: &str,
    adapter: &'a A,
) -> PluginDatabaseHookContext<'a>
where
    A: DbAdapter + 'a,
{
    PluginDatabaseHookContext {
        plugin_id: hook.plugin_id().unwrap_or_default().to_owned(),
        hook_name: hook.name.clone(),
        operation,
        model: model.to_owned(),
        adapter,
        request_path: current_request_path().ok().flatten(),
    }
}

fn mismatched_continue_input(
    expected: PluginDatabaseOperation,
    actual: PluginDatabaseBeforeInput,
) -> OpenAuthError {
    OpenAuthError::InvalidConfig(format!(
        "database before hook for {expected:?} returned {:?} input",
        actual.operation()
    ))
}
