use std::sync::{Arc, Mutex};

use super::super::{
    AdapterFuture, Create, DbAdapter, DbRecord, Delete, DeleteMany, FindMany, Update, UpdateMany,
};
use crate::context::request_state::current_request_path;
use crate::env::logger::Logger;
use crate::error::OpenAuthError;
use crate::plugin::{
    PluginDatabaseAfterInput, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
    PluginDatabaseHook, PluginDatabaseHookContext, PluginDatabaseOperation,
};

#[derive(Clone, Default)]
pub(super) struct AfterHookQueue {
    inputs: Arc<Mutex<Vec<PluginDatabaseAfterInput>>>,
}

impl AfterHookQueue {
    fn push(&self, input: PluginDatabaseAfterInput) -> Result<(), OpenAuthError> {
        self.inputs
            .lock()
            .map_err(|_| OpenAuthError::LockPoisoned {
                context: "after hook queue",
            })?
            .push(input);
        Ok(())
    }

    pub(super) async fn run<A>(
        &self,
        hooks: &[PluginDatabaseHook],
        logger: &Logger,
        adapter: &A,
    ) -> Result<(), OpenAuthError>
    where
        A: DbAdapter,
    {
        let inputs = {
            let mut guard = self
                .inputs
                .lock()
                .map_err(|_| OpenAuthError::LockPoisoned {
                    context: "after hook queue",
                })?;
            std::mem::take(&mut *guard)
        };
        for input in inputs {
            run_after_hooks(hooks, input, logger, adapter).await?;
        }
        Ok(())
    }
}

pub(super) fn hooked_create<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    logger: Logger,
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
            &logger,
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
            &logger,
            inner,
        )
        .await?;
        Ok(result)
    })
}

pub(super) fn hooked_update<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    logger: Logger,
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
            &logger,
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
            &logger,
            inner,
        )
        .await?;
        Ok(result)
    })
}

pub(super) fn hooked_update_many<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    logger: Logger,
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
            &logger,
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
            &logger,
            inner,
        )
        .await?;
        Ok(result)
    })
}

pub(super) fn hooked_delete<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    logger: Logger,
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
        .await?;
        let (query, snapshots) = match run_before_hooks(
            hooks.as_slice(),
            PluginDatabaseBeforeInput::Delete { query, snapshots },
            &logger,
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
            &logger,
            inner,
        )
        .await?;
        Ok(())
    })
}

pub(super) fn hooked_delete_many<'a, A>(
    inner: &'a A,
    hooks: Arc<Vec<PluginDatabaseHook>>,
    logger: Logger,
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
        .await?;
        let (query, snapshots) = match run_before_hooks(
            hooks.as_slice(),
            PluginDatabaseBeforeInput::DeleteMany { query, snapshots },
            &logger,
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
            &logger,
            inner,
        )
        .await?;
        Ok(result)
    })
}

async fn load_delete_snapshots<A>(
    inner: &A,
    model: String,
    where_clauses: Vec<super::super::Where>,
    limit: Option<usize>,
) -> Result<Vec<DbRecord>, OpenAuthError>
where
    A: DbAdapter,
{
    let mut query = FindMany::new(model);
    query.where_clauses = where_clauses;
    query.limit = limit;
    inner.find_many(query).await
}

async fn run_before_hooks<A>(
    hooks: &[PluginDatabaseHook],
    mut input: PluginDatabaseBeforeInput,
    logger: &Logger,
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
        let context = hook_context(hook, operation, &model, logger, adapter);
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
    logger: &Logger,
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
        let context = hook_context(hook, operation, input.model(), logger, adapter);
        handler(context, input.clone()).await?;
    }
    Ok(())
}

async fn run_or_queue_after_hooks<A>(
    queue: Option<&AfterHookQueue>,
    hooks: &[PluginDatabaseHook],
    input: PluginDatabaseAfterInput,
    logger: &Logger,
    adapter: &A,
) -> Result<(), OpenAuthError>
where
    A: DbAdapter,
{
    if let Some(queue) = queue {
        queue.push(input)
    } else {
        run_after_hooks(hooks, input, logger, adapter).await
    }
}

fn hook_context<'a, A>(
    hook: &PluginDatabaseHook,
    operation: PluginDatabaseOperation,
    model: &str,
    logger: &'a Logger,
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
        logger,
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
