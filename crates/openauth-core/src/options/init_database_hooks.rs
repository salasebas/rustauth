//! Init-time database hooks (parity with Better Auth `databaseHooks`).

use std::fmt;
use std::sync::Arc;

use crate::db::DbRecord;
use crate::error::OpenAuthError;
use crate::plugin::PluginDatabaseHookContext;

/// Action returned by an init-time database before hook.
#[derive(Debug, PartialEq)]
pub enum InitDatabaseBeforeAction {
    Continue,
    Cancel(OpenAuthError),
    Replace(DbRecord),
}

/// Runs before a core model create/update mutation.
pub trait InitDatabaseBeforeHook: Send + Sync + 'static {
    fn before(
        &self,
        context: &PluginDatabaseHookContext<'_>,
        record: &mut DbRecord,
    ) -> Result<InitDatabaseBeforeAction, OpenAuthError>;
}

impl<F> InitDatabaseBeforeHook for F
where
    F: Fn(
            &PluginDatabaseHookContext<'_>,
            &mut DbRecord,
        ) -> Result<InitDatabaseBeforeAction, OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn before(
        &self,
        context: &PluginDatabaseHookContext<'_>,
        record: &mut DbRecord,
    ) -> Result<InitDatabaseBeforeAction, OpenAuthError> {
        self(context, record)
    }
}

/// Runs after a core model create/update mutation.
pub trait InitDatabaseAfterHook: Send + Sync + 'static {
    fn after(
        &self,
        context: &PluginDatabaseHookContext<'_>,
        record: &DbRecord,
    ) -> Result<(), OpenAuthError>;
}

impl<F> InitDatabaseAfterHook for F
where
    F: Fn(&PluginDatabaseHookContext<'_>, &DbRecord) -> Result<(), OpenAuthError>
        + Send
        + Sync
        + 'static,
{
    fn after(
        &self,
        context: &PluginDatabaseHookContext<'_>,
        record: &DbRecord,
    ) -> Result<(), OpenAuthError> {
        self(context, record)
    }
}

/// Before/after hook pair for a single mutation kind.
#[derive(Clone, Default)]
pub struct DatabaseOperationHooks {
    pub before: Option<Arc<dyn InitDatabaseBeforeHook>>,
    pub after: Option<Arc<dyn InitDatabaseAfterHook>>,
}

impl fmt::Debug for DatabaseOperationHooks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseOperationHooks")
            .field(
                "before",
                &self.before.as_ref().map(|_| "<init-database-before>"),
            )
            .field(
                "after",
                &self.after.as_ref().map(|_| "<init-database-after>"),
            )
            .finish()
    }
}

impl DatabaseOperationHooks {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn before<H>(mut self, hook: H) -> Self
    where
        H: InitDatabaseBeforeHook,
    {
        self.before = Some(Arc::new(hook));
        self
    }

    #[must_use]
    pub fn after<H>(mut self, hook: H) -> Self
    where
        H: InitDatabaseAfterHook,
    {
        self.after = Some(Arc::new(hook));
        self
    }
}

/// Create/update hooks for one core model.
#[derive(Clone, Debug, Default)]
pub struct DatabaseModelHooks {
    pub create: DatabaseOperationHooks,
    pub update: DatabaseOperationHooks,
}

impl DatabaseModelHooks {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Structured init-time database hooks for core models.
#[derive(Clone, Debug, Default)]
pub struct InitDatabaseHooksOptions {
    pub user: DatabaseModelHooks,
    pub session: DatabaseModelHooks,
    pub account: DatabaseModelHooks,
    pub verification: DatabaseModelHooks,
}

impl InitDatabaseHooksOptions {
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn plugin_database_hooks_from_init(
    options: &InitDatabaseHooksOptions,
) -> Vec<crate::plugin::PluginDatabaseHook> {
    let mut hooks = Vec::new();
    append_model_hooks(&mut hooks, "user", &options.user);
    append_model_hooks(&mut hooks, "session", &options.session);
    append_model_hooks(&mut hooks, "account", &options.account);
    append_model_hooks(&mut hooks, "verification", &options.verification);
    hooks
}

fn append_model_hooks(
    hooks: &mut Vec<crate::plugin::PluginDatabaseHook>,
    model: &str,
    model_hooks: &DatabaseModelHooks,
) {
    if let Some(before) = model_hooks.create.before.clone() {
        append_create_before(hooks, model, before);
    }
    if let Some(after) = model_hooks.create.after.clone() {
        append_create_after(hooks, model, after);
    }
    if let Some(before) = model_hooks.update.before.clone() {
        append_update_before(hooks, model, before);
    }
    if let Some(after) = model_hooks.update.after.clone() {
        append_update_after(hooks, model, after);
    }
}

fn append_create_before(
    hooks: &mut Vec<crate::plugin::PluginDatabaseHook>,
    model: &str,
    hook: Arc<dyn InitDatabaseBeforeHook>,
) {
    use crate::plugin::{
        PluginDatabaseBeforeAction, PluginDatabaseBeforeInput, PluginDatabaseHook,
    };

    let model = model.to_owned();
    hooks.push(PluginDatabaseHook::before_create(
        format!("{model}-create-before"),
        move |context, query| {
            if query.model != model {
                return Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Create(query),
                ));
            }
            let mut query = query;
            match hook.before(context, &mut query.data)? {
                InitDatabaseBeforeAction::Continue => Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Create(query),
                )),
                InitDatabaseBeforeAction::Cancel(error) => {
                    Ok(PluginDatabaseBeforeAction::Cancel(error))
                }
                InitDatabaseBeforeAction::Replace(record) => {
                    query.data = record;
                    Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Create(query),
                    ))
                }
            }
        },
    ));
}

fn append_create_after(
    hooks: &mut Vec<crate::plugin::PluginDatabaseHook>,
    model: &str,
    hook: Arc<dyn InitDatabaseAfterHook>,
) {
    use crate::plugin::PluginDatabaseHook;

    let model = model.to_owned();
    hooks.push(PluginDatabaseHook::after_create(
        format!("{model}-create-after"),
        move |context, query, result| {
            if query.model != model {
                return Ok(());
            }
            hook.after(context, result)
        },
    ));
}

fn append_update_before(
    hooks: &mut Vec<crate::plugin::PluginDatabaseHook>,
    model: &str,
    hook: Arc<dyn InitDatabaseBeforeHook>,
) {
    use crate::plugin::{
        PluginDatabaseBeforeAction, PluginDatabaseBeforeInput, PluginDatabaseHook,
    };

    let model = model.to_owned();
    hooks.push(PluginDatabaseHook::before_update(
        format!("{model}-update-before"),
        move |context, query| {
            if query.model != model {
                return Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Update(query),
                ));
            }
            let mut query = query;
            match hook.before(context, &mut query.data)? {
                InitDatabaseBeforeAction::Continue => Ok(PluginDatabaseBeforeAction::Continue(
                    PluginDatabaseBeforeInput::Update(query),
                )),
                InitDatabaseBeforeAction::Cancel(error) => {
                    Ok(PluginDatabaseBeforeAction::Cancel(error))
                }
                InitDatabaseBeforeAction::Replace(record) => {
                    query.data = record;
                    Ok(PluginDatabaseBeforeAction::Continue(
                        PluginDatabaseBeforeInput::Update(query),
                    ))
                }
            }
        },
    ));
}

fn append_update_after(
    hooks: &mut Vec<crate::plugin::PluginDatabaseHook>,
    model: &str,
    hook: Arc<dyn InitDatabaseAfterHook>,
) {
    use crate::plugin::PluginDatabaseHook;

    let model = model.to_owned();
    hooks.push(PluginDatabaseHook::after_update(
        format!("{model}-update-after"),
        move |context, query, result| {
            if query.model != model {
                return Ok(());
            }
            if let Some(record) = result {
                hook.after(context, record)?;
            }
            Ok(())
        },
    ));
}
