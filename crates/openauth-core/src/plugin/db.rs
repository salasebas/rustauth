//! Database plugin hooks and migration metadata.

use std::fmt;
use std::sync::Arc;

use crate::db::{Create, DbRecord, Delete, DeleteMany, Update, UpdateMany};
use crate::error::OpenAuthError;

/// Mutating database operations that can be observed by plugins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginDatabaseOperation {
    Create,
    Update,
    UpdateMany,
    Delete,
    DeleteMany,
}

/// Query passed to a database hook before the adapter operation runs.
#[derive(Debug, Clone, PartialEq)]
pub enum PluginDatabaseBeforeInput {
    Create(Create),
    Update(Update),
    UpdateMany(UpdateMany),
    Delete {
        query: Delete,
        snapshots: Vec<DbRecord>,
    },
    DeleteMany {
        query: DeleteMany,
        snapshots: Vec<DbRecord>,
    },
}

impl PluginDatabaseBeforeInput {
    pub fn operation(&self) -> PluginDatabaseOperation {
        match self {
            Self::Create(_) => PluginDatabaseOperation::Create,
            Self::Update(_) => PluginDatabaseOperation::Update,
            Self::UpdateMany(_) => PluginDatabaseOperation::UpdateMany,
            Self::Delete { .. } => PluginDatabaseOperation::Delete,
            Self::DeleteMany { .. } => PluginDatabaseOperation::DeleteMany,
        }
    }

    pub fn model(&self) -> &str {
        match self {
            Self::Create(query) => &query.model,
            Self::Update(query) => &query.model,
            Self::UpdateMany(query) => &query.model,
            Self::Delete { query, .. } => &query.model,
            Self::DeleteMany { query, .. } => &query.model,
        }
    }
}

/// Action returned by a before hook.
#[derive(Debug, PartialEq)]
pub enum PluginDatabaseBeforeAction {
    Continue(PluginDatabaseBeforeInput),
    Cancel(OpenAuthError),
}

/// Query and adapter result passed to a database hook after the operation runs.
#[derive(Debug, Clone, PartialEq)]
pub enum PluginDatabaseAfterInput {
    Create {
        query: Create,
        result: DbRecord,
    },
    Update {
        query: Update,
        result: Option<DbRecord>,
    },
    UpdateMany {
        query: UpdateMany,
        result: u64,
    },
    Delete {
        query: Delete,
        snapshots: Vec<DbRecord>,
    },
    DeleteMany {
        query: DeleteMany,
        snapshots: Vec<DbRecord>,
        result: u64,
    },
}

impl PluginDatabaseAfterInput {
    pub fn operation(&self) -> PluginDatabaseOperation {
        match self {
            Self::Create { .. } => PluginDatabaseOperation::Create,
            Self::Update { .. } => PluginDatabaseOperation::Update,
            Self::UpdateMany { .. } => PluginDatabaseOperation::UpdateMany,
            Self::Delete { .. } => PluginDatabaseOperation::Delete,
            Self::DeleteMany { .. } => PluginDatabaseOperation::DeleteMany,
        }
    }

    pub fn model(&self) -> &str {
        match self {
            Self::Create { query, .. } => &query.model,
            Self::Update { query, .. } => &query.model,
            Self::UpdateMany { query, .. } => &query.model,
            Self::Delete { query, .. } => &query.model,
            Self::DeleteMany { query, .. } => &query.model,
        }
    }
}

/// Runtime metadata passed to executable database hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginDatabaseHookContext {
    pub plugin_id: String,
    pub hook_name: String,
    pub operation: PluginDatabaseOperation,
    pub model: String,
}

pub type PluginDatabaseBeforeHookHandler = Arc<
    dyn Fn(
            &PluginDatabaseHookContext,
            PluginDatabaseBeforeInput,
        ) -> Result<PluginDatabaseBeforeAction, OpenAuthError>
        + Send
        + Sync,
>;

pub type PluginDatabaseAfterHookHandler = Arc<
    dyn Fn(&PluginDatabaseHookContext, &PluginDatabaseAfterInput) -> Result<(), OpenAuthError>
        + Send
        + Sync,
>;

/// Executable database hook registered by a plugin.
#[derive(Clone)]
pub struct PluginDatabaseHook {
    pub name: String,
    pub operation: PluginDatabaseOperation,
    pub before: Option<PluginDatabaseBeforeHookHandler>,
    pub after: Option<PluginDatabaseAfterHookHandler>,
    plugin_id: Option<String>,
}

impl PluginDatabaseHook {
    pub fn before<F>(
        name: impl Into<String>,
        operation: PluginDatabaseOperation,
        handler: F,
    ) -> Self
    where
        F: Fn(
                &PluginDatabaseHookContext,
                PluginDatabaseBeforeInput,
            ) -> Result<PluginDatabaseBeforeAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            name: name.into(),
            operation,
            before: Some(Arc::new(handler)),
            after: None,
            plugin_id: None,
        }
    }

    pub fn after<F>(name: impl Into<String>, operation: PluginDatabaseOperation, handler: F) -> Self
    where
        F: Fn(&PluginDatabaseHookContext, &PluginDatabaseAfterInput) -> Result<(), OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            name: name.into(),
            operation,
            before: None,
            after: Some(Arc::new(handler)),
            plugin_id: None,
        }
    }

    pub fn before_create<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(
                &PluginDatabaseHookContext,
                Create,
            ) -> Result<PluginDatabaseBeforeAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::before(
            name,
            PluginDatabaseOperation::Create,
            move |context, input| match input {
                PluginDatabaseBeforeInput::Create(query) => handler(context, query),
                other => mismatched_before_input(PluginDatabaseOperation::Create, other),
            },
        )
    }

    pub fn before_update<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(
                &PluginDatabaseHookContext,
                Update,
            ) -> Result<PluginDatabaseBeforeAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::before(
            name,
            PluginDatabaseOperation::Update,
            move |context, input| match input {
                PluginDatabaseBeforeInput::Update(query) => handler(context, query),
                other => mismatched_before_input(PluginDatabaseOperation::Update, other),
            },
        )
    }

    pub fn before_update_many<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(
                &PluginDatabaseHookContext,
                UpdateMany,
            ) -> Result<PluginDatabaseBeforeAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::before(
            name,
            PluginDatabaseOperation::UpdateMany,
            move |context, input| match input {
                PluginDatabaseBeforeInput::UpdateMany(query) => handler(context, query),
                other => mismatched_before_input(PluginDatabaseOperation::UpdateMany, other),
            },
        )
    }

    pub fn before_delete<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(
                &PluginDatabaseHookContext,
                Delete,
                Vec<DbRecord>,
            ) -> Result<PluginDatabaseBeforeAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::before(
            name,
            PluginDatabaseOperation::Delete,
            move |context, input| match input {
                PluginDatabaseBeforeInput::Delete { query, snapshots } => {
                    handler(context, query, snapshots)
                }
                other => mismatched_before_input(PluginDatabaseOperation::Delete, other),
            },
        )
    }

    pub fn before_delete_many<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(
                &PluginDatabaseHookContext,
                DeleteMany,
                Vec<DbRecord>,
            ) -> Result<PluginDatabaseBeforeAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::before(
            name,
            PluginDatabaseOperation::DeleteMany,
            move |context, input| match input {
                PluginDatabaseBeforeInput::DeleteMany { query, snapshots } => {
                    handler(context, query, snapshots)
                }
                other => mismatched_before_input(PluginDatabaseOperation::DeleteMany, other),
            },
        )
    }

    pub fn after_create<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(&PluginDatabaseHookContext, &Create, &DbRecord) -> Result<(), OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::after(
            name,
            PluginDatabaseOperation::Create,
            move |context, input| match input {
                PluginDatabaseAfterInput::Create { query, result } => {
                    handler(context, query, result)
                }
                other => mismatched_after_input(PluginDatabaseOperation::Create, other),
            },
        )
    }

    pub fn after_update<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(&PluginDatabaseHookContext, &Update, &Option<DbRecord>) -> Result<(), OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::after(
            name,
            PluginDatabaseOperation::Update,
            move |context, input| match input {
                PluginDatabaseAfterInput::Update { query, result } => {
                    handler(context, query, result)
                }
                other => mismatched_after_input(PluginDatabaseOperation::Update, other),
            },
        )
    }

    pub fn after_update_many<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(&PluginDatabaseHookContext, &UpdateMany, u64) -> Result<(), OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::after(
            name,
            PluginDatabaseOperation::UpdateMany,
            move |context, input| match input {
                PluginDatabaseAfterInput::UpdateMany { query, result } => {
                    handler(context, query, *result)
                }
                other => mismatched_after_input(PluginDatabaseOperation::UpdateMany, other),
            },
        )
    }

    pub fn after_delete<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(&PluginDatabaseHookContext, &Delete, &[DbRecord]) -> Result<(), OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::after(
            name,
            PluginDatabaseOperation::Delete,
            move |context, input| match input {
                PluginDatabaseAfterInput::Delete { query, snapshots } => {
                    handler(context, query, snapshots)
                }
                other => mismatched_after_input(PluginDatabaseOperation::Delete, other),
            },
        )
    }

    pub fn after_delete_many<F>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(
                &PluginDatabaseHookContext,
                &DeleteMany,
                &[DbRecord],
                u64,
            ) -> Result<(), OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        Self::after(
            name,
            PluginDatabaseOperation::DeleteMany,
            move |context, input| match input {
                PluginDatabaseAfterInput::DeleteMany {
                    query,
                    snapshots,
                    result,
                } => handler(context, query, snapshots, *result),
                other => mismatched_after_input(PluginDatabaseOperation::DeleteMany, other),
            },
        )
    }

    pub fn plugin_id(&self) -> Option<&str> {
        self.plugin_id.as_deref()
    }

    pub fn with_plugin_id(mut self, plugin_id: impl Into<String>) -> Self {
        self.plugin_id = Some(plugin_id.into());
        self
    }

    pub fn has_overlapping_phase(&self, other: &Self) -> bool {
        self.name == other.name
            && self.operation == other.operation
            && ((self.before.is_some() && other.before.is_some())
                || (self.after.is_some() && other.after.is_some()))
    }
}

impl fmt::Debug for PluginDatabaseHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginDatabaseHook")
            .field("name", &self.name)
            .field("operation", &self.operation)
            .field("before", &self.before.as_ref().map(|_| "<before>"))
            .field("after", &self.after.as_ref().map(|_| "<after>"))
            .field("plugin_id", &self.plugin_id)
            .finish()
    }
}

fn mismatched_before_input(
    expected: PluginDatabaseOperation,
    actual: PluginDatabaseBeforeInput,
) -> Result<PluginDatabaseBeforeAction, OpenAuthError> {
    Err(OpenAuthError::InvalidConfig(format!(
        "database before hook expected {expected:?} input but received {:?}",
        actual.operation()
    )))
}

fn mismatched_after_input(
    expected: PluginDatabaseOperation,
    actual: &PluginDatabaseAfterInput,
) -> Result<(), OpenAuthError> {
    Err(OpenAuthError::InvalidConfig(format!(
        "database after hook expected {expected:?} input but received {:?}",
        actual.operation()
    )))
}

/// Plugin migration metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMigration {
    pub name: String,
}

impl PluginMigration {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}
