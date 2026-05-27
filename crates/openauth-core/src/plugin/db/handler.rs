use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::db::DbAdapter;
use crate::env::logger::Logger;
use crate::error::OpenAuthError;
use crate::plugin::{
    PluginDatabaseAfterInput, PluginDatabaseBeforeAction, PluginDatabaseBeforeInput,
};

use super::PluginDatabaseOperation;

/// Runtime metadata passed to executable database hooks.
pub struct PluginDatabaseHookContext<'a> {
    pub plugin_id: String,
    pub hook_name: String,
    pub operation: PluginDatabaseOperation,
    pub model: String,
    pub adapter: &'a dyn DbAdapter,
    pub request_path: Option<String>,
    /// Application logger (same instance as [`crate::context::AuthContext::logger`]).
    pub logger: &'a Logger,
}

impl fmt::Debug for PluginDatabaseHookContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginDatabaseHookContext")
            .field("plugin_id", &self.plugin_id)
            .field("hook_name", &self.hook_name)
            .field("operation", &self.operation)
            .field("model", &self.model)
            .field("adapter", &self.adapter.id())
            .field("request_path", &self.request_path)
            .finish()
    }
}

pub type PluginDatabaseBeforeHookFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PluginDatabaseBeforeAction, OpenAuthError>> + Send + 'a>>;
pub type PluginDatabaseAfterHookFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), OpenAuthError>> + Send + 'a>>;

pub type PluginDatabaseBeforeHookHandler = Arc<
    dyn for<'a> Fn(
            PluginDatabaseHookContext<'a>,
            PluginDatabaseBeforeInput,
        ) -> PluginDatabaseBeforeHookFuture<'a>
        + Send
        + Sync,
>;

pub type PluginDatabaseAfterHookHandler = Arc<
    dyn for<'a> Fn(
            PluginDatabaseHookContext<'a>,
            PluginDatabaseAfterInput,
        ) -> PluginDatabaseAfterHookFuture<'a>
        + Send
        + Sync,
>;
