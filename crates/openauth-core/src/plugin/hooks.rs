//! Endpoint-scoped plugin hooks.

use crate::api::{ApiRequest, ApiResponse};
use crate::context::AuthContext;
use crate::error::OpenAuthError;
use http::Method;
use std::fmt;
use std::sync::Arc;

pub type PluginBeforeHookHandler = Arc<
    dyn Fn(&AuthContext, ApiRequest) -> Result<PluginBeforeHookAction, OpenAuthError> + Send + Sync,
>;
pub type PluginAfterHookHandler = Arc<
    dyn Fn(&AuthContext, &ApiRequest, ApiResponse) -> Result<PluginAfterHookAction, OpenAuthError>
        + Send
        + Sync,
>;

/// Action returned by a before endpoint hook.
pub enum PluginBeforeHookAction {
    Continue(ApiRequest),
    Respond(ApiResponse),
}

/// Action returned by an after endpoint hook.
pub enum PluginAfterHookAction {
    Continue(ApiResponse),
}

/// Matcher used to select endpoint hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHookMatcher {
    pub path: String,
    pub method: Option<Method>,
    pub operation_id: Option<String>,
}

impl PluginHookMatcher {
    pub fn path(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            method: None,
            operation_id: None,
        }
    }

    #[must_use]
    pub fn method(mut self, method: Method) -> Self {
        self.method = Some(method);
        self
    }

    #[must_use]
    pub fn operation_id(mut self, operation_id: impl Into<String>) -> Self {
        self.operation_id = Some(operation_id.into());
        self
    }

    pub fn matches(&self, method: &Method, path: &str, operation_id: Option<&str>) -> bool {
        if self
            .method
            .as_ref()
            .is_some_and(|expected| expected != method)
        {
            return false;
        }
        if self
            .operation_id
            .as_deref()
            .is_some_and(|expected| Some(expected) != operation_id)
        {
            return false;
        }
        path_matches(&self.path, path)
    }
}

#[derive(Clone)]
pub struct PluginBeforeHook {
    pub matcher: PluginHookMatcher,
    pub handler: PluginBeforeHookHandler,
}

impl fmt::Debug for PluginBeforeHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginBeforeHook")
            .field("matcher", &self.matcher)
            .field("handler", &"<before-hook>")
            .finish()
    }
}

#[derive(Clone)]
pub struct PluginAfterHook {
    pub matcher: PluginHookMatcher,
    pub handler: PluginAfterHookHandler,
}

impl fmt::Debug for PluginAfterHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginAfterHook")
            .field("matcher", &self.matcher)
            .field("handler", &"<after-hook>")
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PluginEndpointHooks {
    pub before: Vec<PluginBeforeHook>,
    pub after: Vec<PluginAfterHook>,
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if let Some((prefix, suffix)) = pattern.split_once('*') {
        return path.starts_with(prefix) && path.ends_with(suffix);
    }
    pattern == path
}
