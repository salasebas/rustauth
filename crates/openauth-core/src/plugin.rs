//! Plugin contracts for OpenAuth extensions.

mod db;
mod endpoint;
mod error;
mod hooks;
mod init;
mod rate_limit;
mod schema;

pub use db::{
    PluginDatabaseAfterHookHandler, PluginDatabaseAfterInput, PluginDatabaseBeforeAction,
    PluginDatabaseBeforeHookHandler, PluginDatabaseBeforeInput, PluginDatabaseHook,
    PluginDatabaseHookContext, PluginDatabaseOperation, PluginMigration,
};
pub use endpoint::PluginEndpoint;
pub use error::PluginErrorCode;
pub use hooks::{
    PluginAfterHook, PluginAfterHookAction, PluginAfterHookHandler, PluginBeforeHook,
    PluginBeforeHookAction, PluginBeforeHookHandler, PluginEndpointHooks, PluginHookMatcher,
};
pub use init::{PluginInitHandler, PluginInitOutput};
pub use rate_limit::PluginRateLimitRule;
pub use schema::PluginSchemaContribution;

use crate::api::AsyncAuthEndpoint;
use crate::context::AuthContext;
use crate::error::OpenAuthError;
use http::{Request, Response};
use serde_json::Value;
use std::fmt;
use std::sync::Arc;

pub type PluginBody = Vec<u8>;
pub type PluginRequest = Request<PluginBody>;
pub type PluginResponse = Response<PluginBody>;
pub type PluginOnRequest = Arc<
    dyn Fn(&AuthContext, PluginRequest) -> Result<PluginRequestAction, OpenAuthError> + Send + Sync,
>;
pub type PluginOnResponse = Arc<
    dyn Fn(&AuthContext, &PluginRequest, PluginResponse) -> Result<PluginResponse, OpenAuthError>
        + Send
        + Sync,
>;
pub type PluginMiddlewareHandler = Arc<
    dyn Fn(&AuthContext, &PluginRequest) -> Result<Option<PluginResponse>, OpenAuthError>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct AuthPlugin {
    pub id: String,
    pub version: Option<String>,
    pub options: Option<Value>,
    pub endpoints: Vec<AsyncAuthEndpoint>,
    pub middlewares: Vec<PluginMiddleware>,
    pub on_request: Option<PluginOnRequest>,
    pub on_response: Option<PluginOnResponse>,
    pub init: Option<PluginInitHandler>,
    pub schema: Vec<PluginSchemaContribution>,
    pub rate_limit: Vec<PluginRateLimitRule>,
    pub hooks: PluginEndpointHooks,
    pub error_codes: Vec<PluginErrorCode>,
    pub database_hooks: Vec<PluginDatabaseHook>,
    pub migrations: Vec<PluginMigration>,
}

impl AuthPlugin {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: None,
            options: None,
            endpoints: Vec::new(),
            middlewares: Vec::new(),
            on_request: None,
            on_response: None,
            init: None,
            schema: Vec::new(),
            rate_limit: Vec::new(),
            hooks: PluginEndpointHooks::default(),
            error_codes: Vec::new(),
            database_hooks: Vec::new(),
            migrations: Vec::new(),
        }
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_options(mut self, options: Value) -> Self {
        self.options = Some(options);
        self
    }

    pub fn with_endpoint(mut self, endpoint: AsyncAuthEndpoint) -> Self {
        self.endpoints.push(endpoint);
        self
    }

    pub fn with_init<F>(mut self, init: F) -> Self
    where
        F: Fn(&AuthContext) -> Result<PluginInitOutput, OpenAuthError> + Send + Sync + 'static,
    {
        self.init = Some(Arc::new(init));
        self
    }

    pub fn with_schema(mut self, contribution: PluginSchemaContribution) -> Self {
        self.schema.push(contribution);
        self
    }

    pub fn with_rate_limit(mut self, rule: PluginRateLimitRule) -> Self {
        self.rate_limit.push(rule);
        self
    }

    pub fn with_before_hook<F>(mut self, path: impl Into<String>, hook: F) -> Self
    where
        F: Fn(&AuthContext, PluginRequest) -> Result<PluginBeforeHookAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        self.hooks.before.push(PluginBeforeHook {
            matcher: PluginHookMatcher::path(path),
            handler: Arc::new(hook),
        });
        self
    }

    pub fn with_after_hook<F>(mut self, path: impl Into<String>, hook: F) -> Self
    where
        F: Fn(
                &AuthContext,
                &PluginRequest,
                PluginResponse,
            ) -> Result<PluginAfterHookAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        self.hooks.after.push(PluginAfterHook {
            matcher: PluginHookMatcher::path(path),
            handler: Arc::new(hook),
        });
        self
    }

    pub fn with_error_code(mut self, error_code: PluginErrorCode) -> Self {
        self.error_codes.push(error_code);
        self
    }

    pub fn with_database_hook(mut self, hook: PluginDatabaseHook) -> Self {
        self.database_hooks.push(hook);
        self
    }

    pub fn with_migration(mut self, migration: PluginMigration) -> Self {
        self.migrations.push(migration);
        self
    }

    pub fn with_middleware<F>(mut self, path: impl Into<String>, middleware: F) -> Self
    where
        F: Fn(&AuthContext, &PluginRequest) -> Result<Option<PluginResponse>, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        self.middlewares.push(PluginMiddleware {
            path: path.into(),
            handler: Arc::new(middleware),
        });
        self
    }

    pub fn with_on_request<F>(mut self, hook: F) -> Self
    where
        F: Fn(&AuthContext, PluginRequest) -> Result<PluginRequestAction, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        self.on_request = Some(Arc::new(hook));
        self
    }

    pub fn with_on_response<F>(mut self, hook: F) -> Self
    where
        F: Fn(
                &AuthContext,
                &PluginRequest,
                PluginResponse,
            ) -> Result<PluginResponse, OpenAuthError>
            + Send
            + Sync
            + 'static,
    {
        self.on_response = Some(Arc::new(hook));
        self
    }
}

impl fmt::Debug for AuthPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthPlugin")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("options", &self.options)
            .field("endpoints", &self.endpoints.len())
            .field("middlewares", &self.middlewares)
            .field("on_request", &self.on_request.as_ref().map(|_| "<hook>"))
            .field("on_response", &self.on_response.as_ref().map(|_| "<hook>"))
            .field("init", &self.init.as_ref().map(|_| "<init>"))
            .field("schema", &self.schema)
            .field("rate_limit", &self.rate_limit)
            .field("hooks", &self.hooks)
            .field("error_codes", &self.error_codes)
            .field("database_hooks", &self.database_hooks)
            .field("migrations", &self.migrations)
            .finish()
    }
}

#[derive(Clone)]
pub struct PluginMiddleware {
    pub path: String,
    pub handler: PluginMiddlewareHandler,
}

impl fmt::Debug for PluginMiddleware {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginMiddleware")
            .field("path", &self.path)
            .field("handler", &"<middleware>")
            .finish()
    }
}

pub enum PluginRequestAction {
    Continue(PluginRequest),
    Respond(PluginResponse),
}
