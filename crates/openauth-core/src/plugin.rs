//! Plugin contracts for OpenAuth extensions.

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
    pub middlewares: Vec<PluginMiddleware>,
    pub on_request: Option<PluginOnRequest>,
    pub on_response: Option<PluginOnResponse>,
}

impl AuthPlugin {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: None,
            options: None,
            middlewares: Vec::new(),
            on_request: None,
            on_response: None,
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
            .field("middlewares", &self.middlewares)
            .field("on_request", &self.on_request.as_ref().map(|_| "<hook>"))
            .field("on_response", &self.on_response.as_ref().map(|_| "<hook>"))
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
