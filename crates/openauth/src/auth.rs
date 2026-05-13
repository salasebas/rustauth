//! Public OpenAuth initializer.

use openauth_core::api::{
    core_auth_async_endpoints, core_endpoints, ApiRequest, ApiResponse, AsyncAuthEndpoint,
    AuthEndpoint, AuthRouter, EndpointInfo,
};
use openauth_core::context::{create_auth_context, AuthContext};
use openauth_core::db::{auth_schema, DbAdapter, JoinAdapter};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
use std::sync::Arc;

pub use openauth_core::auth::oauth;

/// Initialized OpenAuth instance.
#[derive(Clone)]
pub struct OpenAuth {
    router: AuthRouter,
    options: OpenAuthOptions,
    context: AuthContext,
}

impl OpenAuth {
    pub fn handler(&self, request: ApiRequest) -> Result<ApiResponse, OpenAuthError> {
        self.router.handle(request)
    }

    pub async fn handler_async(&self, request: ApiRequest) -> Result<ApiResponse, OpenAuthError> {
        self.router.handle_async(request).await
    }

    pub fn options(&self) -> &OpenAuthOptions {
        &self.options
    }

    pub fn context(&self) -> &AuthContext {
        &self.context
    }

    pub fn router(&self) -> &AuthRouter {
        &self.router
    }

    pub fn endpoint_registry(&self) -> Vec<EndpointInfo> {
        self.router.endpoint_registry()
    }

    pub fn openapi_schema(&self) -> serde_json::Value {
        self.router.openapi_schema()
    }
}

/// Initialize OpenAuth with the default product endpoint set.
pub fn open_auth(options: OpenAuthOptions) -> Result<OpenAuth, OpenAuthError> {
    open_auth_with_endpoints(options, Vec::new(), Vec::new())
}

/// Initialize OpenAuth with the default product endpoint set backed by a database adapter.
pub fn open_auth_with_adapter(
    options: OpenAuthOptions,
    adapter: Arc<dyn DbAdapter>,
) -> Result<OpenAuth, OpenAuthError> {
    open_auth_with_adapter_and_endpoints(options, adapter, Vec::new(), Vec::new())
}

/// Initialize OpenAuth with product endpoints, a database adapter, and extra endpoints.
pub fn open_auth_with_adapter_and_endpoints(
    options: OpenAuthOptions,
    adapter: Arc<dyn DbAdapter>,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
) -> Result<OpenAuth, OpenAuthError> {
    let context = create_auth_context(options.clone())?;
    let adapter: Arc<dyn DbAdapter> = Arc::new(JoinAdapter::new(
        auth_schema(Default::default()),
        adapter,
        options.experimental.joins,
    ));
    let mut endpoints = core_endpoints();
    endpoints.extend(extra_endpoints);
    let mut product_async_endpoints = core_auth_async_endpoints(adapter);
    product_async_endpoints.extend(async_endpoints);
    let router =
        AuthRouter::with_async_endpoints(context.clone(), endpoints, product_async_endpoints)?;
    Ok(OpenAuth {
        router,
        options,
        context,
    })
}

/// Initialize OpenAuth with the default product endpoint set plus extra endpoints.
pub fn open_auth_with_endpoints(
    options: OpenAuthOptions,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
) -> Result<OpenAuth, OpenAuthError> {
    let context = create_auth_context(options.clone())?;
    let mut endpoints = core_endpoints();
    endpoints.extend(extra_endpoints);
    let router = AuthRouter::with_async_endpoints(context.clone(), endpoints, async_endpoints)?;
    Ok(OpenAuth {
        router,
        options,
        context,
    })
}
