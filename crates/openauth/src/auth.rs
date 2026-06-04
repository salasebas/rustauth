//! Public OpenAuth initializer.

use openauth_core::api::{
    core_auth_async_endpoints, core_endpoints, ApiRequest, ApiResponse, AsyncAuthEndpoint,
    AuthEndpoint, AuthRouter, EndpointInfo,
};
#[cfg(feature = "telemetry")]
use openauth_core::context::ContextTelemetryEvent;
use openauth_core::context::{create_auth_context, create_auth_context_with_adapter, AuthContext};
use openauth_core::db::{DbAdapter, HookedAdapter, JoinAdapter, SchemaCreation};
use openauth_core::error::OpenAuthError;
use openauth_core::options::OpenAuthOptions;
#[cfg(feature = "telemetry")]
use openauth_telemetry::{create_telemetry, TelemetryContext, TelemetryEvent};
use std::sync::Arc;

pub use openauth_core::auth::oauth;

/// Initialized OpenAuth instance.
#[derive(Clone)]
pub struct OpenAuth {
    router: AuthRouter,
    options: OpenAuthOptions,
    context: AuthContext,
    adapter: Option<Arc<dyn DbAdapter>>,
}

impl OpenAuth {
    /// Start an [`OpenAuthBuilder`] using default [`OpenAuthOptions`].
    pub fn builder() -> OpenAuthBuilder {
        OpenAuthBuilder::new()
    }

    /// Handle a request through the synchronous endpoint router.
    ///
    /// This is useful for endpoint sets that do not require async database or
    /// network work. Most adapter-backed applications should use
    /// [`OpenAuth::handler_async`].
    pub fn handler(&self, request: ApiRequest) -> Result<ApiResponse, OpenAuthError> {
        self.router.handle(request)
    }

    /// Handle a request through the async endpoint router.
    pub async fn handler_async(&self, request: ApiRequest) -> Result<ApiResponse, OpenAuthError> {
        self.router.handle_async(request).await
    }

    /// Return the effective options used to build this instance.
    pub fn options(&self) -> &OpenAuthOptions {
        &self.options
    }

    /// Return the initialized authentication context.
    pub fn context(&self) -> &AuthContext {
        &self.context
    }

    /// Return the underlying router.
    pub fn router(&self) -> &AuthRouter {
        &self.router
    }

    /// Return metadata for all registered endpoints.
    pub fn endpoint_registry(&self) -> Vec<EndpointInfo> {
        self.router.endpoint_registry()
    }

    /// Generate the OpenAPI schema for the registered endpoint surface.
    pub fn openapi_schema(&self) -> serde_json::Value {
        self.router.openapi_schema()
    }

    /// Create the database schema for this instance.
    ///
    /// Returns an error when the instance was created without an adapter.
    /// When `file` is provided, adapter implementations may write migration
    /// SQL to that path and return adapter-specific creation metadata.
    pub async fn create_schema(
        &self,
        file: Option<&str>,
    ) -> Result<Option<SchemaCreation>, OpenAuthError> {
        let adapter = self.adapter.as_ref().ok_or_else(|| {
            OpenAuthError::InvalidConfig(
                "OpenAuth::create_schema requires an adapter-backed instance".to_owned(),
            )
        })?;
        adapter.create_schema(&self.context.db_schema, file).await
    }

    /// Run adapter migrations for the configured core and plugin schema.
    ///
    /// Returns an error when the instance was created without an adapter.
    pub async fn run_migrations(&self) -> Result<(), OpenAuthError> {
        let adapter = self.adapter.as_ref().ok_or_else(|| {
            OpenAuthError::InvalidConfig(
                "OpenAuth::run_migrations requires an adapter-backed instance".to_owned(),
            )
        })?;
        adapter.run_migrations(&self.context.db_schema).await
    }

    #[cfg(feature = "telemetry")]
    /// Publish a telemetry event through the initialized context publisher.
    pub async fn publish_telemetry(&self, event: ContextTelemetryEvent) {
        self.context.publish_telemetry(event).await;
    }
}

/// Builder for constructing an [`OpenAuth`] instance.
///
/// The builder mirrors common [`OpenAuthOptions`] setters and can also attach
/// database adapters, plugins, social providers, and custom endpoints.
#[derive(Default)]
pub struct OpenAuthBuilder {
    options: OpenAuthOptions,
    adapter: Option<Arc<dyn DbAdapter>>,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
    #[cfg(feature = "telemetry")]
    telemetry_context: Option<TelemetryContext>,
}

impl OpenAuthBuilder {
    /// Create a builder with default options and no adapter.
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Replace all options used by the builder.
    pub fn options(mut self, options: OpenAuthOptions) -> Self {
        self.options = options;
        self
    }

    #[must_use]
    /// Set the public base URL used for redirects, cookies, and generated URLs.
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.options = self.options.base_url(base_url);
        self
    }

    #[must_use]
    /// Set the URL path prefix for auth endpoints.
    pub fn base_path(mut self, base_path: impl Into<String>) -> Self {
        self.options = self.options.base_path(base_path);
        self
    }

    #[must_use]
    /// Set the primary application secret.
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.options = self.options.secret(secret);
        self
    }

    #[must_use]
    /// Replace rate limit configuration.
    pub fn rate_limit(mut self, rate_limit: openauth_core::options::RateLimitOptions) -> Self {
        self.options = self.options.rate_limit(rate_limit);
        self
    }

    #[must_use]
    /// Replace session configuration.
    pub fn session(mut self, session: openauth_core::options::SessionOptions) -> Self {
        self.options = self.options.session(session);
        self
    }

    #[must_use]
    /// Replace user model and lifecycle configuration.
    pub fn user(mut self, user: openauth_core::options::UserOptions) -> Self {
        self.options = self.options.user(user);
        self
    }

    #[must_use]
    /// Replace password authentication configuration.
    pub fn password(mut self, password: openauth_core::options::PasswordOptions) -> Self {
        self.options = self.options.password(password);
        self
    }

    #[must_use]
    /// Replace account linking and account model configuration.
    pub fn account(mut self, account: openauth_core::options::AccountOptions) -> Self {
        self.options = self.options.account(account);
        self
    }

    #[must_use]
    /// Replace advanced runtime configuration.
    pub fn advanced(mut self, advanced: openauth_core::options::AdvancedOptions) -> Self {
        self.options = self.options.advanced(advanced);
        self
    }

    #[must_use]
    /// Enable or disable production-mode behavior.
    pub fn production(mut self, production: bool) -> Self {
        self.options = self.options.production(production);
        self
    }

    #[must_use]
    /// Replace telemetry configuration.
    pub fn telemetry(mut self, telemetry: openauth_core::options::TelemetryOptions) -> Self {
        self.options = self.options.telemetry(telemetry);
        self
    }

    #[must_use]
    /// Register an OpenAuth plugin.
    pub fn plugin(mut self, plugin: openauth_core::plugin::AuthPlugin) -> Self {
        self.options = self.options.plugin(plugin);
        self
    }

    #[must_use]
    /// Register a social OAuth provider.
    pub fn social_provider<P>(mut self, provider: P) -> Self
    where
        P: openauth_core::oauth::oauth2::SocialOAuthProvider,
    {
        self.options = self.options.social_provider(provider);
        self
    }

    #[must_use]
    /// Attach a database adapter by value.
    pub fn adapter<A>(mut self, adapter: A) -> Self
    where
        A: DbAdapter + 'static,
    {
        self.adapter = Some(Arc::new(adapter));
        self
    }

    #[must_use]
    /// Attach a shared database adapter.
    pub fn adapter_arc(mut self, adapter: Arc<dyn DbAdapter>) -> Self {
        self.adapter = Some(adapter);
        self
    }

    #[must_use]
    /// Add one synchronous endpoint to the router.
    pub fn endpoint(mut self, endpoint: AuthEndpoint) -> Self {
        self.extra_endpoints.push(endpoint);
        self
    }

    #[must_use]
    /// Add multiple synchronous endpoints to the router.
    pub fn endpoints(mut self, endpoints: Vec<AuthEndpoint>) -> Self {
        self.extra_endpoints.extend(endpoints);
        self
    }

    #[must_use]
    /// Add one async endpoint to the router.
    pub fn async_endpoint(mut self, endpoint: AsyncAuthEndpoint) -> Self {
        self.async_endpoints.push(endpoint);
        self
    }

    #[must_use]
    /// Add multiple async endpoints to the router.
    pub fn async_endpoints(mut self, endpoints: Vec<AsyncAuthEndpoint>) -> Self {
        self.async_endpoints.extend(endpoints);
        self
    }

    #[cfg(feature = "telemetry")]
    #[must_use]
    /// Provide telemetry initialization context for [`Self::build_async`].
    pub fn telemetry_context(mut self, context: TelemetryContext) -> Self {
        self.telemetry_context = Some(context);
        self
    }

    /// Build the configured [`OpenAuth`] instance.
    pub fn build(self) -> Result<OpenAuth, OpenAuthError> {
        if let Some(adapter) = self.adapter {
            open_auth_with_adapter_and_endpoints(
                self.options,
                adapter,
                self.extra_endpoints,
                self.async_endpoints,
            )
        } else {
            open_auth_with_endpoints(self.options, self.extra_endpoints, self.async_endpoints)
        }
    }

    /// Build the configured [`OpenAuth`] instance.
    ///
    /// When the `telemetry` feature is enabled, this also initializes the
    /// telemetry publisher before returning.
    pub async fn build_async(self) -> Result<OpenAuth, OpenAuthError> {
        #[cfg(feature = "telemetry")]
        {
            let telemetry_context = self.telemetry_context.unwrap_or_default();
            if let Some(adapter) = self.adapter {
                open_auth_with_adapter_and_endpoints_async(
                    self.options,
                    adapter,
                    self.extra_endpoints,
                    self.async_endpoints,
                    telemetry_context,
                )
                .await
            } else {
                open_auth_with_endpoints_async(
                    self.options,
                    self.extra_endpoints,
                    self.async_endpoints,
                    telemetry_context,
                )
                .await
            }
        }
        #[cfg(not(feature = "telemetry"))]
        {
            self.build()
        }
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
    let hooked_adapter: Arc<dyn DbAdapter> = Arc::new(HookedAdapter::with_logger(
        adapter,
        context.plugin_database_hooks.clone(),
        context.logger.clone(),
    ));
    let adapter: Arc<dyn DbAdapter> = Arc::new(JoinAdapter::new(
        context.db_schema.clone(),
        hooked_adapter,
        options.experimental.joins,
    ));
    let context = create_auth_context_with_adapter(options.clone(), Arc::clone(&adapter))?;
    let mut endpoints = core_endpoints();
    endpoints.extend(extra_endpoints);
    let mut product_async_endpoints = core_auth_async_endpoints(Arc::clone(&adapter));
    product_async_endpoints.extend(async_endpoints);
    let router =
        AuthRouter::with_async_endpoints(context.clone(), endpoints, product_async_endpoints)?;
    Ok(OpenAuth {
        router,
        options,
        context,
        adapter: Some(adapter),
    })
}

/// Initialize OpenAuth with the default product endpoint set.
pub async fn open_auth_async(options: OpenAuthOptions) -> Result<OpenAuth, OpenAuthError> {
    #[cfg(feature = "telemetry")]
    {
        open_auth_with_endpoints_async(options, Vec::new(), Vec::new(), TelemetryContext::default())
            .await
    }
    #[cfg(not(feature = "telemetry"))]
    {
        open_auth_with_endpoints(options, Vec::new(), Vec::new())
    }
}

/// Initialize OpenAuth with product endpoints.
#[cfg(feature = "telemetry")]
pub async fn open_auth_with_endpoints_async(
    options: OpenAuthOptions,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
    telemetry_context: TelemetryContext,
) -> Result<OpenAuth, OpenAuthError> {
    let mut context = create_auth_context(options.clone())?;
    attach_telemetry(&mut context, &options, telemetry_context).await;
    let mut endpoints = core_endpoints();
    endpoints.extend(extra_endpoints);
    let router = AuthRouter::with_async_endpoints(context.clone(), endpoints, async_endpoints)?;
    Ok(OpenAuth {
        router,
        options,
        context,
        adapter: None,
    })
}

/// Initialize OpenAuth with product endpoints.
#[cfg(not(feature = "telemetry"))]
pub async fn open_auth_with_endpoints_async(
    options: OpenAuthOptions,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
) -> Result<OpenAuth, OpenAuthError> {
    open_auth_with_endpoints(options, extra_endpoints, async_endpoints)
}

/// Initialize OpenAuth with a database adapter.
pub async fn open_auth_with_adapter_async(
    options: OpenAuthOptions,
    adapter: Arc<dyn DbAdapter>,
) -> Result<OpenAuth, OpenAuthError> {
    #[cfg(feature = "telemetry")]
    {
        open_auth_with_adapter_and_endpoints_async(
            options,
            adapter,
            Vec::new(),
            Vec::new(),
            TelemetryContext::default(),
        )
        .await
    }
    #[cfg(not(feature = "telemetry"))]
    {
        open_auth_with_adapter(options, adapter)
    }
}

/// Initialize OpenAuth with product endpoints, a database adapter, and optional extra endpoints.
#[cfg(feature = "telemetry")]
pub async fn open_auth_with_adapter_and_endpoints_async(
    options: OpenAuthOptions,
    adapter: Arc<dyn DbAdapter>,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
    telemetry_context: TelemetryContext,
) -> Result<OpenAuth, OpenAuthError> {
    let context = create_auth_context(options.clone())?;
    let hooked_adapter: Arc<dyn DbAdapter> = Arc::new(HookedAdapter::new(
        adapter,
        context.plugin_database_hooks.clone(),
    ));
    let adapter: Arc<dyn DbAdapter> = Arc::new(JoinAdapter::new(
        context.db_schema.clone(),
        hooked_adapter,
        options.experimental.joins,
    ));
    let mut context = create_auth_context_with_adapter(options.clone(), Arc::clone(&adapter))?;
    attach_telemetry(&mut context, &options, telemetry_context).await;
    let mut endpoints = core_endpoints();
    endpoints.extend(extra_endpoints);
    let mut product_async_endpoints = core_auth_async_endpoints(Arc::clone(&adapter));
    product_async_endpoints.extend(async_endpoints);
    let router =
        AuthRouter::with_async_endpoints(context.clone(), endpoints, product_async_endpoints)?;
    Ok(OpenAuth {
        router,
        options,
        context,
        adapter: Some(adapter),
    })
}

/// Initialize OpenAuth with product endpoints, a database adapter, and optional extra endpoints.
#[cfg(not(feature = "telemetry"))]
pub async fn open_auth_with_adapter_and_endpoints_async(
    options: OpenAuthOptions,
    adapter: Arc<dyn DbAdapter>,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
) -> Result<OpenAuth, OpenAuthError> {
    open_auth_with_adapter_and_endpoints(options, adapter, extra_endpoints, async_endpoints)
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
        adapter: None,
    })
}

#[cfg(feature = "telemetry")]
async fn attach_telemetry(
    context: &mut AuthContext,
    options: &OpenAuthOptions,
    telemetry_context: TelemetryContext,
) {
    let publisher = create_telemetry(options, telemetry_context).await;
    context.telemetry_publisher = Arc::new(move |event: ContextTelemetryEvent| {
        let publisher = publisher.clone();
        Box::pin(async move {
            publisher
                .publish(TelemetryEvent {
                    event_type: event.event_type,
                    anonymous_id: event.anonymous_id,
                    payload: event.payload,
                })
                .await;
        })
    });
}
