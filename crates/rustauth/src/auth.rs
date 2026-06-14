//! Public RustAuth initializer.

use rustauth_core::api::{
    core_auth_async_endpoints, core_endpoints, ApiRequest, ApiResponse, AsyncAuthEndpoint,
    AuthEndpoint, AuthRouter, EndpointInfo,
};
#[cfg(feature = "telemetry")]
use rustauth_core::context::ContextTelemetryEvent;
use rustauth_core::context::{create_auth_context, create_auth_context_with_adapter, AuthContext};
use rustauth_core::db::{DbAdapter, JoinAdapter, SchemaCreation};
use rustauth_core::error::RustAuthError;
use rustauth_core::options::{DeploymentMode, RustAuthOptions};
#[cfg(feature = "telemetry")]
use rustauth_telemetry::{create_telemetry, TelemetryContext, TelemetryEvent};
use std::sync::Arc;

pub use rustauth_core::auth::oauth;

/// Initialized RustAuth instance.
#[derive(Clone)]
pub struct RustAuth {
    router: AuthRouter,
    options: RustAuthOptions,
    context: AuthContext,
    adapter: Option<Arc<dyn DbAdapter>>,
}

impl RustAuth {
    /// Start an [`RustAuthBuilder`] using default [`RustAuthOptions`].
    pub fn builder() -> RustAuthBuilder {
        RustAuthBuilder::new()
    }

    /// Handle a request through the synchronous endpoint router.
    ///
    /// This is useful for endpoint sets that do not require async database or
    /// network work. Most adapter-backed applications should use
    /// [`RustAuth::handler_async`].
    pub fn handler(&self, request: ApiRequest) -> Result<ApiResponse, RustAuthError> {
        self.router.handle(request)
    }

    /// Handle a request through the async endpoint router.
    pub async fn handler_async(&self, request: ApiRequest) -> Result<ApiResponse, RustAuthError> {
        self.router.handle_async(request).await
    }

    /// Return the effective options used to build this instance.
    pub fn options(&self) -> &RustAuthOptions {
        &self.options
    }

    /// Return the initialized authentication context.
    pub fn context(&self) -> &AuthContext {
        &self.context
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
    ) -> Result<Option<SchemaCreation>, RustAuthError> {
        let adapter = self.adapter.as_ref().ok_or_else(|| {
            RustAuthError::InvalidConfig(
                "RustAuth::create_schema requires an adapter-backed instance".to_owned(),
            )
        })?;
        adapter.create_schema(&self.context.db_schema, file).await
    }

    #[cfg(feature = "telemetry")]
    /// Publish a telemetry event through the initialized context publisher.
    pub async fn publish_telemetry(&self, event: ContextTelemetryEvent) {
        self.context.publish_telemetry(event).await;
    }
}

/// Builder for constructing an [`RustAuth`] instance.
///
/// The builder mirrors common [`RustAuthOptions`] setters and can also attach
/// database adapters, plugins, social providers, and custom endpoints.
#[derive(Default)]
pub struct RustAuthBuilder {
    options: RustAuthOptions,
    adapter: Option<Arc<dyn DbAdapter>>,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
    #[cfg(feature = "telemetry")]
    telemetry_context: Option<TelemetryContext>,
}

impl RustAuthBuilder {
    /// Create a builder with default options and no adapter.
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Replace all options used by the builder.
    pub fn options(mut self, options: RustAuthOptions) -> Self {
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
    pub fn rate_limit(mut self, rate_limit: rustauth_core::options::RateLimitOptions) -> Self {
        self.options = self.options.rate_limit(rate_limit);
        self
    }

    #[must_use]
    /// Replace session configuration.
    pub fn session(mut self, session: rustauth_core::options::SessionOptions) -> Self {
        self.options = self.options.session(session);
        self
    }

    #[must_use]
    /// Replace user model and lifecycle configuration.
    pub fn user(mut self, user: rustauth_core::options::UserOptions) -> Self {
        self.options = self.options.user(user);
        self
    }

    #[must_use]
    /// Replace password authentication configuration.
    pub fn password(mut self, password: rustauth_core::options::PasswordOptions) -> Self {
        self.options = self.options.password(password);
        self
    }

    #[must_use]
    /// Replace email/password sign-in and sign-up configuration.
    pub fn email_password(
        mut self,
        email_password: rustauth_core::options::EmailPasswordOptions,
    ) -> Self {
        self.options = self.options.email_password(email_password);
        self
    }

    #[must_use]
    /// Replace account linking and account model configuration.
    pub fn account(mut self, account: rustauth_core::options::AccountOptions) -> Self {
        self.options = self.options.account(account);
        self
    }

    #[must_use]
    /// Replace advanced runtime configuration.
    pub fn advanced(mut self, advanced: rustauth_core::options::AdvancedOptions) -> Self {
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
    /// Enable or disable development-mode behavior.
    pub fn development(mut self, development: bool) -> Self {
        self.options = self.options.development(development);
        self
    }

    #[must_use]
    /// Set deployment posture explicitly.
    pub fn deployment_mode(mut self, mode: DeploymentMode) -> Self {
        self.options = self.options.deployment_mode(mode);
        self
    }

    #[must_use]
    /// Replace telemetry configuration.
    pub fn telemetry(mut self, telemetry: rustauth_core::options::TelemetryOptions) -> Self {
        self.options = self.options.telemetry(telemetry);
        self
    }

    #[must_use]
    /// Register an RustAuth plugin.
    pub fn plugin(mut self, plugin: rustauth_core::plugin::AuthPlugin) -> Self {
        self.options = self.options.plugin(plugin);
        self
    }

    #[must_use]
    /// Register an RustAuth plugin (alias for [`Self::plugin`]).
    pub fn push_plugin(self, plugin: rustauth_core::plugin::AuthPlugin) -> Self {
        self.plugin(plugin)
    }

    #[must_use]
    /// Register multiple RustAuth plugins.
    ///
    /// Appends each plugin to the builder list, like chaining [`.plugin`](Self::plugin).
    /// For a full replacement list, use [`RustAuthOptions::set_plugins`].
    pub fn plugins(mut self, plugins: Vec<rustauth_core::plugin::AuthPlugin>) -> Self {
        self.options = self.options.plugins(plugins);
        self
    }

    #[must_use]
    /// Register multiple RustAuth plugins (alias for [`Self::plugins`]).
    pub fn extend_plugins(self, plugins: Vec<rustauth_core::plugin::AuthPlugin>) -> Self {
        self.plugins(plugins)
    }

    #[cfg(feature = "oauth")]
    #[must_use]
    /// Register a social OAuth provider.
    pub fn social_provider<P>(mut self, provider: P) -> Self
    where
        P: rustauth_core::oauth::oauth2::SocialOAuthProvider,
    {
        self.options = self.options.social_provider(provider);
        self
    }

    #[cfg(feature = "oauth")]
    #[must_use]
    /// Register multiple social OAuth providers.
    pub fn social_providers<I, P>(mut self, providers: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: rustauth_core::oauth::oauth2::SocialOAuthProvider + 'static,
    {
        self.options = self.options.social_providers(providers);
        self
    }

    #[cfg(feature = "oauth")]
    /// Register social OAuth providers built from fallible constructors.
    pub fn try_social_providers<I, P, E>(mut self, iter: I) -> Result<Self, E>
    where
        I: IntoIterator<Item = Result<P, E>>,
        P: rustauth_core::oauth::oauth2::SocialOAuthProvider + 'static,
        E: std::error::Error,
    {
        self.options = self.options.try_social_providers(iter)?;
        Ok(self)
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
    /// Provide telemetry initialization context for [`Self::build`].
    pub fn telemetry_context(mut self, context: TelemetryContext) -> Self {
        self.telemetry_context = Some(context);
        self
    }

    /// Build the configured [`RustAuth`] instance.
    ///
    /// When the `telemetry` feature is enabled, this also initializes the
    /// telemetry publisher before returning.
    pub async fn build(self) -> Result<RustAuth, RustAuthError> {
        if let Some(adapter) = self.adapter {
            build_with_adapter(
                self.options,
                adapter,
                self.extra_endpoints,
                self.async_endpoints,
                #[cfg(feature = "telemetry")]
                self.telemetry_context,
            )
            .await
        } else {
            build_without_adapter(
                self.options,
                self.extra_endpoints,
                self.async_endpoints,
                #[cfg(feature = "telemetry")]
                self.telemetry_context,
            )
            .await
        }
    }
}

async fn build_without_adapter(
    options: RustAuthOptions,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
    #[cfg(feature = "telemetry")] telemetry_context: Option<TelemetryContext>,
) -> Result<RustAuth, RustAuthError> {
    let context = create_auth_context(options.clone())?;
    let context = {
        #[cfg(feature = "telemetry")]
        {
            let mut context = context;
            attach_telemetry(
                &mut context,
                &options,
                telemetry_context.unwrap_or_default(),
            )
            .await;
            context
        }
        #[cfg(not(feature = "telemetry"))]
        {
            context
        }
    };
    let mut endpoints = core_endpoints();
    endpoints.extend(extra_endpoints);
    let router = AuthRouter::with_async_endpoints(context.clone(), endpoints, async_endpoints)?;
    Ok(RustAuth {
        router,
        options,
        context,
        adapter: None,
    })
}

async fn build_with_adapter(
    options: RustAuthOptions,
    adapter: Arc<dyn DbAdapter>,
    extra_endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
    #[cfg(feature = "telemetry")] telemetry_context: Option<TelemetryContext>,
) -> Result<RustAuth, RustAuthError> {
    let context = create_auth_context(options.clone())?;
    let joined_adapter: Arc<dyn DbAdapter> = Arc::new(JoinAdapter::new(
        context.db_schema.clone(),
        adapter,
        options.experimental.joins,
    ));
    let context = create_auth_context_with_adapter(options.clone(), Arc::clone(&joined_adapter))?;
    let adapter = context.adapter.clone().unwrap_or(joined_adapter);
    let context = {
        #[cfg(feature = "telemetry")]
        {
            let mut context = context;
            attach_telemetry(
                &mut context,
                &options,
                telemetry_context.unwrap_or_default(),
            )
            .await;
            context
        }
        #[cfg(not(feature = "telemetry"))]
        {
            context
        }
    };
    let mut endpoints = core_endpoints();
    endpoints.extend(extra_endpoints);
    let mut product_async_endpoints = core_auth_async_endpoints();
    product_async_endpoints.extend(async_endpoints);
    let router =
        AuthRouter::with_async_endpoints(context.clone(), endpoints, product_async_endpoints)?;
    Ok(RustAuth {
        router,
        options,
        context,
        adapter: Some(adapter),
    })
}

#[cfg(feature = "telemetry")]
async fn attach_telemetry(
    context: &mut AuthContext,
    options: &RustAuthOptions,
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
