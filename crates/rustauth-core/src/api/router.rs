use http::StatusCode;
use serde_json::Value;

use crate::context::request_state::{
    run_with_request_state, set_current_request_path, set_request_external,
};
use crate::context::AuthContext;
use crate::error::RustAuthError;
use crate::plugin::{PluginBeforeHookAction, PluginRequestAction};
use crate::rate_limit::{consume_rate_limit, on_request_rate_limit};
use crate::utils::url::normalize_pathname;

use super::endpoint::{
    run_endpoint_middlewares, validate_async_endpoint_request, ApiRequest, ApiResponse,
    AsyncAuthEndpoint, AuthEndpoint, EndpointInfo, EndpointKind,
};
use super::error::{api_error, rate_limit_response, response, ApiErrorCode};
use super::on_api_error::handle_on_api_error;
use super::openapi::build_openapi_schema;
use super::path::{match_path_pattern, route_pathname, PathParams};
use super::plugin_pipeline::{
    endpoint_operation_id, finalize_response, finalize_response_async, plugin_async_endpoints,
    run_after_hooks, run_async_after_hooks, run_async_before_hooks, run_before_hooks,
    run_matching_async_middlewares, run_matching_middlewares, run_on_request_plugins,
    validate_endpoint_conflicts,
};
use super::security::validate_request_security;

#[derive(Clone)]
pub struct AuthRouter {
    context: AuthContext,
    endpoints: Vec<AuthEndpoint>,
    async_endpoints: Vec<AsyncAuthEndpoint>,
}

impl AuthRouter {
    pub fn new(context: AuthContext, endpoints: Vec<AuthEndpoint>) -> Self {
        let async_endpoints = plugin_async_endpoints(&context, Vec::new());
        Self {
            context,
            endpoints,
            async_endpoints,
        }
    }

    pub fn try_new(
        context: AuthContext,
        endpoints: Vec<AuthEndpoint>,
    ) -> Result<Self, RustAuthError> {
        let async_endpoints = plugin_async_endpoints(&context, Vec::new());
        validate_endpoint_conflicts(&endpoints, &async_endpoints)?;
        Ok(Self {
            context,
            endpoints,
            async_endpoints,
        })
    }

    pub fn with_async_endpoints(
        context: AuthContext,
        endpoints: Vec<AuthEndpoint>,
        async_endpoints: Vec<AsyncAuthEndpoint>,
    ) -> Result<Self, RustAuthError> {
        let async_endpoints = plugin_async_endpoints(&context, async_endpoints);
        validate_endpoint_conflicts(&endpoints, &async_endpoints)?;
        Ok(Self {
            context,
            endpoints,
            async_endpoints,
        })
    }

    pub fn endpoint_registry(&self) -> Vec<EndpointInfo> {
        let sync_endpoints = self.endpoints.iter().map(|endpoint| EndpointInfo {
            path: endpoint.path.clone(),
            method: endpoint.method.clone(),
            kind: EndpointKind::Sync,
            operation_id: None,
            allowed_media_types: Vec::new(),
        });
        let async_endpoints = self
            .async_endpoints
            .iter()
            .filter(|endpoint| !endpoint.options.server_only)
            .map(|endpoint| EndpointInfo {
                path: endpoint.path.clone(),
                method: endpoint.method.clone(),
                kind: EndpointKind::Async,
                operation_id: endpoint
                    .options
                    .operation_id
                    .clone()
                    .or_else(|| endpoint.options.openapi.as_ref()?.operation_id.clone()),
                allowed_media_types: endpoint.options.allowed_media_types.clone(),
            });
        sync_endpoints.chain(async_endpoints).collect()
    }

    pub fn openapi_schema(&self) -> Value {
        build_openapi_schema(&self.context, &self.async_endpoints)
    }

    pub fn handle(&self, request: ApiRequest) -> Result<ApiResponse, RustAuthError> {
        let request_for_error = request.clone();
        match self.handle_inner(request) {
            Ok(response) => Ok(response),
            Err(error) => handle_on_api_error(&self.context, &request_for_error, error),
        }
    }

    fn handle_inner(&self, mut request: ApiRequest) -> Result<ApiResponse, RustAuthError> {
        let normalized_path =
            normalize_pathname(&request.uri().to_string(), &self.context.base_path);
        if self
            .context
            .disabled_paths
            .iter()
            .any(|item| item == &normalized_path)
        {
            return finalize_response(
                &self.context,
                &request,
                api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound)?,
            );
        }
        let finalize_request = request.clone();
        request = match run_on_request_plugins(&self.context, request)? {
            PluginRequestAction::Continue(request) => request,
            PluginRequestAction::Respond(response) => {
                return finalize_response(&self.context, &finalize_request, response);
            }
        };
        if let Some(rejection) = validate_request_security(&self.context, &request, false)? {
            return finalize_response(&self.context, &request, rejection);
        }
        let path = route_pathname(
            &request.uri().to_string(),
            &self.context.base_path,
            self.context.options.advanced.skip_trailing_slashes,
        );
        let Some((endpoint, params)) = self.endpoints.iter().find_map(|endpoint| {
            (endpoint.method == *request.method())
                .then(|| match_path_pattern(&endpoint.path, &path).map(|params| (endpoint, params)))
                .flatten()
        }) else {
            if self.async_endpoints.iter().any(|endpoint| {
                endpoint.method == *request.method()
                    && !endpoint.options.server_only
                    && match_path_pattern(&endpoint.path, &path).is_some()
            }) {
                return Err(RustAuthError::Api(
                    "async endpoint requires AuthRouter::handle_async".to_owned(),
                ));
            }
            return finalize_response(
                &self.context,
                &request,
                api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound)?,
            );
        };
        request.extensions_mut().insert(PathParams::new(params));
        if let Some(response) = run_matching_middlewares(&self.context, &request, &path)? {
            return finalize_response(&self.context, &request, response);
        }
        if let Some(rejection) = on_request_rate_limit(&self.context, &request)? {
            return finalize_response(&self.context, &request, rate_limit_response(rejection)?);
        }
        let finalize_request = request.clone();
        request = match run_before_hooks(&self.context, request, &endpoint.method, &path, None)? {
            PluginBeforeHookAction::Continue(request) => request,
            PluginBeforeHookAction::Respond(response) => {
                return finalize_response(&self.context, &finalize_request, response);
            }
        };
        let response = (endpoint.handler)(&self.context, request.clone())?;
        let response = run_after_hooks(
            &self.context,
            &request,
            response,
            &endpoint.method,
            &path,
            None,
        )?;
        finalize_response(&self.context, &request, response)
    }

    pub async fn handle_async(&self, request: ApiRequest) -> Result<ApiResponse, RustAuthError> {
        let request_for_error = request.clone();
        match run_with_request_state(self.handle_async_scoped(request, true)).await {
            Ok(response) => Ok(response),
            Err(error) => handle_on_api_error(&self.context, &request_for_error, error),
        }
    }

    /// Handle a request from trusted server-side code.
    ///
    /// Runs the same pipeline as [`handle_async`](Self::handle_async) but marks
    /// the request as non-internet-facing, allowing endpoints to honor
    /// server-only inputs (such as an explicit user id) that must never be
    /// trusted from internet clients.
    pub async fn handle_async_server(
        &self,
        request: ApiRequest,
    ) -> Result<ApiResponse, RustAuthError> {
        let request_for_error = request.clone();
        match run_with_request_state(self.handle_async_scoped(request, false)).await {
            Ok(response) => Ok(response),
            Err(error) => handle_on_api_error(&self.context, &request_for_error, error),
        }
    }

    async fn handle_async_scoped(
        &self,
        mut request: ApiRequest,
        external: bool,
    ) -> Result<ApiResponse, RustAuthError> {
        set_request_external(external)?;
        let normalized_path =
            normalize_pathname(&request.uri().to_string(), &self.context.base_path);
        if self
            .context
            .disabled_paths
            .iter()
            .any(|item| item == &normalized_path)
        {
            return finalize_response_async(
                &self.context,
                &request,
                api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound)?,
            )
            .await;
        }
        let finalize_request = request.clone();
        request = match run_on_request_plugins(&self.context, request)? {
            PluginRequestAction::Continue(request) => request,
            PluginRequestAction::Respond(response) => {
                return finalize_response_async(&self.context, &finalize_request, response).await;
            }
        };
        let path = route_pathname(
            &request.uri().to_string(),
            &self.context.base_path,
            self.context.options.advanced.skip_trailing_slashes,
        );
        let async_endpoint = self.async_endpoints.iter().find_map(|endpoint| {
            (endpoint.method == *request.method())
                .then(|| match_path_pattern(&endpoint.path, &path).map(|params| (endpoint, params)))
                .flatten()
        });
        let sync_endpoint = self.endpoints.iter().find_map(|endpoint| {
            (endpoint.method == *request.method())
                .then(|| match_path_pattern(&endpoint.path, &path).map(|params| (endpoint, params)))
                .flatten()
        });
        let bypass_origin_security = async_endpoint.as_ref().is_some_and(|(endpoint, _)| {
            !endpoint.options.server_only && endpoint.options.bypass_origin_security
        });
        if let Some(rejection) =
            validate_request_security(&self.context, &request, bypass_origin_security)?
        {
            return finalize_response_async(&self.context, &request, rejection).await;
        }
        if async_endpoint.is_none() && sync_endpoint.is_none() {
            return finalize_response_async(
                &self.context,
                &request,
                api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound)?,
            )
            .await;
        }
        // Consume the route rate limit before plugin middlewares so that security
        // middlewares (such as CAPTCHA) returning a rejection cannot bypass route
        // throttling or force repeated outbound provider calls.
        if let Some(rejection) = consume_rate_limit(&self.context, &request).await? {
            return finalize_response_async(
                &self.context,
                &request,
                rate_limit_response(rejection)?,
            )
            .await;
        }
        if let Some(response) = run_matching_middlewares(&self.context, &request, &path)? {
            return finalize_response_async(&self.context, &request, response).await;
        }
        if let Some(response) =
            run_matching_async_middlewares(&self.context, &request, &path).await?
        {
            return finalize_response_async(&self.context, &request, response).await;
        }
        if let Some((endpoint, params)) = async_endpoint {
            if endpoint.options.server_only && external {
                return finalize_response_async(
                    &self.context,
                    &request,
                    api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound)?,
                )
                .await;
            }
            set_current_request_path(path.clone())?;
            request.extensions_mut().insert(PathParams::new(params));
            if let Some(response) = validate_async_endpoint_request(endpoint, &request)? {
                return finalize_response_async(&self.context, &request, response).await;
            }
            if let Some(response) =
                run_endpoint_middlewares(&self.context, endpoint, &request).await?
            {
                return finalize_response_async(&self.context, &request, response).await;
            }
            let finalize_request = request.clone();
            request = match run_before_hooks(
                &self.context,
                request,
                &endpoint.method,
                &path,
                endpoint_operation_id(endpoint),
            )? {
                PluginBeforeHookAction::Continue(request) => request,
                PluginBeforeHookAction::Respond(response) => {
                    return finalize_response_async(&self.context, &finalize_request, response)
                        .await;
                }
            };
            let finalize_request = request.clone();
            request = match run_async_before_hooks(
                &self.context,
                request,
                &endpoint.method,
                &path,
                endpoint_operation_id(endpoint),
            )
            .await?
            {
                PluginBeforeHookAction::Continue(request) => request,
                PluginBeforeHookAction::Respond(response) => {
                    return finalize_response_async(&self.context, &finalize_request, response)
                        .await;
                }
            };
            let response = (endpoint.handler)(&self.context, request.clone()).await?;
            let response = run_after_hooks(
                &self.context,
                &request,
                response,
                &endpoint.method,
                &path,
                endpoint_operation_id(endpoint),
            )?;
            let response = run_async_after_hooks(
                &self.context,
                &request,
                response,
                &endpoint.method,
                &path,
                endpoint_operation_id(endpoint),
            )
            .await?;
            return finalize_response_async(&self.context, &request, response).await;
        }
        if let Some((endpoint, params)) = sync_endpoint {
            set_current_request_path(path.clone())?;
            request.extensions_mut().insert(PathParams::new(params));
            let finalize_request = request.clone();
            request = match run_before_hooks(&self.context, request, &endpoint.method, &path, None)?
            {
                PluginBeforeHookAction::Continue(request) => request,
                PluginBeforeHookAction::Respond(response) => {
                    return finalize_response_async(&self.context, &finalize_request, response)
                        .await;
                }
            };
            let finalize_request = request.clone();
            request =
                match run_async_before_hooks(&self.context, request, &endpoint.method, &path, None)
                    .await?
                {
                    PluginBeforeHookAction::Continue(request) => request,
                    PluginBeforeHookAction::Respond(response) => {
                        return finalize_response_async(&self.context, &finalize_request, response)
                            .await;
                    }
                };
            let response = (endpoint.handler)(&self.context, request.clone())?;
            let response = run_after_hooks(
                &self.context,
                &request,
                response,
                &endpoint.method,
                &path,
                None,
            )?;
            let response = run_async_after_hooks(
                &self.context,
                &request,
                response,
                &endpoint.method,
                &path,
                None,
            )
            .await?;
            return finalize_response_async(&self.context, &request, response).await;
        }
        finalize_response_async(
            &self.context,
            &request,
            api_error(StatusCode::NOT_FOUND, ApiErrorCode::NotFound)?,
        )
        .await
    }
}

pub fn ok_endpoint(
    _context: &AuthContext,
    _request: ApiRequest,
) -> Result<ApiResponse, RustAuthError> {
    response(StatusCode::OK, b"OK".to_vec())
}

pub fn core_endpoints() -> Vec<AuthEndpoint> {
    vec![AuthEndpoint {
        path: "/ok".to_owned(),
        method: http::Method::GET,
        handler: ok_endpoint,
    }]
}
