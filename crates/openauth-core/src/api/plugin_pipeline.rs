use std::collections::HashSet;

use http::Method;

use crate::context::AuthContext;
use crate::error::OpenAuthError;
use crate::plugin::{PluginAfterHookAction, PluginBeforeHookAction, PluginRequestAction};

use super::endpoint::{ApiRequest, ApiResponse, AsyncAuthEndpoint, AuthEndpoint};
use super::path::path_matches;

pub(super) fn run_on_request_plugins(
    context: &AuthContext,
    mut request: ApiRequest,
) -> Result<PluginRequestAction, OpenAuthError> {
    for plugin in &context.plugins {
        if let Some(hook) = &plugin.on_request {
            match hook(context, request)? {
                PluginRequestAction::Continue(next_request) => request = next_request,
                PluginRequestAction::Respond(response) => {
                    return Ok(PluginRequestAction::Respond(response));
                }
            }
        }
    }
    Ok(PluginRequestAction::Continue(request))
}

pub(super) fn run_matching_middlewares(
    context: &AuthContext,
    request: &ApiRequest,
    path: &str,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    for plugin in &context.plugins {
        for middleware in &plugin.middlewares {
            if path_matches(&middleware.path, path) {
                if let Some(response) = (middleware.handler)(context, request)? {
                    return Ok(Some(response));
                }
            }
        }
    }
    Ok(None)
}

pub(super) async fn run_matching_async_middlewares(
    context: &AuthContext,
    request: &ApiRequest,
    path: &str,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    for plugin in &context.plugins {
        for middleware in &plugin.async_middlewares {
            if path_matches(&middleware.path, path) {
                if let Some(response) = (middleware.handler)(context, request).await? {
                    return Ok(Some(response));
                }
            }
        }
    }
    Ok(None)
}

pub(super) fn run_on_response_plugins(
    context: &AuthContext,
    request: &ApiRequest,
    mut response: ApiResponse,
) -> Result<ApiResponse, OpenAuthError> {
    for plugin in &context.plugins {
        if let Some(hook) = &plugin.on_response {
            response = hook(context, request, response)?;
        }
    }
    Ok(response)
}

pub(super) fn run_before_hooks(
    context: &AuthContext,
    mut request: ApiRequest,
    method: &Method,
    path: &str,
    operation_id: Option<&str>,
) -> Result<PluginBeforeHookAction, OpenAuthError> {
    for plugin in &context.plugins {
        for hook in &plugin.hooks.before {
            if hook.matcher.matches(method, path, operation_id) {
                match (hook.handler)(context, request)? {
                    PluginBeforeHookAction::Continue(next_request) => request = next_request,
                    PluginBeforeHookAction::Respond(response) => {
                        return Ok(PluginBeforeHookAction::Respond(response));
                    }
                }
            }
        }
    }
    Ok(PluginBeforeHookAction::Continue(request))
}

pub(super) fn run_after_hooks(
    context: &AuthContext,
    request: &ApiRequest,
    mut response: ApiResponse,
    method: &Method,
    path: &str,
    operation_id: Option<&str>,
) -> Result<ApiResponse, OpenAuthError> {
    for plugin in &context.plugins {
        for hook in &plugin.hooks.after {
            if hook.matcher.matches(method, path, operation_id) {
                let PluginAfterHookAction::Continue(next_response) =
                    (hook.handler)(context, request, response)?;
                response = next_response;
            }
        }
    }
    Ok(response)
}

pub(super) async fn run_async_after_hooks(
    context: &AuthContext,
    request: &ApiRequest,
    mut response: ApiResponse,
    method: &Method,
    path: &str,
    operation_id: Option<&str>,
) -> Result<ApiResponse, OpenAuthError> {
    for plugin in &context.plugins {
        for hook in &plugin.hooks.async_after {
            if hook.matcher.matches(method, path, operation_id) {
                let PluginAfterHookAction::Continue(next_response) =
                    (hook.handler)(context, request, response).await?;
                response = next_response;
            }
        }
    }
    Ok(response)
}

pub(super) fn plugin_async_endpoints(
    context: &AuthContext,
    mut async_endpoints: Vec<AsyncAuthEndpoint>,
) -> Vec<AsyncAuthEndpoint> {
    for plugin in &context.plugins {
        async_endpoints.extend(plugin.endpoints.iter().cloned());
    }
    async_endpoints
}

pub(super) fn endpoint_operation_id(endpoint: &AsyncAuthEndpoint) -> Option<&str> {
    endpoint
        .options
        .operation_id
        .as_deref()
        .or_else(|| endpoint.options.openapi.as_ref()?.operation_id.as_deref())
}

pub(super) fn validate_endpoint_conflicts(
    endpoints: &[AuthEndpoint],
    async_endpoints: &[AsyncAuthEndpoint],
) -> Result<(), OpenAuthError> {
    let mut seen = HashSet::new();
    for endpoint in endpoints {
        let key = (
            endpoint.method.clone(),
            endpoint_conflict_key(&endpoint.path),
        );
        if !seen.insert(key) {
            return Err(OpenAuthError::Api(format!(
                "endpoint conflict for {} {}",
                endpoint.method, endpoint.path
            )));
        }
    }
    for endpoint in async_endpoints {
        let key = (
            endpoint.method.clone(),
            endpoint_conflict_key(&endpoint.path),
        );
        if !seen.insert(key) {
            return Err(OpenAuthError::Api(format!(
                "endpoint conflict for {} {}",
                endpoint.method, endpoint.path
            )));
        }
    }
    Ok(())
}

fn endpoint_conflict_key(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.starts_with(':') && segment.len() > 1 {
                ":".to_owned()
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}
