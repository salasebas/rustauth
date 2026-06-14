//! Custom session plugin.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::{header, StatusCode};
use rustauth_core::api::{ApiRequest, ApiResponse};
use rustauth_core::context::AuthContext;
use rustauth_core::error::RustAuthError;
use rustauth_core::plugin::{AuthPlugin, PluginAfterHookAction, PluginAfterHookFuture};
use serde::Serialize;
use serde_json::Value;

pub const UPSTREAM_PLUGIN_ID: &str = "custom-session";

/// Options for the custom session plugin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomSessionOptions {
    pub should_mutate_list_device_sessions_endpoint: bool,
}

impl CustomSessionOptions {
    #[must_use]
    pub fn builder() -> CustomSessionOptionsBuilder {
        CustomSessionOptionsBuilder::default()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CustomSessionOptionsBuilder {
    should_mutate_list_device_sessions_endpoint: Option<bool>,
}

impl CustomSessionOptionsBuilder {
    #[must_use]
    pub fn should_mutate_list_device_sessions_endpoint(mut self, enabled: bool) -> Self {
        self.should_mutate_list_device_sessions_endpoint = Some(enabled);
        self
    }

    #[must_use]
    pub fn build(self) -> CustomSessionOptions {
        let defaults = CustomSessionOptions::default();
        CustomSessionOptions {
            should_mutate_list_device_sessions_endpoint: self
                .should_mutate_list_device_sessions_endpoint
                .unwrap_or(defaults.should_mutate_list_device_sessions_endpoint),
        }
    }
}

/// Session payload passed to the custom session handler.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomSessionInput {
    pub user: Value,
    pub session: Value,
}

/// Request context available to custom session handlers.
#[derive(Clone, Copy)]
pub struct CustomSessionContext<'a> {
    pub auth_context: &'a AuthContext,
    pub request: &'a ApiRequest,
}

pub type CustomSessionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Value, RustAuthError>> + Send + 'a>>;

type CustomSessionHandler = Arc<
    dyn for<'a> Fn(CustomSessionInput, CustomSessionContext<'a>) -> CustomSessionFuture<'a>
        + Send
        + Sync,
>;

/// Create a custom session plugin with options and request-aware handler.
#[must_use]
pub fn custom_session<F>(options: CustomSessionOptions, handler: F) -> AuthPlugin
where
    F: for<'a> Fn(CustomSessionInput, CustomSessionContext<'a>) -> CustomSessionFuture<'a>
        + Send
        + Sync
        + 'static,
{
    let handler: CustomSessionHandler = Arc::new(handler);
    let mut plugin = AuthPlugin::new(UPSTREAM_PLUGIN_ID)
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_options(serde_json::to_value(options).unwrap_or(Value::Null))
        .with_async_after_hook("/get-session", {
            let handler = Arc::clone(&handler);
            move |context, request, response| {
                transform_get_session_response(&handler, context, request, response)
            }
        });

    if options.should_mutate_list_device_sessions_endpoint {
        plugin = plugin.with_async_after_hook("/multi-session/list-device-sessions", {
            let handler = Arc::clone(&handler);
            move |context, request, response| {
                transform_list_device_sessions_response(&handler, context, request, response)
            }
        });
    }

    plugin
}

fn transform_get_session_response<'a>(
    handler: &CustomSessionHandler,
    auth_context: &'a AuthContext,
    request: &'a ApiRequest,
    response: ApiResponse,
) -> PluginAfterHookFuture<'a> {
    let handler = Arc::clone(handler);
    Box::pin(async move {
        if response.status() != StatusCode::OK {
            return Ok(PluginAfterHookAction::Continue(response));
        }
        let (parts, body) = response.into_parts();
        let value = response_json(&body)?;
        if value.is_null() {
            return Ok(PluginAfterHookAction::Continue(ApiResponse::from_parts(
                parts, body,
            )));
        }
        let input = custom_session_input(value)?;
        let custom = handler(
            input,
            CustomSessionContext {
                auth_context,
                request,
            },
        )
        .await?;
        Ok(PluginAfterHookAction::Continue(json_response(
            parts, &custom,
        )?))
    })
}

fn transform_list_device_sessions_response<'a>(
    handler: &CustomSessionHandler,
    auth_context: &'a AuthContext,
    request: &'a ApiRequest,
    response: ApiResponse,
) -> PluginAfterHookFuture<'a> {
    let handler = Arc::clone(handler);
    Box::pin(async move {
        if response.status() != StatusCode::OK {
            return Ok(PluginAfterHookAction::Continue(response));
        }
        let (parts, body) = response.into_parts();
        let value = response_json(&body)?;
        let Some(sessions) = value.as_array() else {
            return Err(RustAuthError::Api(
                "custom-session expected list-device-sessions response to be an array".to_owned(),
            ));
        };
        let mut custom_sessions = Vec::with_capacity(sessions.len());
        for session in sessions {
            let input = custom_session_input(session.clone())?;
            custom_sessions.push(
                handler(
                    input,
                    CustomSessionContext {
                        auth_context,
                        request,
                    },
                )
                .await?,
            );
        }
        Ok(PluginAfterHookAction::Continue(json_response(
            parts,
            &Value::Array(custom_sessions),
        )?))
    })
}

fn custom_session_input(value: Value) -> Result<CustomSessionInput, RustAuthError> {
    let Value::Object(mut object) = value else {
        return Err(RustAuthError::Api(
            "custom-session expected session response to be an object".to_owned(),
        ));
    };
    let Some(user) = object.remove("user") else {
        return Err(RustAuthError::Api(
            "custom-session expected session response to include user".to_owned(),
        ));
    };
    let Some(session) = object.remove("session") else {
        return Err(RustAuthError::Api(
            "custom-session expected session response to include session".to_owned(),
        ));
    };
    Ok(CustomSessionInput { user, session })
}

fn response_json(body: &[u8]) -> Result<Value, RustAuthError> {
    serde_json::from_slice(body).map_err(|error| RustAuthError::Api(error.to_string()))
}

fn json_response(
    mut parts: http::response::Parts,
    body: &Value,
) -> Result<ApiResponse, RustAuthError> {
    parts.headers.insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);
    let body = serde_json::to_vec(body).map_err(|error| RustAuthError::Api(error.to_string()))?;
    Ok(ApiResponse::from_parts(parts, body))
}
