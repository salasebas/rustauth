use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::{header, Request, Response, StatusCode};
use serde_json::Value;

use crate::context::AuthContext;
use crate::error::OpenAuthError;

use super::body::parse_request_body;
use super::error::ApiErrorResponse;
use super::openapi::OpenApiOperation;
use super::schema::BodySchema;

pub type Body = Vec<u8>;
pub type ApiRequest = Request<Body>;
pub type ApiResponse = Response<Body>;
pub type EndpointHandler = fn(&AuthContext, ApiRequest) -> Result<ApiResponse, OpenAuthError>;
pub type EndpointFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ApiResponse, OpenAuthError>> + Send + 'a>>;
pub type AsyncEndpointHandler =
    Arc<dyn for<'a> Fn(&'a AuthContext, ApiRequest) -> EndpointFuture<'a> + Send + Sync>;
pub type EndpointMiddlewareFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<ApiResponse>, OpenAuthError>> + Send + 'a>>;
pub type EndpointMiddlewareHandler = Arc<
    dyn for<'a> Fn(&'a AuthContext, &'a ApiRequest) -> EndpointMiddlewareFuture<'a> + Send + Sync,
>;

#[derive(Clone)]
pub struct EndpointMiddleware {
    pub handler: EndpointMiddlewareHandler,
}

impl EndpointMiddleware {
    pub fn new<F>(handler: F) -> Self
    where
        F: for<'a> Fn(&'a AuthContext, &'a ApiRequest) -> EndpointMiddlewareFuture<'a>
            + Send
            + Sync
            + 'static,
    {
        Self {
            handler: Arc::new(handler),
        }
    }
}

#[derive(Clone, Default)]
pub struct AuthEndpointOptions {
    pub operation_id: Option<String>,
    pub allowed_media_types: Vec<String>,
    pub body_schema: Option<BodySchema>,
    pub middlewares: Vec<EndpointMiddleware>,
    pub openapi: Option<OpenApiOperation>,
    pub server_only: bool,
    pub hide_from_openapi: bool,
    pub bypass_origin_security: bool,
}

impl AuthEndpointOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn operation_id(mut self, operation_id: impl Into<String>) -> Self {
        self.operation_id = Some(operation_id.into());
        self
    }

    #[must_use]
    pub fn allowed_media_types<I, S>(mut self, media_types: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_media_types = media_types.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn body_schema(mut self, schema: BodySchema) -> Self {
        self.body_schema = Some(schema);
        self
    }

    #[must_use]
    pub fn middleware(mut self, middleware: EndpointMiddleware) -> Self {
        self.middlewares.push(middleware);
        self
    }

    #[must_use]
    pub fn openapi(mut self, operation: OpenApiOperation) -> Self {
        self.openapi = Some(operation);
        self
    }

    #[must_use]
    pub fn server_only(mut self) -> Self {
        self.server_only = true;
        self
    }

    #[must_use]
    pub fn hide_from_openapi(mut self) -> Self {
        self.hide_from_openapi = true;
        self
    }

    #[must_use]
    pub fn bypass_origin_security(mut self) -> Self {
        self.bypass_origin_security = true;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Sync,
    Async,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointInfo {
    pub path: String,
    pub method: http::Method,
    pub kind: EndpointKind,
    pub operation_id: Option<String>,
    pub allowed_media_types: Vec<String>,
}

#[derive(Clone)]
pub struct AuthEndpoint {
    pub path: String,
    pub method: http::Method,
    pub handler: EndpointHandler,
}

#[derive(Clone)]
pub struct AsyncAuthEndpoint {
    pub path: String,
    pub method: http::Method,
    pub handler: AsyncEndpointHandler,
    pub options: AuthEndpointOptions,
}

impl AsyncAuthEndpoint {
    pub fn new<F>(path: impl Into<String>, method: http::Method, handler: F) -> Self
    where
        F: for<'a> Fn(&'a AuthContext, ApiRequest) -> EndpointFuture<'a> + Send + Sync + 'static,
    {
        Self {
            path: path.into(),
            method,
            handler: Arc::new(handler),
            options: AuthEndpointOptions::default(),
        }
    }
}

pub fn create_auth_endpoint<F>(
    path: impl Into<String>,
    method: http::Method,
    options: AuthEndpointOptions,
    handler: F,
) -> AsyncAuthEndpoint
where
    F: for<'a> Fn(&'a AuthContext, ApiRequest) -> EndpointFuture<'a> + Send + Sync + 'static,
{
    AsyncAuthEndpoint {
        path: path.into(),
        method,
        handler: Arc::new(handler),
        options,
    }
}

pub(super) fn validate_async_endpoint_request(
    endpoint: &AsyncAuthEndpoint,
    request: &ApiRequest,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    if endpoint.options.allowed_media_types.is_empty() && endpoint.options.body_schema.is_none() {
        return Ok(None);
    }

    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if !endpoint.options.allowed_media_types.is_empty() {
        let Some(content_type) = content_type else {
            return invalid_request_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                "Missing Content-Type",
            )
            .map(Some);
        };
        if !endpoint
            .options
            .allowed_media_types
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(content_type))
        {
            return invalid_request_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "UNSUPPORTED_MEDIA_TYPE",
                "Unsupported Content-Type",
            )
            .map(Some);
        }
    }

    if let Some(schema) = &endpoint.options.body_schema {
        let body = match parse_request_body::<Value>(request) {
            Ok(body) => body,
            Err(error) => {
                return invalid_request_response(
                    StatusCode::BAD_REQUEST,
                    "INVALID_REQUEST_BODY",
                    &error.to_string(),
                )
                .map(Some);
            }
        };
        if let Err(message) = schema.validate(&body) {
            return invalid_request_response(
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST_BODY",
                &message,
            )
            .map(Some);
        }
    }

    Ok(None)
}

pub(super) async fn run_endpoint_middlewares(
    context: &AuthContext,
    endpoint: &AsyncAuthEndpoint,
    request: &ApiRequest,
) -> Result<Option<ApiResponse>, OpenAuthError> {
    for middleware in &endpoint.options.middlewares {
        if let Some(response) = (middleware.handler)(context, request).await? {
            return Ok(Some(response));
        }
    }
    Ok(None)
}

fn invalid_request_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.to_owned(),
        message: message.to_owned(),
        original_message: None,
    })
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}
