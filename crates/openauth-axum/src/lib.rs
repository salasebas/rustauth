//! Axum integration for OpenAuth.

use std::error::Error as _;

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use http_body_util::LengthLimitError;
use openauth::{ApiErrorResponse, ApiRequest, OpenAuth, OpenAuthError};

const DEFAULT_BODY_LIMIT: usize = 10 * 1024 * 1024;

/// Axum adapter options.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenAuthAxumOptions {
    body_limit: usize,
}

impl OpenAuthAxumOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn body_limit(mut self, body_limit: usize) -> Self {
        self.body_limit = body_limit;
        self
    }

    #[must_use]
    pub fn request_body_limit(&self) -> usize {
        self.body_limit
    }
}

impl Default for OpenAuthAxumOptions {
    fn default() -> Self {
        Self {
            body_limit: DEFAULT_BODY_LIMIT,
        }
    }
}

#[derive(Clone)]
struct OpenAuthAxumState {
    auth: OpenAuth,
    options: OpenAuthAxumOptions,
}

/// Errors returned while constructing an Axum router for OpenAuth.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OpenAuthAxumError {
    #[error("OpenAuth base path must start with `/`: {0}")]
    InvalidBasePath(String),
}

/// Convenience extension methods for mounting OpenAuth into Axum.
pub trait OpenAuthAxumExt {
    /// Mount OpenAuth at `OpenAuthOptions.base_path`, defaulting to `/api/auth`.
    fn into_router(self) -> Result<Router, OpenAuthAxumError>;

    /// Mount OpenAuth with adapter-specific options.
    fn into_router_with_options(
        self,
        options: OpenAuthAxumOptions,
    ) -> Result<Router, OpenAuthAxumError>;

    /// Return unmounted OpenAuth routes for callers that want to nest manually.
    fn into_routes(self) -> Router;

    /// Return unmounted OpenAuth routes with adapter-specific options.
    fn into_routes_with_options(self, options: OpenAuthAxumOptions) -> Router;
}

impl OpenAuthAxumExt for OpenAuth {
    fn into_router(self) -> Result<Router, OpenAuthAxumError> {
        router(self)
    }

    fn into_router_with_options(
        self,
        options: OpenAuthAxumOptions,
    ) -> Result<Router, OpenAuthAxumError> {
        router_with_options(self, options)
    }

    fn into_routes(self) -> Router {
        routes(self)
    }

    fn into_routes_with_options(self, options: OpenAuthAxumOptions) -> Router {
        routes_with_options(self, options)
    }
}

/// Mount OpenAuth at `auth.context().base_path`.
pub fn router(auth: OpenAuth) -> Result<Router, OpenAuthAxumError> {
    router_with_options(auth, OpenAuthAxumOptions::default())
}

/// Mount OpenAuth at `auth.context().base_path` with adapter-specific options.
pub fn router_with_options(
    auth: OpenAuth,
    options: OpenAuthAxumOptions,
) -> Result<Router, OpenAuthAxumError> {
    let base_path = auth.context().base_path.clone();
    validate_base_path(&base_path)?;
    if base_path == "/" {
        return Ok(routes_with_options(auth, options));
    }
    Ok(Router::new().nest(&base_path, routes_with_options(auth, options)))
}

/// Build unmounted OpenAuth catch-all routes.
///
/// Use this when composing with an existing Axum router manually. The returned
/// router should be nested at the same path as `OpenAuthOptions.base_path`.
pub fn routes(auth: OpenAuth) -> Router {
    routes_with_options(auth, OpenAuthAxumOptions::default())
}

/// Build unmounted OpenAuth catch-all routes with adapter-specific options.
pub fn routes_with_options(auth: OpenAuth, options: OpenAuthAxumOptions) -> Router {
    Router::new()
        .route("/", any(route_handler))
        .route("/{*path}", any(route_handler))
        .with_state(OpenAuthAxumState { auth, options })
}

/// Handle a single Axum request through OpenAuth.
pub async fn handle(auth: OpenAuth, request: Request<Body>) -> axum::response::Response {
    handle_with_options(auth, OpenAuthAxumOptions::default(), request).await
}

/// Handle a single Axum request through OpenAuth with adapter-specific options.
pub async fn handle_with_options(
    auth: OpenAuth,
    options: OpenAuthAxumOptions,
    request: Request<Body>,
) -> axum::response::Response {
    match to_api_request(request, options.body_limit).await {
        Ok(request) => match auth.handler_async(request).await {
            Ok(response) => from_api_response(response),
            Err(error) => internal_error_response(error),
        },
        Err(response) => response,
    }
}

async fn route_handler(
    State(state): State<OpenAuthAxumState>,
    request: Request<Body>,
) -> impl IntoResponse {
    handle_with_options(state.auth, state.options, request).await
}

async fn to_api_request(
    request: Request<Body>,
    body_limit: usize,
) -> Result<ApiRequest, axum::response::Response> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, body_limit)
        .await
        .map_err(body_error_response)?
        .to_vec();
    let headers = parts.headers;
    let extensions = parts.extensions;
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(parts.uri)
        .version(parts.version);
    let Some(builder_headers) = builder.headers_mut() else {
        return Err(bad_request_response());
    };
    *builder_headers = headers;
    let mut request = builder
        .body(body)
        .map_err(|_error| bad_request_response())?;
    *request.extensions_mut() = extensions;
    Ok(request)
}

fn from_api_response(response: openauth::ApiResponse) -> axum::response::Response {
    let (parts, body) = response.into_parts();
    let mut builder = Response::builder()
        .status(parts.status)
        .version(parts.version);
    if let Some(builder_headers) = builder.headers_mut() {
        *builder_headers = parts.headers;
    }
    match builder.body(Body::from(body)) {
        Ok(response) => response,
        Err(error) => internal_error_response(OpenAuthError::Api(error.to_string())),
    }
}

fn validate_base_path(base_path: &str) -> Result<(), OpenAuthAxumError> {
    if base_path.starts_with('/') {
        Ok(())
    } else {
        Err(OpenAuthAxumError::InvalidBasePath(base_path.to_owned()))
    }
}

fn bad_request_response() -> axum::response::Response {
    json_error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_REQUEST_BODY",
        "Invalid request body",
        None,
    )
}

fn payload_too_large_response() -> axum::response::Response {
    json_error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "PAYLOAD_TOO_LARGE",
        "Payload too large",
        None,
    )
}

fn body_error_response(error: axum::Error) -> axum::response::Response {
    if error
        .source()
        .is_some_and(|source| source.is::<LengthLimitError>())
    {
        payload_too_large_response()
    } else {
        bad_request_response()
    }
}

fn internal_error_response(_error: OpenAuthError) -> axum::response::Response {
    json_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Internal server error",
        None,
    )
}

fn json_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    original_message: Option<String>,
) -> axum::response::Response {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.to_owned(),
        message: message.to_owned(),
        original_message,
    })
    .unwrap_or_else(|_| {
        b"{\"code\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Internal server error\"}".to_vec()
    });
    match Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
    {
        Ok(response) => response,
        Err(_) => Response::new(Body::empty()),
    }
}
