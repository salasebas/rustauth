//! Framework-neutral API contracts.

pub mod body;
pub(crate) mod http_json;
pub mod output;
pub mod routes;

pub mod additional_fields;
mod endpoint;
mod error;
mod middleware;
mod on_api_error;
mod openapi;
mod path;
mod plugin_pipeline;
mod response_helpers;
mod router;
mod schema;
mod security;
pub(crate) mod services;
mod session_request_state;

pub use body::parse_request_body;
pub use endpoint::{
    async_auth_handler, async_endpoint_middleware, create_auth_endpoint, create_auth_endpoint_raw,
    request_base_url, ApiRequest, ApiResponse, AsyncAuthEndpoint, AsyncEndpointHandler,
    AuthEndpoint, AuthEndpointOptions, Body, EndpointFuture, EndpointHandler, EndpointInfo,
    EndpointKind, EndpointMiddleware, EndpointMiddlewareFuture, EndpointMiddlewareHandler,
    RequestBaseUrl,
};
pub use error::{api_error, response, ApiErrorCode, ApiErrorResponse};
pub use middleware::{fresh_session_middleware, require_resource_ownership};
pub use openapi::{
    build_openapi_schema, empty_openapi_response, json_openapi_response, path_param, query_param,
    redirect_openapi_response, OpenApiOperation,
};
pub use path::PathParams;
pub use response_helpers::{
    append_cookies, json_response, redirect_response, redirect_with_error_response,
    serialize_cookie, session_cookies,
};
pub use router::{core_endpoints, ok_endpoint, AuthRouter};
pub use routes::core_auth_async_endpoints;
pub use schema::{BodyField, BodySchema, JsonSchemaType};
