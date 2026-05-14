//! Framework-neutral API contracts.

pub mod body;
pub mod routes;

pub(crate) mod additional_fields;
mod endpoint;
mod error;
mod openapi;
mod path;
mod plugin_pipeline;
mod router;
mod schema;
mod security;

pub use body::parse_request_body;
pub use endpoint::{
    create_auth_endpoint, ApiRequest, ApiResponse, AsyncAuthEndpoint, AsyncEndpointHandler,
    AuthEndpoint, AuthEndpointOptions, Body, EndpointFuture, EndpointHandler, EndpointInfo,
    EndpointKind, EndpointMiddleware, EndpointMiddlewareFuture, EndpointMiddlewareHandler,
};
pub use error::{api_error, response, ApiErrorCode, ApiErrorResponse};
pub use openapi::OpenApiOperation;
pub use path::PathParams;
pub use router::{core_endpoints, ok_endpoint, AuthRouter};
pub use routes::core_auth_async_endpoints;
pub use schema::{BodyField, BodySchema, JsonSchemaType};
