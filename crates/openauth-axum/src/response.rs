use axum::body::Body;
use axum::http::Response;

use crate::error::internal_error_response;

pub(crate) fn from_api_response(response: openauth::ApiResponse) -> axum::response::Response {
    let (parts, body) = response.into_parts();
    let mut builder = Response::builder()
        .status(parts.status)
        .version(parts.version);
    if let Some(builder_headers) = builder.headers_mut() {
        *builder_headers = parts.headers;
    }
    match builder.body(Body::from(body)) {
        Ok(response) => response,
        Err(_error) => internal_error_response(),
    }
}
