use axum::body::Body;
use axum::http::{header, Response, StatusCode};
use openauth::ApiErrorResponse;

/// Errors returned while constructing an Axum router for OpenAuth.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum OpenAuthAxumError {
    #[error("OpenAuth base path must be an absolute literal path mountable by Axum: {0}")]
    InvalidBasePath(String),
}

pub(crate) fn bad_request_response() -> axum::response::Response {
    json_error_response(
        StatusCode::BAD_REQUEST,
        "INVALID_REQUEST_BODY",
        "Invalid request body",
        None,
    )
}

pub(crate) fn payload_too_large_response() -> axum::response::Response {
    json_error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "PAYLOAD_TOO_LARGE",
        "Payload too large",
        None,
    )
}

pub(crate) fn internal_error_response() -> axum::response::Response {
    json_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Internal server error",
        None,
    )
}

pub(crate) fn json_error_response(
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
