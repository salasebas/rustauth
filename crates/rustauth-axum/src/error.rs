use axum::body::Body;
use axum::http::{header, HeaderValue, Response, StatusCode};
use rustauth::api::ApiErrorResponse;

/// Errors returned while constructing an Axum router for RustAuth.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RustAuthAxumError {
    #[error("RustAuth base path must be an absolute literal path mountable by Axum: {0}")]
    InvalidBasePath(String),
    #[error("RustAuth base_url is not a valid absolute URL: {0}")]
    InvalidBaseUrl(String),
    #[error(
        "RustAuth base_url path `{url_path}` does not match configured base_path `{base_path}`"
    )]
    InconsistentBaseUrlPath { url_path: String, base_path: String },
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
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}
