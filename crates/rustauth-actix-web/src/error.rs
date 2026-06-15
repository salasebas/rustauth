use actix_web::http::header;
use actix_web::{HttpResponse, ResponseError};
use rustauth::api::ApiErrorResponse;

/// Errors returned while constructing an Actix Web scope for RustAuth.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum RustAuthActixWebError {
    #[error("RustAuth base path must be an absolute literal path mountable by Actix Web: {0}")]
    InvalidBasePath(String),
    #[error("RustAuth base_url is not a valid absolute URL: {0}")]
    InvalidBaseUrl(String),
    #[error(
        "RustAuth base_url path `{url_path}` does not match configured base_path `{base_path}`"
    )]
    InconsistentBaseUrlPath { url_path: String, base_path: String },
}

impl ResponseError for RustAuthActixWebError {}

pub(crate) fn bad_request_response() -> HttpResponse {
    json_error_response(
        actix_web::http::StatusCode::BAD_REQUEST,
        "INVALID_REQUEST_BODY",
        "Invalid request body",
        None,
    )
}

pub(crate) fn payload_too_large_response() -> HttpResponse {
    json_error_response(
        actix_web::http::StatusCode::PAYLOAD_TOO_LARGE,
        "PAYLOAD_TOO_LARGE",
        "Payload too large",
        None,
    )
}

pub(crate) fn internal_error_response() -> HttpResponse {
    json_error_response(
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Internal server error",
        None,
    )
}

pub(crate) fn json_error_response(
    status: actix_web::http::StatusCode,
    code: &str,
    message: &str,
    original_message: Option<String>,
) -> HttpResponse {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.to_owned(),
        message: message.to_owned(),
        original_message,
    })
    .unwrap_or_else(|_| {
        b"{\"code\":\"INTERNAL_SERVER_ERROR\",\"message\":\"Internal server error\"}".to_vec()
    });
    HttpResponse::build(status)
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .body(body)
}
