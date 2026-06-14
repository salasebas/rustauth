use http::StatusCode;
pub use rustauth_core::api::json_response;
use rustauth_core::api::{ApiErrorResponse, ApiResponse};
use rustauth_core::error::RustAuthError;
use rustauth_core::rate_limit::RateLimitRejection;

pub fn unauthorized() -> Result<ApiResponse, RustAuthError> {
    error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")
}

pub fn not_allowed() -> Result<ApiResponse, RustAuthError> {
    error_response(
        StatusCode::UNAUTHORIZED,
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
        "You are not allowed to register this passkey",
    )
}

pub fn session_not_fresh() -> Result<ApiResponse, RustAuthError> {
    error_response(
        StatusCode::FORBIDDEN,
        "SESSION_NOT_FRESH",
        "Session is not fresh",
    )
}

/// Generic passkey authentication failure (unknown credential, bad proof, etc.).
pub fn authentication_failed() -> Result<ApiResponse, RustAuthError> {
    error_response(
        StatusCode::BAD_REQUEST,
        "AUTHENTICATION_FAILED",
        "Authentication failed",
    )
}

pub fn internal_error(
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<ApiResponse, RustAuthError> {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, code, message)
}

pub fn too_many_requests(rejection: RateLimitRejection) -> Result<ApiResponse, RustAuthError> {
    let mut response = error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "TOO_MANY_REQUESTS",
        "Too many requests. Please try again later.",
    )?;
    response.headers_mut().insert(
        "X-Retry-After",
        http::HeaderValue::from_str(&rejection.retry_after.to_string()).map_err(|error| {
            RustAuthError::Serialization {
                context: "building rate limit response headers",
                message: error.to_string(),
            }
        })?,
    );
    Ok(response)
}

pub fn error_response(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<ApiResponse, RustAuthError> {
    json_response(
        status,
        &ApiErrorResponse {
            code: code.into(),
            message: message.into(),
            original_message: None,
        },
        Vec::new(),
    )
}
