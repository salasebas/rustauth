use http::StatusCode;
pub use openauth_core::api::json_response;
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::error::OpenAuthError;

pub fn unauthorized() -> Result<ApiResponse, OpenAuthError> {
    error_response(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized")
}

pub fn not_allowed() -> Result<ApiResponse, OpenAuthError> {
    error_response(
        StatusCode::UNAUTHORIZED,
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
        "You are not allowed to register this passkey",
    )
}

pub fn session_not_fresh() -> Result<ApiResponse, OpenAuthError> {
    error_response(
        StatusCode::FORBIDDEN,
        "SESSION_NOT_FRESH",
        "Session is not fresh",
    )
}

pub fn internal_error(
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<ApiResponse, OpenAuthError> {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, code, message)
}

pub fn error_response(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Result<ApiResponse, OpenAuthError> {
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
