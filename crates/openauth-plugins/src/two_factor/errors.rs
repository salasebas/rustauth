use http::{header, StatusCode};
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginErrorCode;

pub const TWO_FACTOR_ERROR_CODES: &[(&str, &str)] = &[
    ("OTP_NOT_ENABLED", "OTP not enabled"),
    ("OTP_HAS_EXPIRED", "OTP has expired"),
    ("TOTP_NOT_ENABLED", "TOTP not enabled"),
    ("TWO_FACTOR_NOT_ENABLED", "Two factor isn't enabled"),
    ("BACKUP_CODES_NOT_ENABLED", "Backup codes aren't enabled"),
    ("INVALID_BACKUP_CODE", "Invalid backup code"),
    ("INVALID_CODE", "Invalid code"),
    (
        "TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE",
        "Too many attempts. Please request a new code.",
    ),
    ("INVALID_TWO_FACTOR_COOKIE", "Invalid two factor cookie"),
    ("INVALID_PASSWORD", "Invalid password"),
    ("FAILED_TO_CREATE_SESSION", "Failed to create session"),
    ("OTP_NOT_CONFIGURED", "otp isn't configured"),
    ("TOTP_NOT_CONFIGURED", "totp isn't configured"),
];

pub fn plugin_error_codes() -> Vec<PluginErrorCode> {
    TWO_FACTOR_ERROR_CODES
        .iter()
        .map(|(code, message)| PluginErrorCode::new(*code, *message))
        .collect()
}

pub fn error_response(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.to_owned(),
        message: message.to_owned(),
        original_message: None,
    })
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}

pub fn error_message(code: &str) -> &'static str {
    TWO_FACTOR_ERROR_CODES
        .iter()
        .find_map(|(candidate, message)| (*candidate == code).then_some(*message))
        .unwrap_or("Two factor error")
}
