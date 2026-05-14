use http::StatusCode;
use openauth_core::api::ApiErrorResponse;
use openauth_core::plugin::PluginErrorCode;

pub const INVALID_USERNAME_OR_PASSWORD: &str = "INVALID_USERNAME_OR_PASSWORD";
pub const EMAIL_NOT_VERIFIED: &str = "EMAIL_NOT_VERIFIED";
pub const UNEXPECTED_ERROR: &str = "UNEXPECTED_ERROR";
pub const USERNAME_IS_ALREADY_TAKEN: &str = "USERNAME_IS_ALREADY_TAKEN";
pub const USERNAME_TOO_SHORT: &str = "USERNAME_TOO_SHORT";
pub const USERNAME_TOO_LONG: &str = "USERNAME_TOO_LONG";
pub const INVALID_USERNAME: &str = "INVALID_USERNAME";
pub const INVALID_DISPLAY_USERNAME: &str = "INVALID_DISPLAY_USERNAME";

pub fn error_codes() -> Vec<PluginErrorCode> {
    vec![
        PluginErrorCode::new(INVALID_USERNAME_OR_PASSWORD, "Invalid username or password"),
        PluginErrorCode::new(EMAIL_NOT_VERIFIED, "Email not verified"),
        PluginErrorCode::new(UNEXPECTED_ERROR, "Unexpected error"),
        PluginErrorCode::new(
            USERNAME_IS_ALREADY_TAKEN,
            "Username is already taken. Please try another.",
        ),
        PluginErrorCode::new(USERNAME_TOO_SHORT, "Username is too short"),
        PluginErrorCode::new(USERNAME_TOO_LONG, "Username is too long"),
        PluginErrorCode::new(INVALID_USERNAME, "Username is invalid"),
        PluginErrorCode::new(INVALID_DISPLAY_USERNAME, "Display username is invalid"),
    ]
}

pub fn error_response(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Result<openauth_core::api::ApiResponse, openauth_core::error::OpenAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.to_owned(),
        message: message.to_owned(),
        original_message: None,
    })
    .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))?;

    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| openauth_core::error::OpenAuthError::Api(error.to_string()))
}
