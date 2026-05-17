use http::StatusCode;
use openauth_core::api::{ApiErrorResponse, ApiResponse};
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginErrorCode;

pub const INVALID_METADATA_TYPE: &str = "INVALID_METADATA_TYPE";
pub const REFILL_AMOUNT_AND_INTERVAL_REQUIRED: &str = "REFILL_AMOUNT_AND_INTERVAL_REQUIRED";
pub const REFILL_INTERVAL_AND_AMOUNT_REQUIRED: &str = "REFILL_INTERVAL_AND_AMOUNT_REQUIRED";
pub const UNAUTHORIZED_SESSION: &str = "UNAUTHORIZED_SESSION";
pub const KEY_NOT_FOUND: &str = "KEY_NOT_FOUND";
pub const KEY_DISABLED: &str = "KEY_DISABLED";
pub const KEY_EXPIRED: &str = "KEY_EXPIRED";
pub const USAGE_EXCEEDED: &str = "USAGE_EXCEEDED";
pub const EXPIRES_IN_IS_TOO_SMALL: &str = "EXPIRES_IN_IS_TOO_SMALL";
pub const EXPIRES_IN_IS_TOO_LARGE: &str = "EXPIRES_IN_IS_TOO_LARGE";
pub const INVALID_PREFIX_LENGTH: &str = "INVALID_PREFIX_LENGTH";
pub const INVALID_NAME_LENGTH: &str = "INVALID_NAME_LENGTH";
pub const METADATA_DISABLED: &str = "METADATA_DISABLED";
pub const RATE_LIMIT_EXCEEDED: &str = "RATE_LIMIT_EXCEEDED";
pub const NO_VALUES_TO_UPDATE: &str = "NO_VALUES_TO_UPDATE";
pub const KEY_DISABLED_EXPIRATION: &str = "KEY_DISABLED_EXPIRATION";
pub const INVALID_API_KEY: &str = "INVALID_API_KEY";
pub const INVALID_REFERENCE_ID_FROM_API_KEY: &str = "INVALID_REFERENCE_ID_FROM_API_KEY";
pub const SERVER_ONLY_PROPERTY: &str = "SERVER_ONLY_PROPERTY";
pub const FAILED_TO_UPDATE_API_KEY: &str = "FAILED_TO_UPDATE_API_KEY";
pub const NAME_REQUIRED: &str = "NAME_REQUIRED";
pub const ORGANIZATION_ID_REQUIRED: &str = "ORGANIZATION_ID_REQUIRED";
pub const USER_NOT_MEMBER_OF_ORGANIZATION: &str = "USER_NOT_MEMBER_OF_ORGANIZATION";
pub const INSUFFICIENT_API_KEY_PERMISSIONS: &str = "INSUFFICIENT_API_KEY_PERMISSIONS";
pub const NO_DEFAULT_API_KEY_CONFIGURATION_FOUND: &str = "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND";
pub const ORGANIZATION_PLUGIN_REQUIRED: &str = "ORGANIZATION_PLUGIN_REQUIRED";

pub const ERROR_CODES: &[(&str, &str)] = &[
    (INVALID_METADATA_TYPE, "metadata must be an object or undefined"),
    (
        REFILL_AMOUNT_AND_INTERVAL_REQUIRED,
        "refillAmount is required when refillInterval is provided",
    ),
    (
        REFILL_INTERVAL_AND_AMOUNT_REQUIRED,
        "refillInterval is required when refillAmount is provided",
    ),
    (UNAUTHORIZED_SESSION, "Unauthorized or invalid session"),
    (KEY_NOT_FOUND, "API Key not found"),
    (KEY_DISABLED, "API Key is disabled"),
    (KEY_EXPIRED, "API Key has expired"),
    (USAGE_EXCEEDED, "API Key has reached its usage limit"),
    (
        EXPIRES_IN_IS_TOO_SMALL,
        "The expiresIn is smaller than the predefined minimum value.",
    ),
    (
        EXPIRES_IN_IS_TOO_LARGE,
        "The expiresIn is larger than the predefined maximum value.",
    ),
    (
        INVALID_PREFIX_LENGTH,
        "The prefix length is either too large or too small.",
    ),
    (
        INVALID_NAME_LENGTH,
        "The name length is either too large or too small.",
    ),
    (METADATA_DISABLED, "Metadata is disabled."),
    (RATE_LIMIT_EXCEEDED, "Rate limit exceeded."),
    (NO_VALUES_TO_UPDATE, "No values to update."),
    (
        KEY_DISABLED_EXPIRATION,
        "Custom key expiration values are disabled.",
    ),
    (INVALID_API_KEY, "Invalid API key."),
    (
        INVALID_REFERENCE_ID_FROM_API_KEY,
        "The reference id from the API key is invalid.",
    ),
    (
        SERVER_ONLY_PROPERTY,
        "The property you're trying to set can only be set from the server auth instance only.",
    ),
    (FAILED_TO_UPDATE_API_KEY, "Failed to update API key"),
    (NAME_REQUIRED, "API Key name is required."),
    (
        ORGANIZATION_ID_REQUIRED,
        "Organization ID is required for organization-owned API keys.",
    ),
    (
        USER_NOT_MEMBER_OF_ORGANIZATION,
        "You are not a member of the organization that owns this API key.",
    ),
    (
        INSUFFICIENT_API_KEY_PERMISSIONS,
        "You do not have permission to perform this action on organization API keys.",
    ),
    (
        NO_DEFAULT_API_KEY_CONFIGURATION_FOUND,
        "No default api-key configuration found.",
    ),
    (
        ORGANIZATION_PLUGIN_REQUIRED,
        "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.",
    ),
];

pub fn message(code: &str) -> &'static str {
    ERROR_CODES
        .iter()
        .find_map(|(candidate, message)| (*candidate == code).then_some(*message))
        .unwrap_or("Unknown API key error")
}

pub fn plugin_error_codes() -> Vec<PluginErrorCode> {
    ERROR_CODES
        .iter()
        .map(|(code, message)| PluginErrorCode::new(*code, *message))
        .collect()
}

pub fn error_response(status: StatusCode, code: &str) -> Result<ApiResponse, OpenAuthError> {
    error_response_with_message(status, code, message(code))
}

pub fn error_response_with_message(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(&ApiErrorResponse {
        code: code.to_owned(),
        message: message.into(),
        original_message: None,
    })
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}
