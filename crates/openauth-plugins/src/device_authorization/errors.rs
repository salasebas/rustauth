use http::{header, Response, StatusCode};
use openauth_core::api::ApiResponse;
use openauth_core::error::OpenAuthError;
use openauth_core::plugin::PluginErrorCode;
use serde::Serialize;

pub const INVALID_DEVICE_CODE: &str = "INVALID_DEVICE_CODE";
pub const EXPIRED_DEVICE_CODE: &str = "EXPIRED_DEVICE_CODE";
pub const EXPIRED_USER_CODE: &str = "EXPIRED_USER_CODE";
pub const AUTHORIZATION_PENDING: &str = "AUTHORIZATION_PENDING";
pub const ACCESS_DENIED: &str = "ACCESS_DENIED";
pub const INVALID_USER_CODE: &str = "INVALID_USER_CODE";
pub const DEVICE_CODE_ALREADY_PROCESSED: &str = "DEVICE_CODE_ALREADY_PROCESSED";
pub const POLLING_TOO_FREQUENTLY: &str = "POLLING_TOO_FREQUENTLY";
pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";
pub const FAILED_TO_CREATE_SESSION: &str = "FAILED_TO_CREATE_SESSION";
pub const INVALID_DEVICE_CODE_STATUS: &str = "INVALID_DEVICE_CODE_STATUS";
pub const AUTHENTICATION_REQUIRED: &str = "AUTHENTICATION_REQUIRED";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthDeviceError {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    AuthorizationPending,
    SlowDown,
    ExpiredToken,
    AccessDenied,
    Unauthorized,
    ServerError,
}

impl OAuthDeviceError {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::AccessDenied => "access_denied",
            Self::Unauthorized => "unauthorized",
            Self::ServerError => "server_error",
        }
    }
}

#[derive(Serialize)]
struct OAuthErrorBody<'a> {
    error: &'a str,
    error_description: &'a str,
}

pub fn plugin_error_code(code: &str, message: &str) -> PluginErrorCode {
    PluginErrorCode::new(code, message)
}

pub fn oauth_error_response(
    status: StatusCode,
    error: OAuthDeviceError,
    description: &str,
) -> Result<ApiResponse, OpenAuthError> {
    let body = serde_json::to_vec(&OAuthErrorBody {
        error: error.as_str(),
        error_description: description,
    })
    .map_err(|error| OpenAuthError::Api(error.to_string()))?;

    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .map_err(|error| OpenAuthError::Api(error.to_string()))
}
